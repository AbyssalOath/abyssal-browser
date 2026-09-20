//! `<audio>`/`<video>` fetching and decoding — mirrors `images`'s own
//! established pattern closely (resolve each `src` against the page's
//! own URL, fetch through the SAME blocklist-checking, third-party-
//! aware `FilteringFetcher` any other subresource uses, then decode
//! inside THIS sandboxed process, never in `app` — see `layout::
//! MediaAsset`'s doc comment for why that split matters here too).
//!
//! **Audio only — no video frame decoding.** Real-world `<video>`
//! files overwhelmingly use H.264 or VP9, and there is no mature
//! pure-Rust decoder for either; every real option is a C/C++ library,
//! which this project avoids for parsing untrusted content (the same
//! reasoning behind choosing Boa over a C JS engine, and the
//! pure-Rust `image` crate for `<img>`). Decoding is via `symphonia`
//! (pure Rust throughout — see this crate's own Cargo.toml for exactly
//! which containers/codecs are enabled), which demuxes a container and
//! decodes whichever audio track it finds; a `<video>`'s picture is
//! never touched at all. See `layout::MediaContent`'s own doc comment
//! for what this means on screen: real sound, real transport controls,
//! a static poster/placeholder image instead of motion.
//!
//! Two size caps, layered:
//!   - `MAX_FETCHED_MEDIA_BYTES` on the FETCHED (compressed) file, so
//!     an absurdly large file is never even handed to the decoder.
//!   - `MAX_DECODED_AUDIO_BYTES` on the DECODED PCM output, checked
//!     incrementally as decoding proceeds (compressed audio commonly
//!     expands 5-10x once decoded to raw samples) — this is the cap
//!     that actually matters for `ipc::AudioPcmData`'s own message-size
//!     headroom (see that type's doc comment).
//!
//! Either one failing just means no audio for that element (real
//! browsers show a broken/empty player for an unplayable source too),
//! not a failed navigation — matching `images`'s own "silent but
//! logged" failure philosophy.

use std::collections::HashMap;

use network::{Fetcher, FilteringFetcher};
use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::{DecoderOptions, CODEC_TYPE_NULL};
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

/// See this module's own doc comment.
pub const MAX_FETCHED_MEDIA_BYTES: usize = 45 * 1024 * 1024;
/// See this module's own doc comment.
pub const MAX_DECODED_AUDIO_BYTES: usize = 40 * 1024 * 1024;

/// One media element's fully decoded audio track — interleaved 16-bit
/// signed samples, exactly the shape `ipc::AudioPcmData` (and, from
/// there, `cpal`) wants, so nothing needs reformatting downstream.
pub struct DecodedAudio {
    pub samples: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u16,
}

impl DecodedAudio {
    pub fn duration_secs(&self) -> f32 {
        if self.channels == 0 || self.sample_rate == 0 {
            return 0.0;
        }
        self.samples.len() as f32 / self.channels as f32 / self.sample_rate as f32
    }
}

/// One `<audio>`/`<video>` element found in the document — mirrors
/// `images::extract_image_sources`'s shape and reasoning closely.
/// `src` is `None` for an element with no `src` attribute at all
/// (still real: it just has nothing to play, the same way a real
/// browser shows empty/disabled-looking controls for one).
pub struct MediaSource {
    pub node_id: dom::NodeId,
    pub kind: layout::MediaKind,
    pub src: Option<String>,
    pub controls: bool,
}

/// Collects every `<audio>`/`<video>` element's source info, in
/// document order.
pub fn extract_media_sources(document: &dom::NodeRef) -> Vec<MediaSource> {
    let mut sources = Vec::new();
    collect_media_sources(document, &mut sources);
    sources
}

fn collect_media_sources(node: &dom::NodeRef, out: &mut Vec<MediaSource>) {
    let (found, children) = {
        let node_ref = node.borrow();
        match &node_ref.node_type {
            dom::NodeType::Element(el) if el.tag_name == "audio" || el.tag_name == "video" => {
                let kind = if el.tag_name == "video" {
                    layout::MediaKind::Video
                } else {
                    layout::MediaKind::Audio
                };
                let source = MediaSource {
                    node_id: node_ref.id,
                    kind,
                    src: el.attributes.get("src").cloned(),
                    controls: el.attributes.contains_key("controls"),
                };
                (Some(source), node_ref.children.clone())
            }
            _ => (None, node_ref.children.clone()),
        }
    };
    if let Some(source) = found {
        out.push(source);
    }
    for child in &children {
        collect_media_sources(child, out);
    }
}

/// Resolves and fetches every media source, decoding each one's audio
/// track. Returns the STATIC `layout::MediaAsset` for every element
/// found (even one with no playable audio at all — `duration_secs:
/// 0.0` — so its poster/controls still render, see `layout::
/// MediaContent`'s own doc comment) alongside the actually-decoded
/// samples for whichever ones succeeded (`renderer::script::Session`
/// caches these, answering `ipc::ClientMessageKind::FetchAudioPcm`
/// from cache rather than re-fetching/re-decoding on every play click).
pub fn resolve_and_decode_media<F: Fetcher>(
    sources: &[MediaSource],
    page_url: &str,
    images: &HashMap<dom::NodeId, layout::ImageContent>,
    fetcher: &mut FilteringFetcher<F>,
) -> (
    HashMap<dom::NodeId, layout::MediaAsset>,
    HashMap<dom::NodeId, DecodedAudio>,
) {
    let mut assets = HashMap::new();
    let mut decoded_audio = HashMap::new();
    if sources.is_empty() {
        return (assets, decoded_audio);
    }

    let page_host = match url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(host) => host,
        None => {
            eprintln!(
                "renderer: could not determine the page's own host from {page_url:?} — skipping all \
                 media elements on this page rather than risk misjudging first/third-party."
            );
            return (assets, decoded_audio);
        }
    };

    for source in sources {
        let poster = if source.kind == layout::MediaKind::Video {
            images.get(&source.node_id).cloned()
        } else {
            None
        };
        let no_source_asset = || layout::MediaAsset {
            kind: source.kind,
            controls: source.controls,
            duration_secs: 0.0,
            poster: poster.clone(),
        };

        let Some(src) = &source.src else {
            assets.insert(source.node_id, no_source_asset());
            continue;
        };
        let Some(resolved_url) = url::Url::parse(page_url)
            .and_then(|base| base.join(src))
            .ok()
            .map(|u| u.to_string())
        else {
            eprintln!(
                "renderer: could not resolve media src {src:?} against page URL {page_url:?} (skipping)"
            );
            assets.insert(source.node_id, no_source_asset());
            continue;
        };
        let response = match fetcher.fetch_in_context(&resolved_url, Some(&page_host)) {
            Ok(response) => response,
            Err(e) => {
                eprintln!("renderer: failed to fetch media {resolved_url:?}: {e:?} (skipping)");
                assets.insert(source.node_id, no_source_asset());
                continue;
            }
        };
        if response.body.len() > MAX_FETCHED_MEDIA_BYTES {
            eprintln!(
                "renderer: media file {resolved_url:?} is too large to decode ({} bytes, cap is {} bytes) — skipping",
                response.body.len(),
                MAX_FETCHED_MEDIA_BYTES
            );
            assets.insert(source.node_id, no_source_asset());
            continue;
        }

        match decode_audio(response.body) {
            Ok(decoded) => {
                let mut asset = no_source_asset();
                asset.duration_secs = decoded.duration_secs();
                assets.insert(source.node_id, asset);
                decoded_audio.insert(source.node_id, decoded);
            }
            Err(e) => {
                eprintln!("renderer: failed to decode media {resolved_url:?}: {e} (skipping)");
                assets.insert(source.node_id, no_source_asset());
            }
        }
    }

    (assets, decoded_audio)
}

/// Demuxes `bytes` (sniffed from the content itself — symphonia probes
/// the container format rather than trusting a file extension or
/// `Content-Type`, the same "never trust a label for attacker-
/// controlled bytes" stance `images::decode_and_downscale` takes) and
/// decodes its first real audio track to interleaved 16-bit PCM.
fn decode_audio(bytes: Vec<u8>) -> Result<DecodedAudio, String> {
    let source = Box::new(std::io::Cursor::new(bytes));
    let mss = MediaSourceStream::new(source, Default::default());

    let probed = symphonia::default::get_probe()
        .format(
            &Hint::new(),
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|e| format!("could not probe media format: {e}"))?;
    let mut format = probed.format;

    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
        .ok_or_else(|| "no audio track found".to_string())?;
    let track_id = track.id;
    let sample_rate = track
        .codec_params
        .sample_rate
        .ok_or_else(|| "audio track has no known sample rate".to_string())?;
    let channels = track
        .codec_params
        .channels
        .ok_or_else(|| "audio track has no known channel layout".to_string())?
        .count() as u16;

    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| format!("unsupported audio codec: {e}"))?;

    let mut samples: Vec<i16> = Vec::new();
    loop {
        let packet = match format.next_packet() {
            Ok(packet) => packet,
            // A real, expected end-of-stream signal — see symphonia's
            // own docs on `FormatReader::next_packet`.
            Err(SymphoniaError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break
            }
            Err(e) => return Err(format!("error reading media packet: {e}")),
        };
        if packet.track_id() != track_id {
            continue;
        }
        match decoder.decode(&packet) {
            Ok(decoded) => {
                let mut sample_buf =
                    SampleBuffer::<i16>::new(decoded.capacity() as u64, *decoded.spec());
                sample_buf.copy_interleaved_ref(decoded);
                samples.extend_from_slice(sample_buf.samples());
                if samples.len() * std::mem::size_of::<i16>() > MAX_DECODED_AUDIO_BYTES {
                    return Err(format!(
                        "audio is too long to decode in full (decoded output exceeds the {} MB cap)",
                        MAX_DECODED_AUDIO_BYTES / (1024 * 1024)
                    ));
                }
            }
            // A single corrupt/unsupported packet — real files
            // occasionally have one; skip it and keep decoding the
            // rest, rather than failing the whole track over it.
            Err(SymphoniaError::DecodeError(_)) => continue,
            Err(e) => return Err(format!("error decoding media packet: {e}")),
        }
    }

    if samples.is_empty() {
        return Err("no audio samples were decoded".to_string());
    }

    Ok(DecodedAudio {
        samples,
        sample_rate,
        channels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(html: &str) -> dom::NodeRef {
        html::parse(html)
    }

    #[test]
    fn extract_media_sources_finds_audio_and_video_with_their_own_attributes() {
        let document = parse(
            r#"<html><body>
                 <audio src="song.mp3" controls></audio>
                 <video src="clip.mp4" poster="thumb.png"></video>
               </body></html>"#,
        );
        let sources = extract_media_sources(&document);
        assert_eq!(sources.len(), 2);

        assert_eq!(sources[0].kind, layout::MediaKind::Audio);
        assert_eq!(sources[0].src.as_deref(), Some("song.mp3"));
        assert!(sources[0].controls);

        assert_eq!(sources[1].kind, layout::MediaKind::Video);
        assert_eq!(sources[1].src.as_deref(), Some("clip.mp4"));
        assert!(!sources[1].controls);
    }

    #[test]
    fn extract_media_sources_allows_a_missing_src() {
        let document = parse("<html><body><audio controls></audio></body></html>");
        let sources = extract_media_sources(&document);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].src, None);
    }

    #[test]
    fn resolve_and_decode_media_produces_an_asset_with_no_source_and_no_decoded_audio() {
        let fake = network::FakeFetcher::new();
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());
        let sources = vec![MediaSource {
            node_id: dom::NodeId(1),
            kind: layout::MediaKind::Audio,
            src: None,
            controls: true,
        }];

        let (assets, decoded) = resolve_and_decode_media(
            &sources,
            "https://example.com/",
            &HashMap::new(),
            &mut fetcher,
        );

        let asset = assets
            .get(&dom::NodeId(1))
            .expect("should still get an asset");
        assert_eq!(asset.duration_secs, 0.0);
        assert!(asset.controls);
        assert!(!decoded.contains_key(&dom::NodeId(1)));
    }

    #[test]
    fn resolve_and_decode_media_skips_a_fetch_that_fails() {
        let fake = network::FakeFetcher::new(); // nothing registered
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());
        let sources = vec![MediaSource {
            node_id: dom::NodeId(1),
            kind: layout::MediaKind::Audio,
            src: Some("missing.mp3".to_string()),
            controls: true,
        }];

        let (assets, decoded) = resolve_and_decode_media(
            &sources,
            "https://example.com/",
            &HashMap::new(),
            &mut fetcher,
        );

        assert_eq!(assets.get(&dom::NodeId(1)).unwrap().duration_secs, 0.0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn resolve_and_decode_media_skips_bytes_that_are_not_real_audio() {
        let mut fake = network::FakeFetcher::new();
        fake.register("https://example.com/fake.mp3", "not actually audio");
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());
        let sources = vec![MediaSource {
            node_id: dom::NodeId(1),
            kind: layout::MediaKind::Audio,
            src: Some("fake.mp3".to_string()),
            controls: true,
        }];

        let (assets, decoded) = resolve_and_decode_media(
            &sources,
            "https://example.com/",
            &HashMap::new(),
            &mut fetcher,
        );

        assert_eq!(assets.get(&dom::NodeId(1)).unwrap().duration_secs, 0.0);
        assert!(
            decoded.is_empty(),
            "malformed audio bytes should be skipped, not panic or produce garbage samples"
        );
    }

    #[test]
    fn resolve_and_decode_media_skips_a_blocked_third_party_source() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes("http://g.doubleclick.net/track.mp3", vec![0u8; 100]);
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::with_seed_list());
        let sources = vec![MediaSource {
            node_id: dom::NodeId(1),
            kind: layout::MediaKind::Audio,
            src: Some("http://g.doubleclick.net/track.mp3".to_string()),
            controls: true,
        }];

        let (assets, decoded) = resolve_and_decode_media(
            &sources,
            "https://news.example.com/",
            &HashMap::new(),
            &mut fetcher,
        );

        assert_eq!(assets.get(&dom::NodeId(1)).unwrap().duration_secs, 0.0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn resolve_and_decode_media_attaches_a_videos_poster_from_the_images_map() {
        let fake = network::FakeFetcher::new();
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());
        let sources = vec![MediaSource {
            node_id: dom::NodeId(1),
            kind: layout::MediaKind::Video,
            src: None,
            controls: false,
        }];
        let mut images = HashMap::new();
        images.insert(
            dom::NodeId(1),
            layout::ImageContent {
                width: 10,
                height: 5,
                pixels: vec![0u8; 10 * 5 * 4],
            },
        );

        let (assets, _) =
            resolve_and_decode_media(&sources, "https://example.com/", &images, &mut fetcher);

        let poster = assets
            .get(&dom::NodeId(1))
            .unwrap()
            .poster
            .as_ref()
            .expect("should have attached the poster");
        assert_eq!((poster.width, poster.height), (10, 5));
    }

    /// A tiny, real, valid WAV file (a handful of PCM samples) —
    /// hand-encoded rather than pulled from disk, the same "small
    /// enough to embed, exercised through the real decode path either
    /// way" reasoning `images::tests::tiny_red_png` already uses.
    fn tiny_wav() -> Vec<u8> {
        let samples: [i16; 4] = [1000, -1000, 2000, -2000];
        let data_bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let sample_rate: u32 = 8000;
        let channels: u16 = 1;
        let bits_per_sample: u16 = 16;
        let byte_rate = sample_rate * channels as u32 * (bits_per_sample as u32 / 8);
        let block_align = channels * (bits_per_sample / 8);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + data_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(b"WAVE");
        bytes.extend_from_slice(b"fmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes()); // PCM
        bytes.extend_from_slice(&channels.to_le_bytes());
        bytes.extend_from_slice(&sample_rate.to_le_bytes());
        bytes.extend_from_slice(&byte_rate.to_le_bytes());
        bytes.extend_from_slice(&block_align.to_le_bytes());
        bytes.extend_from_slice(&bits_per_sample.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&(data_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&data_bytes);
        bytes
    }

    #[test]
    fn decode_audio_decodes_a_real_wav_file() {
        let decoded = decode_audio(tiny_wav()).expect("should decode a real WAV file");
        assert_eq!(decoded.sample_rate, 8000);
        assert_eq!(decoded.channels, 1);
        assert_eq!(decoded.samples, vec![1000, -1000, 2000, -2000]);
        assert!((decoded.duration_secs() - 4.0 / 8000.0).abs() < 0.0001);
    }

    #[test]
    fn decode_audio_fails_cleanly_on_garbage_bytes() {
        assert!(decode_audio(b"not audio at all".to_vec()).is_err());
    }

    #[test]
    fn resolve_and_decode_media_decodes_a_real_fetched_wav() {
        let mut fake = network::FakeFetcher::new();
        fake.register_bytes("https://example.com/song.wav", tiny_wav());
        let mut fetcher = FilteringFetcher::new(fake, privacy::Blocklist::new());
        let sources = vec![MediaSource {
            node_id: dom::NodeId(1),
            kind: layout::MediaKind::Audio,
            src: Some("song.wav".to_string()),
            controls: true,
        }];

        let (assets, decoded) = resolve_and_decode_media(
            &sources,
            "https://example.com/",
            &HashMap::new(),
            &mut fetcher,
        );

        assert!(assets.get(&dom::NodeId(1)).unwrap().duration_secs > 0.0);
        let decoded_audio = decoded
            .get(&dom::NodeId(1))
            .expect("should have decoded audio");
        assert_eq!(decoded_audio.samples, vec![1000, -1000, 2000, -2000]);
    }
}
