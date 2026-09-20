//! Real PDF "reader mode" — see this crate's own Cargo.toml for why
//! full visual-fidelity PDF rendering isn't attempted at all: there's
//! no mature pure-Rust PDF rendering engine, and real fidelity would
//! mean a C library like pdfium/mupdf, which this project consistently
//! avoids for anything parsing untrusted content. Instead,
//! `pdf-extract` (itself pure Rust, built on the `lopdf` object-model
//! parser) pulls real per-page TEXT out of a real PDF's actual
//! structure, and this module wraps that text in a plain synthetic
//! HTML document that the browser's OWN existing layout engine then
//! renders exactly like any other page — no images, no vector
//! graphics, no exact positioning, but genuinely real, readable text
//! for a text-heavy PDF (an article, a paper, documentation).
//!
//! Each page becomes a real `<h2>Page N</h2>` landmark followed by its
//! paragraphs — deliberately real headings, not just a visual divider:
//! `app::accessibility` already maps `<h1>`-`<h6>` to a real
//! `accesskit::Role::Heading` with a real hierarchical level, so a
//! screen reader user gets real per-page navigation landmarks through
//! a multi-page PDF for free, on top of the sighted "which page is
//! this" cue.
//!
//! No caps on input size or page count (unlike `renderer::media`/
//! `renderer::download`, which both cap the untrusted bytes they'll
//! decode) — a documented, deliberate difference: this crate's other
//! size caps exist because decoding audio/fetching a download can be
//! asked for repeatedly or run unbounded loops over attacker-chosen
//! data, but a PDF is fetched (and so bounded) by the exact same
//! `ipc::MAX_MESSAGE_LEN`-constrained pipeline every other page already
//! goes through, and `pdf-extract`'s own parser bounds its own work to
//! the document's actual real structure. If a pathologically large
//! real-world PDF turns out to need one in practice, it belongs here
//! alongside the others — not added speculatively ahead of evidence.

use dom::NodeRef;

/// The real PDF magic number — `%PDF-` at the very start of the file
/// (per the PDF spec, ISO 32000-1 §7.5.2) — checked directly against
/// the fetched bytes rather than any URL suffix or response header:
/// this crate's `network::Response` doesn't expose arbitrary response
/// headers like `Content-Type` at all (see that struct's own doc
/// comment), so a real PDF served from a URL with no `.pdf` extension
/// (or a mislabeled one) is still detected correctly, and a `.pdf`-
/// named URL that ISN'T actually a PDF is correctly left alone.
pub fn looks_like_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-")
}

/// Extracts each page's real text and wraps it in a plain synthetic
/// HTML document — see this module's own doc comment for the exact
/// shape and why. `Err` for a malformed, encrypted (this crate never
/// supplies a password), or otherwise unparseable PDF — `renderer::navigate`
/// surfaces that as an ordinary failed-navigation error, the same as a
/// real network failure would be.
pub fn build_document(bytes: &[u8]) -> Result<NodeRef, String> {
    let pages = pdf_extract::extract_text_from_mem_by_pages(bytes)
        .map_err(|e| format!("could not extract text from this PDF: {e}"))?;
    Ok(document_from_pages(&pages))
}

fn document_from_pages(pages: &[String]) -> NodeRef {
    let document = dom::Node::new_document();
    let html = dom::Node::new_element("html");
    let head = dom::Node::new_element("head");
    let title = dom::Node::new_element("title");
    dom::append_child(&title, dom::Node::new_text("PDF document"));
    dom::append_child(&head, title);
    let body = dom::Node::new_element("body");

    for (index, page_text) in pages.iter().enumerate() {
        let heading = dom::Node::new_element("h2");
        dom::append_child(
            &heading,
            dom::Node::new_text(&format!("Page {}", index + 1)),
        );
        dom::append_child(&body, heading);

        let mut any_paragraph = false;
        for paragraph in page_text.split("\n\n") {
            // Collapses each paragraph's own internal line breaks
            // (`pdf-extract`'s own line-wrapping, not a real paragraph
            // break) into single spaces — real HTML would collapse
            // that whitespace during layout anyway, so nothing is lost
            // by doing it here instead.
            let collapsed = paragraph.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.is_empty() {
                continue;
            }
            let p = dom::Node::new_element("p");
            dom::append_child(&p, dom::Node::new_text(&collapsed));
            dom::append_child(&body, p);
            any_paragraph = true;
        }
        if !any_paragraph {
            let p = dom::Node::new_element("p");
            dom::append_child(
                &p,
                dom::Node::new_text("(this page has no extractable text)"),
            );
            dom::append_child(&body, p);
        }
    }

    dom::append_child(&html, head);
    dom::append_child(&html, body);
    dom::append_child(&document, html);
    document
}

/// A tiny, real, valid, hand-built single-page PDF containing the
/// literal text "Hello PDF" — built directly from the PDF spec's own
/// object syntax (a `%PDF-` header, a `Catalog`/`Pages`/`Page` object
/// graph, a content stream with one `Tj` text-showing operator, and a
/// REAL, byte-accurate cross-reference table with a correct
/// `startxref` offset — `lopdf` needs a real one, not an approximate
/// one), not borrowed from any external file, so no test using this
/// has any dependency on anything outside this repository. Byte
/// offsets are computed as the buffer is built, rather than hand-
/// counted, specifically so this can't silently go stale if the
/// object text above it ever changes. `pub(crate)` (not test-private)
/// so `renderer::tests`' own end-to-end `handle_message`/`Navigate`
/// tests can reuse it too, rather than a second, drift-prone copy.
#[cfg(test)]
pub(crate) fn tiny_one_page_pdf_for_tests() -> Vec<u8> {
    tiny_one_page_pdf()
}

#[cfg(test)]
fn tiny_one_page_pdf() -> Vec<u8> {
    let content_stream = "BT /F1 24 Tf 72 712 Td (Hello PDF) Tj ET";
    let mut buf: Vec<u8> = Vec::new();
    let mut object_offsets: Vec<usize> = Vec::new();

    buf.extend_from_slice(b"%PDF-1.4\n");

    object_offsets.push(buf.len());
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    object_offsets.push(buf.len());
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    object_offsets.push(buf.len());
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
              /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n",
    );

    object_offsets.push(buf.len());
    buf.extend_from_slice(
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            content_stream.len(),
            content_stream,
        )
        .as_bytes(),
    );

    object_offsets.push(buf.len());
    buf.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    );

    let xref_offset = buf.len();
    buf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f\r\n");
    for offset in &object_offsets {
        buf.extend_from_slice(format!("{offset:010} 00000 n\r\n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    buf.extend_from_slice(format!("{xref_offset}\n").as_bytes());
    buf.extend_from_slice(b"%%EOF");

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_pdf_recognizes_the_real_magic_number() {
        assert!(looks_like_pdf(b"%PDF-1.4\nrest of a real file..."));
    }

    #[test]
    fn looks_like_pdf_rejects_ordinary_html() {
        assert!(!looks_like_pdf(b"<html><body>hi</body></html>"));
    }

    #[test]
    fn looks_like_pdf_rejects_an_empty_response() {
        assert!(!looks_like_pdf(b""));
    }

    #[test]
    fn build_document_extracts_real_text_from_a_real_pdf() {
        let document = build_document(&tiny_one_page_pdf()).expect("a valid PDF should parse");
        let text = collect_all_text(&document);
        assert!(
            text.contains("Hello PDF"),
            "expected the real extracted text, got: {text:?}"
        );
        assert!(text.contains("Page 1"), "expected a real page heading");
    }

    #[test]
    fn build_document_sets_a_real_title() {
        let document = build_document(&tiny_one_page_pdf()).unwrap();
        let html = &document.borrow().children[0];
        let head = &html.borrow().children[0];
        let title = &head.borrow().children[0];
        assert!(matches!(
            &title.borrow().node_type,
            dom::NodeType::Element(el) if el.tag_name == "title"
        ));
    }

    #[test]
    fn build_document_fails_honestly_on_garbage_bytes() {
        // Starts with the real magic number (so `looks_like_pdf` would
        // accept it — `renderer::navigate` only calls `build_document`
        // after that check already passed) but has no real structure
        // behind it at all.
        let result = build_document(b"%PDF-1.4\nnot a real pdf structure at all");
        assert!(result.is_err());
    }

    fn collect_all_text(node: &NodeRef) -> String {
        let (text, children) = {
            let borrowed = node.borrow();
            match &borrowed.node_type {
                dom::NodeType::Text(t) => (Some(t.clone()), Vec::new()),
                _ => (None, borrowed.children.clone()),
            }
        };
        let mut out = text.unwrap_or_default();
        for child in &children {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&collect_all_text(child));
        }
        out
    }
}
