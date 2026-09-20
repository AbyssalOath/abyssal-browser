//! A standards-compliant (BIP-39) mnemonic encoder/decoder — turns raw
//! entropy into a checksummed sequence of words from a fixed 2048-word
//! list, and back. This is what `random_recovery_code` uses to
//! generate the account's actual credential, replacing a raw hex blob
//! (40 hex characters is hard to transcribe correctly by hand and
//! gives you no way to tell if you got it wrong) with 15 words that
//! are far easier to write down/read aloud/type — and, because of the
//! checksum, a wrong word or wrong word order gets CAUGHT (see
//! `mnemonic_to_entropy`) instead of silently producing a different,
//! equally-plausible-looking wrong secret.
//!
//! This module implements the BIP-39 encoding scheme itself (entropy
//! -> checksummed word indices -> words, and back) — it does NOT
//! implement BIP-39's separate seed-derivation step (PBKDF2-HMAC-SHA512
//! over the mnemonic sentence), because this app doesn't need it: the
//! mnemonic here is just a human-friendly SECRET STRING, fed as-is into
//! this crate's own `derive_key`/`derive_auth_secret` (Argon2id), the
//! same way a hex recovery code or a user's chosen password would be.
//! Interoperability with other BIP-39 wallets' seed derivation is
//! explicitly not a goal.
//!
//! The wordlist itself (`assets/bip39-english.txt`) is the standard
//! English list from the BIP-39 specification (MIT-licensed — see
//! `assets/BIP39-LICENSE.txt`), fetched directly from the canonical
//! `bitcoin/bips` repository and verified against its well-known
//! SHA-256 checksum before being bundled here, not retyped by hand.

use sha2::{Digest, Sha256};

const WORDLIST_TEXT: &str = include_str!("../assets/bip39-english.txt");

fn wordlist() -> Vec<&'static str> {
    WORDLIST_TEXT.lines().collect()
}

/// Entropy was decodable into whole bytes but failed a BIP-39 sanity
/// check: a word count in {12, 15, 18, 21, 24}, every word actually in
/// the wordlist, and (crucially) a checksum match. Deliberately doesn't
/// distinguish "one word was misspelled" from "the checksum just
/// doesn't match" — from a security standpoint those need the same
/// response (reject and ask the user to re-check what they wrote down),
/// same reasoning as `DecryptError` not distinguishing its own failure
/// modes.
#[derive(Debug)]
pub struct InvalidMnemonic;

impl std::fmt::Display for InvalidMnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "not a valid BIP-39 mnemonic (wrong word, wrong order, or wrong word count)"
        )
    }
}

impl std::error::Error for InvalidMnemonic {}

/// Encodes `entropy` into a checksummed mnemonic phrase using the
/// standard English wordlist. `entropy.len()` must be one of BIP-39's
/// defined sizes (16/20/24/28/32 bytes = 128/160/192/224/256 bits,
/// producing 12/15/18/21/24 words respectively) — this crate always
/// calls it with 20 bytes (15 words), matching the 160 bits of entropy
/// the recovery code carried before this module existed.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> String {
    let bit_len = entropy.len() * 8;
    assert!(
        matches!(bit_len, 128 | 160 | 192 | 224 | 256),
        "BIP-39 entropy must be 128/160/192/224/256 bits, got {bit_len}"
    );

    let checksum_bit_len = bit_len / 32;
    let hash = Sha256::digest(entropy);

    // The "message" bits are the entropy itself followed by the first
    // `checksum_bit_len` bits of SHA-256(entropy) — see BIP-39's
    // "Generating the mnemonic" section. Chopped into 11-bit groups,
    // each group is one word's index into the 2048-word list (2^11 ==
    // 2048, which is exactly why the list has that many entries).
    let mut bits = Vec::with_capacity(bit_len + checksum_bit_len);
    for &byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    for i in 0..checksum_bit_len {
        bits.push(bit_at(&hash, i));
    }

    let words = wordlist();
    bits.chunks(11)
        .map(|chunk| words[bits_to_index(chunk)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decodes a mnemonic phrase back into its original entropy bytes,
/// verifying the checksum along the way. `Err(InvalidMnemonic)` covers
/// every way a hand-transcribed phrase can go wrong: wrong number of
/// words, a word that isn't in the list (typo), or words that are all
/// individually valid but in an order/combination whose checksum
/// doesn't match (transposed words, one word swapped for another).
///
/// Not currently called anywhere in `app` — there's no "restore this
/// account on a new device by typing its recovery phrase" UI flow yet
/// (see `account`'s module docs). It's here because a correct decoder
/// is the other half of what makes the checksum meaningful at all, and
/// because that restore flow will need exactly this function once it
/// exists.
pub fn mnemonic_to_entropy(phrase: &str) -> Result<Vec<u8>, InvalidMnemonic> {
    let given: Vec<&str> = phrase.split_whitespace().collect();
    if !matches!(given.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(InvalidMnemonic);
    }

    let words = wordlist();
    let mut bits = Vec::with_capacity(given.len() * 11);
    for word in &given {
        let index = words
            .iter()
            .position(|w| w == word)
            .ok_or(InvalidMnemonic)?;
        for i in (0..11).rev() {
            bits.push((index >> i) & 1 == 1);
        }
    }

    // ENT (entropy bits) + ENT/32 (checksum bits) == total bits, so
    // ENT == total * 32 / 33 — the inverse of `entropy_to_mnemonic`'s
    // `checksum_bit_len = bit_len / 32`.
    let total_bits = bits.len();
    let checksum_bit_len = total_bits / 33;
    let entropy_bit_len = total_bits - checksum_bit_len;

    let mut entropy = vec![0u8; entropy_bit_len / 8];
    for (i, byte) in entropy.iter_mut().enumerate() {
        *byte = bits_to_index(&bits[i * 8..i * 8 + 8]) as u8;
    }

    let hash = Sha256::digest(&entropy);
    for i in 0..checksum_bit_len {
        if bits[entropy_bit_len + i] != bit_at(&hash, i) {
            return Err(InvalidMnemonic);
        }
    }

    Ok(entropy)
}

fn bit_at(bytes: &[u8], bit_index: usize) -> bool {
    let byte = bytes[bit_index / 8];
    (byte >> (7 - (bit_index % 8))) & 1 == 1
}

fn bits_to_index(bits: &[bool]) -> usize {
    bits.iter()
        .fold(0usize, |acc, &b| (acc << 1) | (b as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_exactly_2048_unique_words() {
        let words = wordlist();
        assert_eq!(words.len(), 2048);
        let mut sorted = words.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 2048, "wordlist must not contain duplicates");
    }

    #[test]
    fn encodes_160_bits_of_entropy_into_15_words() {
        let entropy = [7u8; 20];
        let phrase = entropy_to_mnemonic(&entropy);
        assert_eq!(phrase.split_whitespace().count(), 15);
    }

    #[test]
    fn decoding_a_generated_phrase_recovers_the_original_entropy() {
        let entropy = [0x42u8; 20];
        let phrase = entropy_to_mnemonic(&entropy);
        let decoded = mnemonic_to_entropy(&phrase).unwrap();
        assert_eq!(decoded, entropy);
    }

    #[test]
    fn a_known_answer_vector_matches_the_reference_bip39_implementation() {
        // Standard BIP-39 test vector (all-zero 128-bit entropy),
        // widely published (e.g. trezor/python-mnemonic's test suite)
        // — confirms this implementation agrees with the real spec,
        // not just with itself.
        let entropy = [0u8; 16];
        let phrase = entropy_to_mnemonic(&entropy);
        assert_eq!(phrase, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }

    #[test]
    fn rejects_a_phrase_with_a_word_not_in_the_list() {
        let entropy = [1u8; 20];
        let phrase = entropy_to_mnemonic(&entropy);
        let mut words: Vec<&str> = phrase.split(' ').collect();
        words[0] = "notarealbip39word";
        let tampered = words.join(" ");

        assert!(mnemonic_to_entropy(&tampered).is_err());
    }

    #[test]
    fn rejects_a_phrase_with_swapped_word_order() {
        let entropy = [3u8; 20];
        let phrase = entropy_to_mnemonic(&entropy);
        let mut words: Vec<&str> = phrase.split(' ').collect();
        words.swap(0, 1);
        let reordered = words.join(" ");

        // Swapping two words changes the encoded index sequence, which
        // (with overwhelming probability) breaks the checksum — this
        // is exactly the transcription-error detection a raw hex blob
        // could never offer.
        assert!(mnemonic_to_entropy(&reordered).is_err());
    }

    #[test]
    fn rejects_the_wrong_word_count() {
        assert!(mnemonic_to_entropy("abandon abandon abandon").is_err());
    }

    #[test]
    fn every_standard_entropy_size_round_trips() {
        for byte_len in [16usize, 20, 24, 28, 32] {
            let entropy = vec![0xABu8; byte_len];
            let phrase = entropy_to_mnemonic(&entropy);
            let expected_words = (byte_len * 8 + byte_len * 8 / 32) / 11;
            assert_eq!(phrase.split_whitespace().count(), expected_words);
            assert_eq!(mnemonic_to_entropy(&phrase).unwrap(), entropy);
        }
    }
}
