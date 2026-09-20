//! `account` — accounts and client-side encryption, no email required.
//!
//! The model (same shape as Bitwarden/Standard Notes, simplified):
//!   1. `create_account()` mints a random `account_id`, a random
//!      `recovery_code`, and a random `kdf_salt`. The recovery code IS
//!      the credential — there's no email/username/password unless the
//!      user also sets an optional password on top.
//!   2. `derive_key()` runs the recovery code (or password) through
//!      Argon2id, salted with `kdf_salt`, entirely on-device.
//!   3. `encrypt`/`decrypt` use that key (via ChaCha20Poly1305, a real
//!      AEAD) to seal/open the bookmarks and settings blob (built in
//!      the `storage` crate) before it ever reaches `sync`.
//!   4. The server (whatever `sync` talks to) only ever sees
//!      ciphertext plus the account_id used to address it, plus the
//!      (non-secret) `kdf_salt` needed to re-derive the key on another
//!      device. It cannot derive the key and cannot read the contents.
//!
//! **The crypto here is real now** — Argon2id (memory-hard key
//! derivation, resists GPU/ASIC cracking far better than a fast hash)
//! and ChaCha20Poly1305 (authenticated encryption: tampering with the
//! ciphertext makes `decrypt` fail loudly instead of silently
//! producing garbage, which the old XOR placeholder could never do).
//! `rand`'s OS-backed CSPRNG replaces the old `RandomState`-based
//! stand-in for the KDF salt, the AEAD nonce, and the recovery code
//! itself.
//!
//! What's still NOT done, and matters for a full security posture
//! (not just "is the crypto itself real"):
//!   - No secure memory handling beyond `zeroize`ing derived keys and
//!     decrypted plaintext (see `derive_key`/`decrypt`) — they're still
//!     regular (potentially swappable, potentially core-dumpable)
//!     process memory up until that point, not locked/mlocked.
//!
//! Recovery UX, stated plainly because it's a real product tradeoff
//! and not just an implementation detail: without email, there is no
//! "forgot password" flow. Losing the recovery code (and any
//! optional password layered on top of it) means the encrypted data
//! is unrecoverable, by design — that's what "the server can't read
//! your data" actually costs.
//!
//! Next steps, roughly in order of payoff:
//!   1. Decide on optional password-on-top-of-recovery-code UX, and
//!      whether multiple devices derive the same key independently
//!      (simplest, what's implemented) or negotiate one via a
//!      key-exchange flow.
//!   2. `mlock`/`madvise(MADV_DONTDUMP)` the buffers `derive_key`
//!      returns, so a core dump or swapped page can't leak them —
//!      `zeroize` (already in use) only guarantees they're wiped
//!      after use, not that they were never written to disk/a dump
//!      while live.
//!   3. A "restore this account on a new device" UI flow that has the
//!      user type their recovery phrase back in — `bip39::
//!      mnemonic_to_entropy` (already implemented, see that module)
//!      is the missing piece's other half; there's just no UI calling
//!      it yet, since today `app` only ever reads the recovery code
//!      back from its own local file on the SAME device.

pub mod bip39;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

pub struct Account {
    pub account_id: String,
    pub recovery_code: String,
    /// Random salt for Argon2id key derivation, generated once at
    /// account creation. NOT secret — safe to store/sync alongside
    /// `account_id`. Needed to re-derive the SAME key on another
    /// device from the same recovery code (Argon2 is deterministic
    /// given the same password + salt + parameters).
    pub kdf_salt: [u8; 16],
}

/// Create a brand-new account: a random ID to address it by, a random
/// recovery code that doubles as the only credential, and a random
/// KDF salt. No email, no username collection.
pub fn create_account() -> Account {
    Account {
        account_id: random_token("acct", 16),
        recovery_code: random_recovery_code(),
        kdf_salt: random_bytes::<16>(),
    }
}

/// Fill a fixed-size array with real OS-backed CSPRNG bytes.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_token(prefix: &str, byte_len: usize) -> String {
    let bytes = {
        let mut buf = vec![0u8; byte_len];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    };
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}_{hex}")
}

/// A human-typable recovery code: a 15-word BIP-39 mnemonic (see the
/// `bip39` module) encoding 160 bits of real CSPRNG entropy — the same
/// entropy a raw 40-character hex blob would have carried, just in a
/// form that's actually feasible to write down/read aloud/type
/// correctly, with a built-in checksum that catches a mis-transcribed
/// or reordered word instead of silently producing a different, wrong
/// secret. This IS the account's actual secret credential, so its
/// entropy comes from the same real CSPRNG as the KDF salt/AEAD nonce —
/// unlike the account_id (which only needs to be unique, not
/// unpredictable).
fn random_recovery_code() -> String {
    let entropy = random_bytes::<20>();
    bip39::entropy_to_mnemonic(&entropy)
}

/// Argon2id cost parameters, chosen deliberately for this app rather
/// than left at `Argon2::default()`'s generic minimum (19 MiB / t=2 /
/// p=1). Rationale:
///
///   - This KDF only ever runs LOCALLY, to protect a stolen ciphertext
///     blob (bookmarks/settings) against offline brute-forcing of the
///     recovery code/password — never on a server authenticating many
///     concurrent users, so there's no server-side capacity cost to
///     being generous with it.
///   - `argon2` (the RustCrypto crate backing this) has no
///     multi-threaded/rayon-based lane execution: every lane runs
///     serially no matter what `p_cost` is, so raising `p_cost` only
///     adds wall-clock time with no speedup from spare CPU cores.
///     `KDF_PARALLELISM` is kept at the minimum (1) and the whole time
///     budget goes into `KDF_MEMORY_COST_KIB` instead, which is the
///     parameter that actually resists GPU/ASIC cracking (more memory
///     per guess is expensive to replicate across many parallel
///     cracking units in hardware).
///   - 128 MiB / 3 iterations is well above OWASP's Argon2id minimum
///     (19 MiB / t=2) while still completing in well under a second on
///     ordinary desktop hardware in a release build (this crate does
///     runtime AVX2 detection on x86_64). A `cargo build` debug binary
///     (this workspace's default — see the root `Cargo.toml`'s
///     `[profile.dev]`) is meaningfully slower; that's an expected
///     dev-loop cost, not evidence these numbers need lowering.
const KDF_MEMORY_COST_KIB: u32 = 128 * 1024;
const KDF_TIME_COST: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

/// Builds the `Argon2` context every derivation in this module uses,
/// so the two call sites (`derive_key`, `derive_auth_secret`) can never
/// silently drift apart on parameters — there's exactly one place that
/// decides what "the KDF" means for this app.
fn kdf() -> Argon2<'static> {
    let params = Params::new(KDF_MEMORY_COST_KIB, KDF_TIME_COST, KDF_PARALLELISM, None)
        .expect("hardcoded KDF params are always within Params::new's valid ranges");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Derive a symmetric encryption key from a low-entropy secret
/// (recovery code or password) using Argon2id — memory-hard key
/// derivation, specifically chosen (over a fast hash) so that
/// brute-forcing a stolen ciphertext blob is expensive even with
/// GPU/ASIC hardware. `salt` should be `Account::kdf_salt` — the same
/// salt must be used every time to re-derive the same key.
pub fn derive_key(secret: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    kdf()
        .hash_password_into(secret.as_bytes(), salt, &mut *key)
        .expect(
            "Argon2 key derivation into a fixed 32-byte buffer should never fail \
             for a non-empty, reasonably-sized secret and salt",
        );
    key
}

/// Derives a SECOND, cryptographically independent secret from the
/// same recovery code — used only to authenticate to the sync server,
/// never to encrypt anything. Domain-separated from `derive_key`'s
/// output by a fixed prefix, so the sync server (which must see this
/// value to authenticate requests) can never use it to derive the
/// encryption key and read the user's actual data.
pub fn derive_auth_secret(secret: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let domain_separated = format!("abyssal-sync-auth-v1|{secret}");
    kdf()
        .hash_password_into(domain_separated.as_bytes(), salt, &mut *key)
        .expect(
            "Argon2 key derivation into a fixed 32-byte buffer should never fail \
             for a non-empty, reasonably-sized secret and salt",
        );
    key
}

/// Seal plaintext with the derived key using ChaCha20Poly1305 (a real
/// AEAD): a fresh random nonce is generated for this call and
/// prepended to the returned ciphertext (the nonce isn't secret — it
/// only needs to be unique per encryption under a given key, and
/// storing it alongside the ciphertext is the standard, simplest way
/// to make it available to `decrypt` later).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let key: Key = key
        .as_slice()
        .try_into()
        .expect("key is always exactly 32 bytes");
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce_bytes = random_bytes::<12>();
    let nonce: Nonce = nonce_bytes
        .as_slice()
        .try_into()
        .expect("nonce is always exactly 12 bytes");

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption with a validly-sized key and nonce should not fail");

    let mut output = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decryption failed: either the key was wrong, or the ciphertext was
/// truncated/corrupted/tampered with. Deliberately doesn't distinguish
/// which — an AEAD's whole point is that "wrong key" and "tampered
/// data" are indistinguishable from the outside, which is a security
/// property, not a missing feature.
#[derive(Debug)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "decryption failed (wrong key, or corrupted/tampered ciphertext)"
        )
    }
}

impl std::error::Error for DecryptError {}

/// Open ciphertext produced by `encrypt`. Returns `Err` rather than
/// silently producing garbage if the key is wrong or the data was
/// tampered with — a real, meaningful improvement over the old XOR
/// placeholder, which could never detect either case.
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    if ciphertext.len() < 12 {
        return Err(DecryptError);
    }
    let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(12);
    let key: Key = key
        .as_slice()
        .try_into()
        .expect("key is always exactly 32 bytes");
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce: Nonce = nonce_bytes.try_into().map_err(|_| DecryptError)?;
    cipher
        .decrypt(&nonce, actual_ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| DecryptError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_an_account_with_no_email_fields() {
        let account = create_account();
        assert!(account.account_id.starts_with("acct_"));
        assert!(!account.recovery_code.is_empty());
    }

    #[test]
    fn two_accounts_get_different_salts_and_recovery_codes() {
        // A real CSPRNG should never produce the same output twice in
        // a row in practice — this would only spuriously fail with
        // astronomically unlikely bad luck, same as any such test.
        let a = create_account();
        let b = create_account();
        assert_ne!(a.kdf_salt, b.kdf_salt);
        assert_ne!(a.recovery_code, b.recovery_code);
        assert_ne!(a.account_id, b.account_id);
    }

    #[test]
    fn derive_key_is_deterministic_for_the_same_secret_and_salt() {
        let salt = [7u8; 16];
        let a = derive_key("correct horse battery staple", &salt);
        let b = derive_key("correct horse battery staple", &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn different_salts_derive_different_keys_from_the_same_secret() {
        let a = derive_key("correct horse battery staple", &[1u8; 16]);
        let b = derive_key("correct horse battery staple", &[2u8; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = derive_key("my recovery code", &[9u8; 16]);
        let plaintext = b"bookmarks and settings blob";
        let ciphertext = encrypt(&key, plaintext);
        assert_ne!(ciphertext, plaintext);
        assert_eq!(
            decrypt(&key, &ciphertext).unwrap().as_slice(),
            &plaintext[..]
        );
    }

    #[test]
    fn two_encryptions_of_the_same_plaintext_produce_different_ciphertext() {
        // Proof the nonce is actually random per call — if it weren't,
        // encrypting the same plaintext twice under the same key would
        // produce identical ciphertext, which leaks that two messages
        // are the same even without breaking the cipher itself.
        let key = derive_key("my recovery code", &[9u8; 16]);
        let a = encrypt(&key, b"hello");
        let b = encrypt(&key, b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn decrypting_with_the_wrong_key_fails_instead_of_returning_garbage() {
        let key_a = derive_key("recovery code A", &[1u8; 16]);
        let key_b = derive_key("recovery code B", &[2u8; 16]);
        let ciphertext = encrypt(&key_a, b"secret bookmarks");
        assert!(decrypt(&key_b, &ciphertext).is_err());
    }

    #[test]
    fn decrypting_tampered_ciphertext_fails_instead_of_returning_garbage() {
        let key = derive_key("my recovery code", &[9u8; 16]);
        let mut ciphertext = encrypt(&key, b"secret bookmarks");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF; // flip bits in the authentication tag
        assert!(decrypt(&key, &ciphertext).is_err());
    }
}
