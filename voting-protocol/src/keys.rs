use rand::RngCore;
use hex;
use std::time::{SystemTime, UNIX_EPOCH};
use aptos_types::{
    keyless::{Configuration, OpenIdSig},
    transaction::authenticator::EphemeralPublicKey,
};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};

/// Generates a new ephemeral keypair and computes:
/// - a blinder
/// - an expiry timestamp (`exp_date_secs`)
/// - a nonce by hashing `epk || blinder || exp_date_secs`
///
/// Returns a tuple of:
/// - The ephemeral secret key (esk)
/// - The ephemeral public key (epk)
/// - The expiry timestamp (exp_date_secs)
/// - The nonce as a hex string
pub fn generate_keypair_and_nonce() -> (
    Ed25519PrivateKey,
    EphemeralPublicKey,
    u64,
    String,
    [u8; 31],
) {
    // 1) Generate the keypair
    let esk_bytes =
        hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let serialized: &[u8] = esk_bytes.as_slice();
    let esk = Ed25519PrivateKey::try_from(serialized).unwrap();
    let epk = EphemeralPublicKey::ed25519(Ed25519PublicKey::from(&esk));
    println!("esk_hexlified={}", hex::encode(esk.to_bytes()));
    println!("epk_hexlified={}", hex::encode(epk.to_bytes()));

    // 2) Generate a 31‑byte blinder
    let blinder: [u8; 31] = [0u8; 31];
    println!("blinder_hexlified={}", hex::encode(blinder));

    // 3) Compute expiry time (1 hour from now)
    let exp_date_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before UNIX EPOCH!")
        .as_secs()
        + 3600;

    // 4) Compute nonce = H(epk || blinder || exp_date_secs)
    let nonce = OpenIdSig::reconstruct_oauth_nonce(
        blinder.as_slice(),
        exp_date_secs,
        &epk,
        &Configuration::new_for_devnet(),
    ).unwrap();

    (esk, epk, exp_date_secs, nonce, blinder)
}
