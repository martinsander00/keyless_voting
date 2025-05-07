use anyhow::{Result};
use reqwest::Client;
use sha2::{Sha256, Digest};
use rand::RngCore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use aptos_types::transaction::authenticator::EphemeralPublicKey;
use aptos_keyless_pepper_common::{
    jwt, vuf::{self, VUF}, PepperInput, PepperRequest, PepperResponse, PepperV0VufPubKey, SignatureResponse,
};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use reqwest::StatusCode;

#[derive(Debug)]
pub struct PepperServiceClient {
    client: Client,
    base_url: String,
}

impl PepperServiceClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    pub async fn get_pepper_and_vuf(&self, jwt: &str, epk: &EphemeralPublicKey, exp_date_secs: u64, blinder: [u8; 31]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Get the pepper VUF
        let vuf_pub_key_url = format!("{}/v0/vuf-pub-key", self.base_url);
        let fetch_url = format!("{}/v0/fetch", self.base_url);
        let sig_url = format!("{}/v0/signature", self.base_url);
        let response = self.client
            .get(vuf_pub_key_url)
            .send()
            .await
            .unwrap()
            .json::<PepperV0VufPubKey>()
            .await
            .unwrap();

        // Here is the VUF
        let PepperV0VufPubKey { public_key: ref vuf_pk } = response;
        let vuf_pk: ark_bls12_381::G2Projective =
            ark_bls12_381::G2Affine::deserialize_with_mode(
                vuf_pk.as_slice(),
                Compress::Yes,
                Validate::Yes,
            )
            .unwrap()
            .into();

        println!();
        println!(
            "response_json={}",
            serde_json::to_string_pretty(&response).unwrap()
        );
        
        println!("Client: nonce = {:?}", extract_jwt_nonce(&jwt));

        // Create a PepperRequest object.
        let request = PepperRequest {
            jwt: jwt.to_string(),
            epk: epk.clone(),
            exp_date_secs,
            uid_key: None,
            epk_blinder: blinder.to_vec(),
            derivation_path: None,
        };

        // Serialize to JSON with proper field order.
        let json_str = serde_json::to_string_pretty(&request)
            .expect("Failed to serialize request");
        println!("Sending request: {}", json_str);

        let pepper_raw_response = self.client
            .post(&format!("{}/v0/fetch", self.base_url))
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, pepper_raw_response.status());

        let pepper_response = pepper_raw_response.json::<PepperResponse>().await.unwrap();
        println!();
        println!(
            "pepper_service_response={}",
            serde_json::to_string_pretty(&pepper_response).unwrap()
        );

        let PepperResponse { ref pepper, address } = pepper_response;

        let signature_raw_response = self.client
            .post(sig_url)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, signature_raw_response.status());
        let signature_response = signature_raw_response
            .json::<SignatureResponse>()
            .await
            .unwrap();

        println!(
            "signature_response={}",
            serde_json::to_string_pretty(&signature_response).unwrap()
        );

        let SignatureResponse { signature } = signature_response;

        println!("signature={:?}", hex::encode(signature.clone()));
        println!("pepper={:?}", hex::encode(pepper.clone()));
        println!("address={:?}", hex::encode(address.clone()))
        ;

        let claims = jwt::parse(jwt).unwrap();

        println!();
        println!("Verify the pepper against the server's verification key, part of the JWT, and the actual aud.");

        let pepper_input = PepperInput {
            iss: claims.claims.iss.clone(),
            uid_key: "sub".to_string(),
            uid_val: claims.claims.sub.clone(),
            aud: claims.claims.aud.clone(),
        };
        let pepper_input_bytes = bcs::to_bytes(&pepper_input).unwrap();
        vuf::bls12381_g1_bls::Bls12381G1Bls::verify(&vuf_pk, &pepper_input_bytes, &signature, &[])
            .unwrap();
        println!("Pepper verification succeeded!");

        Ok((pepper.clone(), response.public_key.clone()))
    }
}

pub fn calculate_anonymous_id(pepper: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pepper);
    
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result[..]);
    bytes.to_vec()
}

fn extract_jwt_nonce(jwt: &str) -> Option<String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    // JWT payload is the second part
    let payload_b64 = parts[1];
    // Decode URL-safe base64 (no padding)
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    // Parse as JSON
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    // Pull out the "nonce" field as a string
    payload.get("nonce")?.as_str().map(|s| s.to_string())
}

/// Create a nullifier from a pepper and an election ID.
#[warn(dead_code)]
pub fn create_nullifier(pepper: &[u8], election_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pepper);
    hasher.update(election_id.as_bytes());

    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result[..]);
    bytes
}