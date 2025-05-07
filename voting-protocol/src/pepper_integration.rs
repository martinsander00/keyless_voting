use anyhow::{anyhow, Result};
use serde::{Deserialize};
use aptos_types::transaction::authenticator::EphemeralPublicKey;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct Proof {
    pub a: String,
    pub b: String,
    pub c: String,
}

#[derive(Debug, Deserialize)]
pub struct ProverResponse {
    pub proof: Proof,
    pub public_inputs_hash: String,
    pub training_wheels_signature: String,
}

pub async fn generate_proof(
    jwt: &str,
    epk: &EphemeralPublicKey,
    exp_date: u64,
    blinder: &[u8; 31],
    pepper: &Vec<u8>,
) -> Result<ProverResponse> {
    let client = reqwest::Client::new();
    
    let blinder_hex = blinder.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let pepper_hex = pepper.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let request = json!({
        "epk": hex::encode(epk.to_bytes()),
        "epk_blinder": blinder_hex,
        "exp_date_secs": exp_date,
        "exp_horizon_secs": 10000000,
        "jwt_b64": jwt,
        "pepper": pepper_hex,
        "uid_key": "email"
    });

    println!("Request JSON: {}", serde_json::to_string_pretty(&request)?);

    // Send request to the prover service
    let response = client.post("http://localhost:8083/v0/prove")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(anyhow!("Prover service error: {}", error_text));
    }

    // Debug response
    let response_text = response.text().await?;
    // println!("Raw response: {}", response_text);

    match serde_json::from_str::<ProverResponse>(&response_text) {
        Ok(proof_response) => Ok(proof_response),
        Err(e) => {
            println!("JSON parsing error: {}", e);
            println!("Response structure doesn't match expected format.");
            Err(anyhow!("Failed to parse prover response: {}", e))
        }
    }
}