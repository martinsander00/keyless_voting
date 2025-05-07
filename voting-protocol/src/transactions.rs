use anyhow::Result;
use aptos_rest_client::Client;
use aptos_sdk::types::{LocalAccount, KeylessAccount, EphemeralKeyPair, EphemeralPrivateKey};
use aptos_types::{
    transaction::{TransactionPayload, Script},
    keyless::{self, Claims, Pepper, ZeroKnowledgeSig, ZKP, Groth16Proof},
    transaction::authenticator::{EphemeralPublicKey, EphemeralSignature},
    chain_id::ChainId,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use url::Url;
use crate::pepper_integration::ProverResponse;

// Import G1Bytes and G2Bytes
use aptos_types::keyless::{G1Bytes, G2Bytes};

// Import your Ed25519 private key type
use aptos_crypto::ed25519::Ed25519PrivateKey;

// Hardcoded values for simplicity
const APTOS_NODE_URL: &str = "http://localhost:8080";

/// Submit a registration transaction to the Aptos blockchain
pub async fn submit_register_transaction(
    jwt_token: &str,
    proof_response: &ProverResponse,
    esk: &Ed25519PrivateKey,               
    epk: &EphemeralPublicKey,              
    exp_date_secs: u64,
    pepper: &Vec<u8>,
    blinder: [u8; 31],                    
) -> Result<()> {
    // Create Aptos client
    let client = Client::new(Url::parse(APTOS_NODE_URL)?);
    
    // Extract parts from JWT
    let parts: Vec<&str> = jwt_token.split('.').collect();
    let header_bytes = base64::engine::general_purpose::STANDARD.decode(parts[0])?;
    let jwt_header_json = String::from_utf8(header_bytes)?;
    
    let jwt_payload_json = URL_SAFE.decode(parts[1])?;
    let claims: Claims = serde_json::from_slice(&jwt_payload_json)?;
    
    let iss = claims.oidc_claims.iss.clone();
    let aud = claims.oidc_claims.aud.clone();
    let uid_key = "sub".to_string();
    let uid_val = claims.get_uid_val(&uid_key)?;
    
    // Create Pepper from bytes - now uses fixed size array
    let mut pepper_array = [0u8; 31];
    pepper_array.copy_from_slice(&pepper[..31]);
    let pepper_obj = Pepper::new(pepper_array);
    
    // Convert to Groth16Proof
    let proof_bytes_a = hex::decode(&proof_response.proof.a)?;
    let proof_bytes_b = hex::decode(&proof_response.proof.b)?;
    let proof_bytes_c = hex::decode(&proof_response.proof.c)?;
    
    // Create a Groth16Proof
    let groth16_proof = Groth16Proof::new(
        G1Bytes::new_from_vec(proof_bytes_a)?,
        G2Bytes::new_from_vec(proof_bytes_b)?,
        G1Bytes::new_from_vec(proof_bytes_c)?
    );
    
    // Create ZKP
    let zkp = ZKP::Groth16(groth16_proof);
    
    // Convert training wheels signature
    let training_wheels_sig = EphemeralSignature::try_from(
        hex::decode(&proof_response.training_wheels_signature)?.as_slice()
    )?;
    
    // Create ZeroKnowledgeSig
    let zk_sig = ZeroKnowledgeSig {
        proof: zkp,
        exp_horizon_secs: 10000000, // Standard value for devnet
        extra_field: None,
        override_aud_val: None,
        training_wheels_signature: Some(training_wheels_sig),
    };

    let config = keyless::Configuration::new_for_devnet();

    let eph_private_key = EphemeralPrivateKey::Ed25519 {
        inner_private_key: esk.clone(),
    };

    let eph_key_pair = EphemeralKeyPair::new_ed25519(
        esk.clone(),            
        exp_date_secs,
        blinder.to_vec(),       
    )?;

    // Create KeylessAccount
    let keyless_account = KeylessAccount::new(
        &iss,
        &aud,
        &uid_key,
        &uid_val,
        &jwt_header_json,
        eph_key_pair,
        pepper_obj,
        zk_sig,
    )?;
    
    // Create LocalAccount
    let local_account = LocalAccount::new_keyless(
        keyless_account.authentication_key().account_address(),
        keyless_account,
        0,
    );
    
    // Create a registration script (empty here as placeholder)
    let script = Script::new(
        vec![], // bytecode
        vec![], // ty_args
        vec![], // args
    );
    
    // Create the transaction payload
    let payload = TransactionPayload::Script(script);
    
    let gas_unit_price = 100;
    let chain_id = ChainId::new(1); // Example value for devnet
    
    let builder = aptos_sdk::transaction_builder::TransactionBuilder::new(
        payload,
        gas_unit_price,
        chain_id
    );
    
    // Sign transaction
    let signed_tx = local_account.sign_with_transaction_builder(builder);
    
    // Submit transaction and wait for confirmation
    let response = client.submit(&signed_tx).await?;
    println!("Transaction submitted successfully: {:?}", response);
    
    client.wait_for_transaction(response.inner()).await?;
    println!("Transaction confirmed on blockchain!");
    
    Ok(())
}
