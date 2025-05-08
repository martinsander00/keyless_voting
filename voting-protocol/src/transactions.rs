use crate::pepper_integration::ProverResponse;
use anyhow::{anyhow, Result};
use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_rest_client::Client;
use aptos_sdk::{
    rest_client::FaucetClient,
    types::{EphemeralKeyPair, EphemeralPrivateKey, KeylessAccount, LocalAccount},
};
use aptos_types::{
    chain_id::ChainId,
    keyless::{self, Claims, Configuration, Groth16Proof, Pepper, ZeroKnowledgeSig, ZKP},
    transaction::{authenticator::{EphemeralPublicKey, EphemeralSignature}, Script, TransactionPayload},
};
use aptos_types::keyless::{G1Bytes, G2Bytes};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD}, Engine as _};
use move_core_types::account_address::AccountAddress;
use url::Url;

const APTOS_NODE_URL: &str = "https://fullnode.devnet.aptoslabs.com";
const APTOS_FAUCET_URL: &str = "https://faucet.devnet.aptoslabs.com";

pub async fn submit_register_transaction(
    jwt_token: &str,
    proof_response: &ProverResponse,
    esk: &Ed25519PrivateKey,
    epk: &EphemeralPublicKey,
    exp_date_secs: u64,
    pepper: &Vec<u8>,
    blinder: [u8; 31],
) -> Result<()> {
    // REST clients
    let node_url = Url::parse(APTOS_NODE_URL)?;
    let faucet_url = Url::parse(APTOS_FAUCET_URL)?;
    let client = Client::new(node_url.clone());
    let faucet_client = FaucetClient::new(faucet_url, node_url);

    // Decode JWT
    let parts: Vec<&str> = jwt_token.split('.').collect();
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|e| anyhow!("Failed to decode JWT header: {}", e))?;
    let jwt_header_json = String::from_utf8(header_bytes)
        .map_err(|e| anyhow!("Failed to parse JWT header as UTF-8: {}", e))?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|e| anyhow!("Failed to decode JWT payload: {}", e))?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("Failed to parse JWT claims: {}", e))?;

    let iss = claims.oidc_claims.iss.clone();
    let aud = claims.oidc_claims.aud.clone();
    let uid_key = "sub".to_string();
    let uid_val = claims.get_uid_val(&uid_key)?;

    // Prepare pepper
    let mut pepper_array = [0u8; 31];
    pepper_array.copy_from_slice(&pepper[..31]);
    let pepper_obj = Pepper::new(pepper_array);

    // Build Groth16 proof
    let proof_bytes_a = hex::decode(&proof_response.proof.a)?;
    let proof_bytes_b = hex::decode(&proof_response.proof.b)?;
    let proof_bytes_c = hex::decode(&proof_response.proof.c)?;
    let groth16_proof = Groth16Proof::new(
        G1Bytes::new_from_vec(proof_bytes_a)?,
        G2Bytes::new_from_vec(proof_bytes_b)?,
        G1Bytes::new_from_vec(proof_bytes_c)?,
    );
    let zkp = ZKP::Groth16(groth16_proof);

    // Training-wheels signature
    let training_wheels_sig = EphemeralSignature::try_from(
        hex::decode(&proof_response.training_wheels_signature)?.as_slice()
    )?;
    let zk_sig = ZeroKnowledgeSig {
        proof: zkp,
        exp_horizon_secs: 1_000_000,
        extra_field: None,
        override_aud_val: None,
        training_wheels_signature: Some(training_wheels_sig),
    };

    // Fetch on-chain keyless Configuration
    let onchain_cfg = client
        .get_account_resource_bcs::<Configuration>(
            AccountAddress::ONE,
            &format!("0x1::{}::Configuration", keyless::KEYLESS_ACCOUNT_MODULE_NAME),
        )
        .await?
        .into_inner();

    // EphemeralKey debugging
    let esk_for_config = EphemeralPrivateKey::Ed25519 { inner_private_key: esk.clone() };
    let esk_for_pub    = EphemeralPrivateKey::Ed25519 { inner_private_key: esk.clone() };
    let eph_key_pair = EphemeralKeyPair::new_with_keyless_config(
        &onchain_cfg,
        esk_for_config,
        exp_date_secs,
        blinder.to_vec(),
    )?;

    let derived_epk = esk_for_pub.public_key();
    println!("▶ derived_epk: {}", hex::encode(derived_epk.to_bytes()));
    println!("▶ prover_epk : {}", hex::encode(epk.to_bytes()));
    assert_eq!(
        derived_epk.to_bytes(),
        epk.to_bytes(),
        "ERROR: Ephemeral public key mismatch"
    );

    // Build KeylessAccount
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

    // Prepare LocalAccount
    let account_address = keyless_account.authentication_key().account_address();
    println!("Account address: {}", account_address);
    let sequence_number = 0u64;
    println!("Using sequence number: {}", sequence_number);
    let local_account = LocalAccount::new_keyless(
        account_address,
        keyless_account,
        sequence_number,
    );

    // Fund new account
    println!("Funding account {} from faucet...", account_address);
    faucet_client
        .fund(account_address, 100_000_000)
        .await
        .map_err(|e| anyhow!("Failed to fund account: {}", e))?;
    println!("Account funded successfully!");

    // Minimal transaction payload: RET
    let payload = TransactionPayload::Script(Script::new(vec![0x02], vec![], vec![]));

    // Gas and chain parameters
    let ledger_info = client.get_ledger_information().await?.into_inner();
    let chain_id = ChainId::new(ledger_info.chain_id);
    println!("▶ devnet chain_id from node: {}", ledger_info.chain_id);

    // Build, sign, submit
    let builder = aptos_sdk::transaction_builder::TransactionBuilder::new(
        payload,
        100, // Gas price
        chain_id,
    )
    .sender(account_address)
    .sequence_number(sequence_number)
    .max_gas_amount(2_000_000)
    .expiration_timestamp_secs(exp_date_secs);

    println!("Signing transaction with sequence number: {}", sequence_number);
    let signed_tx = local_account.sign_with_transaction_builder(builder);

    println!("Submitting transaction to devnet...");
    let response = client.submit(&signed_tx).await?;
    println!("Transaction submitted successfully: {:?}", response);
    client.wait_for_transaction(response.inner()).await?;
    println!("Transaction confirmed on blockchain!");

    Ok(())
}
