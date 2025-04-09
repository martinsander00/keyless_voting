pub mod keys;

mod pepper;

use pepper::{PepperServiceClient};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::sync::Arc;
use tokio::sync::Mutex;
use aptos_types::{
    transaction::authenticator::EphemeralPublicKey,
};
use aptos_crypto::ed25519::{Ed25519PrivateKey};

/// Possible vote choices
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

/// Vote tally results
#[derive(Debug, Serialize, Deserialize)]
pub struct VoteTally {
    pub yes_votes: usize,
    pub no_votes: usize,
    pub abstain_votes: usize,
    pub total_votes: usize,
}

/// User registration record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRecord {
    email: String,
    epk: EphemeralPublicKey,
    has_voted: bool,
    pepper: Option<Vec<u8>>,
}

/// Vote record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VoteRecord {
    nullifier: [u8; 32],
    choice: VoteChoice,
}

/// JWT Claims structure
#[derive(Debug, Deserialize)]
struct JwtClaims {
    email: String,
    email_verified: Option<bool>,
    // Add other fields as needed
}

/// Voting protocol state
#[derive(Debug, Serialize, Deserialize)]
pub struct VotingProtocol {
    election_id: String,
    allowed_domains: Vec<String>,
    users: HashMap<String, UserRecord>,
    votes: Vec<VoteRecord>,
    #[serde(skip)]
    pepper_client: Option<Arc<Mutex<PepperServiceClient>>>,
}

// Go from base64 to binary
fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(input)
}

impl VotingProtocol {
    pub fn new(election_id: String, allowed_domains: Vec<String>) -> Self {
        Self {
            election_id,
            allowed_domains,
            users: HashMap::new(),
            votes: Vec::new(),
            pepper_client: None,
        }
    }

    /// Initialize the voting protocol
    pub fn initialize(&mut self, _prover_key_path: &str, _verifier_key_path: &str) -> Result<()> {
        Ok(())
    }

    pub fn set_pepper_service(&mut self, url: &str) {
        self.pepper_client = Some(Arc::new(Mutex::new(
            PepperServiceClient::new(url)
        )));
    }

    pub async fn register_user(
        &mut self,
        jwt_token: &str,
        keypair: (Ed25519PrivateKey, EphemeralPublicKey),
        exp_date_secs: u64,
        blinder: [u8; 31],
    ) -> Result<(Ed25519PrivateKey, EphemeralPublicKey)> {
        // Extract the email from the JWT token
        let email = self.extract_email_from_jwt(jwt_token)?;

        // Check if the email domain is allowed
        if !self.is_domain_allowed(&email) {
            return Err(anyhow!("Email domain not allowed: {}", email));
        }

        // Check if the user is already registered.
        if self.users.contains_key(&email) {
            return Err(anyhow!("User already registered: {}", email));
        }

        let (esk, epk) = keypair;

        println!("Using provided ephemeral public key: {:?}", hex::encode(epk.to_bytes()));

        // Get the pepper from the pepper service.
        let pepper = match &self.pepper_client {
            Some(client) => {
                let client = client.lock().await;
                client.get_pepper(jwt_token, &epk, exp_date_secs, blinder).await?
            },
            None => return Err(anyhow!("Pepper service not configured")),
        };

        // Register the user using the provided keypair.
        let user_record = UserRecord {
            email: email.clone(),
            epk: epk.clone(),
            has_voted: false,
            pepper: Some(pepper),
        };

        self.users.insert(email, user_record);
        Ok((esk, epk))
    }

    /// Cast a vote with a provided EPK (compatibility method)
    pub async fn cast_vote(&mut self, jwt_token: &str, epk: &EphemeralPublicKey, choice: VoteChoice) -> Result<()> {
        // Extract email from JWT token
        let email = self.extract_email_from_jwt(jwt_token)?;

        // Check if the user is registered
        let user = self.users.get_mut(&email)
            .ok_or_else(|| anyhow!("User not registered: {}", email))?;

        // Check if the user has already voted
        if user.has_voted {
            return Err(anyhow!("User has already voted: {}", email));
        }

        // Verify the EPK
        if &user.epk != epk {
            return Err(anyhow!("EPK does not match registered EPK for user: {}", email));
        }

        // Create nullifier from pepper and election ID
        // let nullifier = create_nullifier(&pepper, &self.election_id);

        // Record the vote
        // let vote_record = VoteRecord {
        //     nullifier,
        //     choice,
        // };

        // self.votes.push(vote_record);
        // user.has_voted = true;
        Ok(())
    }

    /// Get a user's EPK
    pub fn get_user_epk(&self, email: &str) -> Result<EphemeralPublicKey> {
        let user = self.users.get(email)
            .ok_or_else(|| anyhow!("User not registered: {}", email))?;

        Ok(user.epk.clone())
    }

    /// Tally the votes
    pub fn tally_votes(&self) -> VoteTally {
        let mut yes_votes = 0;
        let mut no_votes = 0;
        let mut abstain_votes = 0;

        for vote in &self.votes {
            match vote.choice {
                VoteChoice::Yes => yes_votes += 1,
                VoteChoice::No => no_votes += 1,
                VoteChoice::Abstain => abstain_votes += 1,
            }
        }

        VoteTally {
            yes_votes,
            no_votes,
            abstain_votes,
            total_votes: self.votes.len(),
        }
    }

    /// Save the protocol state to disk
    pub fn save_state(&self) -> Result<()> {
        let state_dir = format!("data/{}", self.election_id);
        let state_path = format!("{}/state.json", state_dir);

        // Create the directory if it doesn't exist
        fs::create_dir_all(&state_dir)?;

        // Serialize and save the state
        let state_json = serde_json::to_string(self)?;
        fs::write(state_path, state_json)?;

        Ok(())
    }

    /// Load the protocol state from disk
    pub fn load_state(&mut self) -> Result<()> {
        let state_path = format!("data/{}/state.json", self.election_id);

        // Check if the state file exists
        if !Path::new(&state_path).exists() {
            return Err(anyhow!("State file not found: {}", state_path));
        }

        // Load and deserialize the state
        let state_json = fs::read_to_string(state_path)?;
        let state: VotingProtocol = serde_json::from_str(&state_json)?;

        // Update the current instance
        self.allowed_domains = state.allowed_domains;
        self.users = state.users;
        self.votes = state.votes;

        Ok(())
    }

    /// Helper: Check if an email domain is allowed
    fn is_domain_allowed(&self, email: &str) -> bool {
        // If no domains are specified, allow all
        if self.allowed_domains.is_empty() {
            return true;
        }

        // Extract the domain from the email
        if let Some(domain) = email.split('@').nth(1) {
            return self.allowed_domains.iter().any(|d| d == domain);
        }

        false
    }

    /// Helper: Extract email from JWT token
    fn extract_email_from_jwt(&self, jwt_token: &str) -> Result<String> {
        // Simple JWT parsing without full verification
        // In a real implementation, you should use a JWT library to verify the token
        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid JWT token format"));
        }

        // Decode the payload (second part)
        let payload_base64 = parts[1];
        let payload_json = match decode(payload_base64) {
            Ok(bytes) => String::from_utf8(bytes)
                .map_err(|_| anyhow!("Invalid JWT payload encoding"))?,
            Err(_) => {
                // Try with URL-safe base64
                let payload_base64 = payload_base64.replace('-', "+").replace('_', "/");
                let padding = payload_base64.len() % 4;
                let payload_base64 = if padding > 0 {
                    payload_base64 + &"=".repeat(4 - padding)
                } else {
                    payload_base64
                };

                let bytes = decode(&payload_base64)
                    .map_err(|_| anyhow!("Invalid JWT payload encoding"))?;
                String::from_utf8(bytes)
                    .map_err(|_| anyhow!("Invalid JWT payload encoding"))?
            }
        };

        // Parse the payload as JSON
        let claims: JwtClaims = serde_json::from_str(&payload_json)
            .map_err(|_| anyhow!("Invalid JWT payload format"))?;

        // Check if the email is verified (optional)
        if let Some(verified) = claims.email_verified {
            if !verified {
                return Err(anyhow!("Email not verified"));
            }
        }

        Ok(claims.email)
    }
}
