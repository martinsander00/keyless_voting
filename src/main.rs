use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use keyless_voting::auth::GoogleAuthClient;
use std::io::{self, Write};
use std::path::PathBuf;
// Import the vote protocol, choice enum, and keys module.
use voting_protocol::{VoteChoice, VotingProtocol};
use voting_protocol::keys::generate_keypair_and_nonce;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new election
    Init {
        /// The ID of the election
        #[arg(short, long)]
        election_id: String,
        /// Allowed email domains (comma-separated)
        #[arg(short, long)]
        domains: Option<String>,
        /// Path to the prover key
        #[arg(short, long)]
        prover_key: PathBuf,
        /// Path to the verifier key
        #[arg(short, long)]
        verifier_key: PathBuf,
    },

    /// Register as a voter
    Register {
        /// The ID of the election
        #[arg(short, long)]
        election_id: String,
    },

    /// Cast a vote
    Vote {
        /// The ID of the election
        #[arg(short, long)]
        election_id: String,
    },

    /// Tally the votes
    Tally {
        /// The ID of the election
        #[arg(short, long)]
        election_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    dotenv::dotenv().ok();
    // Load client_id and client_secret
    let client_id = std::env::var("CLIENT_ID")
        .expect("CLIENT_ID environment variable must be set");
    let client_secret = std::env::var("CLIENT_SECRET")
        .expect("CLIENT_SECRET environment variable must be set");

    // Create the Google auth client *once*
    let auth_client = GoogleAuthClient::new(client_id.clone(), client_secret.clone());

    match &cli.command {
        Commands::Init { election_id, domains, prover_key, verifier_key } => {
            // Init logic remains largely the same as it orchestrates the library's setup
            println!("Initializing election '{}'...", election_id);

            // Parse allowed domains
            let allowed_domains = match domains {
                Some(d) => d.split(',').map(|s| s.trim().to_string()).collect(),
                None => Vec::new(),
            };

            // Create and initialize the voting protocol using the library
            let mut protocol = VotingProtocol::new(
                election_id.to_string(),
                allowed_domains,
            );

            protocol.initialize(
                prover_key.to_str().ok_or_else(|| anyhow!("Invalid prover key path"))?,
                verifier_key.to_str().ok_or_else(|| anyhow!("Invalid verifier key path"))?,
            )?;

            // Save the initial state using the library method
            protocol.save_state()?;

            println!("Election initialized successfully!");
            if let Some(d) = domains {
                println!("Allowed email domains: {}", d);
            } else {
                println!("All email domains are allowed.");
            }
        }
        Commands::Register { election_id } => {
            println!("Registering for election '{}'...", election_id);

            // 1. Generate keypair and nonce locally
            let (esk, epk, exp_date_secs, nonce, blinder) = generate_keypair_and_nonce();
            println!("Generated nonce: {}", nonce); // Nonce might be needed for auth challenge

            // 2. Authenticate user
            println!("Please authenticate with Google to verify your email address.");
            // Pass the nonce into authenticate.
            let auth_tokens = auth_client.authenticate(Some(nonce.as_str())).await?;
            let id_token = auth_tokens.id_token.clone().ok_or_else(|| {
                anyhow!("No ID token received from Google. Please try again.")
            })?;
            let user_info = auth_client.get_user_info(&auth_tokens.access_token).await?;
            println!("Authenticated as: {}", user_info.email);

            // 3. Load protocol state
            let mut protocol = load_protocol(election_id)?;
            protocol.set_pepper_service("http://localhost:8000"); // Configure pepper service

            // 4. Call library's register function
            // Pass the generated keypair along with the token
            protocol.register_user(&id_token, (esk, epk), exp_date_secs, blinder).await?;
            println!("Registration successful!");

            // 5. Save the updated protocol state
            protocol.save_state()?;
        }
        Commands::Vote { election_id } => {
            println!("Voting in election '{}'...", election_id);

            // 1. Authenticate user (re-auth might be needed to ensure freshness/validity)
            println!("Please authenticate with Google to proceed with voting.");
            let auth_tokens = auth_client.authenticate(None).await?;
            let id_token = auth_tokens.id_token.clone().ok_or_else(|| {
                anyhow!("No ID token received from Google. Please try again.")
            })?;
            let user_info = auth_client.get_user_info(&auth_tokens.access_token).await?;
            println!("Authenticated as: {}", user_info.email);


            // 2. Get vote choice from user
            println!("Please enter your vote (yes/no/abstain):");
            io::stdout().flush()?;
            let mut choice_str = String::new();
            io::stdin().read_line(&mut choice_str)?;
            let choice = match choice_str.trim().to_lowercase().as_str() {
                "yes" => VoteChoice::Yes,
                "no" => VoteChoice::No,
                "abstain" => VoteChoice::Abstain,
                _ => return Err(anyhow!("Invalid vote choice. Please enter 'yes', 'no', or 'abstain'.")),
            };

            // 3. Load protocol state
            let mut protocol = load_protocol(election_id)?;
            protocol.set_pepper_service("http://localhost:8000"); // Configure pepper service

            // 4. Get user's EPK from the loaded state
            // We need the EPK to pass to cast_vote, as per the library signature
             let epk = protocol.get_user_epk(&user_info.email)?;


            // 5. Call library's cast_vote function
            protocol.cast_vote(&id_token, &epk, choice).await?;
            println!("Vote cast successfully!");

            // 6. Save the updated protocol state
            protocol.save_state()?;
        }
        Commands::Tally { election_id } => {
            println!("Tallying votes for election '{}'...", election_id);

            // 1. Load protocol state
            // No need for mutability here if load_protocol returns an owned VotingProtocol
            let protocol = load_protocol(election_id)?;

            // 2. Call library's tally function
            let tally = protocol.tally_votes();

            // 3. Print results (display logic remains in the CLI)
            println!("===== Vote Tally =====");
            println!("Yes: {}", tally.yes_votes);
            println!("No: {}", tally.no_votes);
            println!("Abstain: {}", tally.abstain_votes);
            println!("Total votes: {}", tally.total_votes);

            // Calculate percentages (excluding abstentions)
            let voting_votes = tally.yes_votes + tally.no_votes;
            if voting_votes > 0 {
                let yes_percent = (tally.yes_votes as f64 / voting_votes as f64) * 100.0;
                let no_percent = (tally.no_votes as f64 / voting_votes as f64) * 100.0;

                println!("Yes: {:.2}%", yes_percent);
                println!("No: {:.2}%", no_percent);
            }
            // No need to save state after tallying
        }
    }

    Ok(())
}

// Helper function to load the voting protocol state using the library method
fn load_protocol(election_id: &str) -> Result<VotingProtocol> {
    // Create a new, empty protocol instance first.
    // The election_id is needed to know *where* to load from.
    // Allowed domains will be overwritten by load_state.
    let mut protocol = VotingProtocol::new(
        election_id.to_string(),
        Vec::new(),
    );

    // Call the library's load_state method
    protocol.load_state()?; // This populates the fields from the saved state file

    Ok(protocol)
}
