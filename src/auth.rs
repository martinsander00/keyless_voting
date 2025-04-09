use anyhow::{anyhow, Result};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationRequest, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl,
};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

pub struct GoogleAuthClient {
    client_id: String,
    client_secret: String,
}

pub struct AuthTokens {
    pub access_token: String,
    pub id_token: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
}

impl GoogleAuthClient {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self { client_id, client_secret }
    }

    /// Asynchronous authentication that accepts an optional nonce.
    pub async fn authenticate(&self, nonce: Option<&str>) -> Result<AuthTokens> {
        let nonce_owned = nonce.map(|s| s.to_owned());
        let client_id = self.client_id.clone();
        let client_secret = self.client_secret.clone();

        tokio::task::spawn_blocking(move || {
            Self::authenticate_blocking(&client_id, &client_secret, nonce_owned)
        })
        .await?
    }

    /// Blocking authentication which now accepts an optional nonce parameter.
    fn authenticate_blocking(
        client_id: &str,
        client_secret: &str,
        nonce: Option<String>,
    ) -> Result<AuthTokens> {
        let google_client_id = ClientId::new(client_id.to_string());
        let google_client_secret = ClientSecret::new(client_secret.to_string());
        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?;
        let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())?;

        // Set up a local redirect server.
        let listener = TcpListener::bind("127.0.0.1:8080")?;
        let redirect_url = RedirectUrl::new("http://localhost:8080".to_string())?;

        let client = BasicClient::new(
            google_client_id,
            Some(google_client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(redirect_url);

        // Build the authorization URL
        let mut auth_request: AuthorizationRequest = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ));

        if let Some(n) = &nonce {
            auth_request = auth_request.add_extra_param("nonce", n);
        }

        let (auth_url, _csrf_token) = auth_request.url();

        println!("Open this URL in your browser to authenticate with Google:");
        println!("{}", auth_url);

        if webbrowser::open(auth_url.as_ref()).is_ok() {
            println!("Browser opened automatically.");
        }

        println!("Waiting for authentication response on http://localhost:8080 ...");
        listener.set_nonblocking(false)?;

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    // Parse the OAuth callback request
                    let code = {
                        let mut reader = BufReader::new(&stream);
                        let mut request_line = String::new();
                        reader.read_line(&mut request_line)?;

                        let redirect_path = request_line
                            .split_whitespace()
                            .nth(1)
                            .ok_or_else(|| anyhow!("Invalid HTTP request line"))?;
                        let full_url_str = format!("http://localhost{}", redirect_path);
                        let url = Url::parse(&full_url_str)
                            .map_err(|e| anyhow!("Failed to parse redirect URL: {}", e))?;

                        url.query_pairs()
                            .find(|(key, _)| key == "code")
                            .map(|(_, value)| value.into_owned())
                            .ok_or_else(|| {
                                anyhow!("OAuth 'code' parameter not found in callback URL")
                            })?
                    };

                    // Respond to browser
                    let response = "\
                        HTTP/1.1 200 OK\r\n\
                        Content-Type: text/html\r\n\r\n\
                        <html><body>Authentication successful! You can close this window.</body></html>";
                    stream.write_all(response.as_bytes())?;
                    stream.shutdown(std::net::Shutdown::Both)?;

                    // Exchange code for tokens
                    let http_client = reqwest::blocking::Client::new();
                    let params = [
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("code", code.as_str()),
                        ("redirect_uri", "http://localhost:8080"),
                        ("grant_type", "authorization_code"),
                    ];

                    let token_response = http_client
                        .post("https://oauth2.googleapis.com/token")
                        .form(&params)
                        .send()?;

                    // FIX: extract status before consuming the response
                    let status = token_response.status();
                    if !status.is_success() {
                        let error_body = token_response
                            .text()
                            .unwrap_or_else(|_| "Failed to read error body".to_string());
                        return Err(anyhow!(
                            "Failed to exchange code for token: status {}, body: {}",
                            status,
                            error_body
                        ));
                    }

                    let token_json: Value = token_response.json()?;
                    let access_token = token_json["access_token"]
                        .as_str()
                        .ok_or_else(|| anyhow!("'access_token' not found in token response"))?
                        .to_string();
                    let id_token = token_json["id_token"].as_str().map(|s| s.to_string());

                    println!("Authentication successful!");
                    if id_token.is_some() {
                        println!("Retrieved ID token (JWT)");
                    } else {
                        println!("Warning: No ID token in response (is 'openid' scope included?)");
                    }

                    return Ok(AuthTokens {
                        access_token,
                        id_token,
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }

        Err(anyhow!(
            "Local server stopped before receiving authentication callback"
        ))
    }

    /// Retrieve user information from Google using the access token.
    pub async fn get_user_info(&self, access_token: &str) -> Result<UserInfo> {
        let client = reqwest::Client::new();
        let user_info_response = client
            .get("https://www.googleapis.com/oauth2/v1/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;

        if !user_info_response.status().is_success() {
            let status = user_info_response.status();
            let body = user_info_response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            return Err(anyhow!("Failed to get user info: status {}, body: {}", status, body));
        }

        let user_info: UserInfo = user_info_response.json().await?;
        Ok(user_info)
    }
}

