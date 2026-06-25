use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub registrar: Option<String>,
    pub creation_date: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn query(_fqdn: &str) -> Result<WhoisInfo> {
    // Stub implementation to allow project to compile.
    // In a full implementation, we would use the whois-rust crate to query WHOIS servers
    // and parse the response text for "Registrar:" and "Creation Date:".
    Ok(WhoisInfo {
        registrar: Some("Stub Registrar".to_string()),
        creation_date: Some(chrono::Utc::now()),
    })
}
