use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub status: u16,
    pub title: Option<String>,
    pub similarity_score: f64,
    pub has_favicon: bool,
    pub has_login_form: bool,
    pub brand_title_match: bool,
}

pub async fn fetch_and_fingerprint(
    fqdn: &str,
    client: &Client,
    baseline: &Option<String>,
    _timeout: u64,
    brand_domain: &str,
) -> Result<HttpInfo> {
    let url = format!("http://{}", fqdn);
    let response = client.get(&url).send().await?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    
    let text_lower = text.to_lowercase();
    
    // Page Title Similarity
    let mut title = None;
    let mut brand_title_match = false;
    
    if let Some(start) = text_lower.find("<title>") {
        if let Some(end) = text_lower[start..].find("</title>") {
            let extracted_title = text[start + 7..start + end].trim().to_string();
            let brand_clean = brand_domain.split('.').next().unwrap_or(brand_domain).to_lowercase();
            
            if extracted_title.to_lowercase().contains(&brand_clean) || 
               strsim::jaro_winkler(&extracted_title.to_lowercase(), &brand_clean) > 0.85 {
                brand_title_match = true;
            }
            title = Some(extracted_title);
        }
    }
    
    // Favicon Extraction
    let has_favicon = text_lower.contains("<link rel=\"icon\"") || text_lower.contains("<link rel=\"shortcut icon\"");
    
    // Credential Harvest Forms
    let has_login_form = text_lower.contains("<input type=\"password\"") || 
                         text_lower.contains("<form action=") ||
                         text_lower.contains("login") ||
                         text_lower.contains("signin") ||
                         text_lower.contains("verify");

    let mut similarity_score = 0.0;
    if let Some(base) = baseline {
        similarity_score = strsim::jaro_winkler(&text_lower, &base.to_lowercase());
    }

    Ok(HttpInfo {
        status,
        title,
        similarity_score,
        has_favicon,
        has_login_form,
        brand_title_match,
    })
}
