use anyhow::Result;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use serde::Deserialize;

pub fn build_http_client(timeout: u64) -> Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;
    Ok(client)
}

#[derive(Deserialize)]
struct IpApiResp {
    status: String,
    isp: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
}

pub async fn lookup_asn(ip: &IpAddr, client: &Client) -> Option<String> {
    let url = format!("http://ip-api.com/json/{}", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(data) = resp.json::<IpApiResp>().await {
            if data.status == "success" {
                if let Some(asn) = data.asn {
                    return Some(asn);
                } else if let Some(isp) = data.isp {
                    return Some(isp);
                }
            }
        }
    }
    None
}
