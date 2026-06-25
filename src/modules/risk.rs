// src/modules/risk.rs
use serde::{Deserialize, Serialize};
use crate::modules::{dns::DnsInfo, tls::TlsInfo, whois::WhoisInfo, http::HttpInfo, typo::DomainVariant};

// ─── Threat Intel: High-Risk Infrastructure ─────────────────────────────────
// A baseline list of ASNs or Organization names notorious for ignoring abuse 
// complaints, bulletproof hosting, or high volumes of automated EASM threats.
static HIGH_RISK_ASN_KEYWORDS: &[&str] = &[
    "AS206264",   // Hostinger (Heavy volume of cheap/free tier abuse)
    "AS132203",   // Tencent Cloud (Frequent lookalike hosting)
    "AS45102",    // Alibaba (Often used for short-lived malicious infra)
    "AS14061",    // DigitalOcean (Automated droplet abuse)
    "AS20473",    // Choopa / Vultr (High abuse rate)
    "DDOS-GUARD", // Known bulletproof proxy/hosting
    "FLOKINET",   // Offshore / bulletproof hosting
    "OFFSHORE",
    "ALEXHOST",
    "SHINJIRU",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreCard {
    pub total: u8,
    pub label: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub variant: DomainVariant,
    pub dns: DnsInfo,
    pub mx_active: bool,
    pub tls: Option<TlsInfo>,
    pub whois: Option<WhoisInfo>,
    pub http: Option<HttpInfo>,
    pub risk_score: u8,
    pub risk_label: String,
    pub indicators: Vec<String>,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

pub struct RiskEngine;

impl RiskEngine {
    pub fn new() -> Self { Self }

    pub fn score(
        &self,
        dns: &DnsInfo,
        mx_active: bool,
        tls: &Option<TlsInfo>,
        whois: &Option<WhoisInfo>,
        http: &Option<HttpInfo>,
    ) -> ScoreCard {
        let mut score: u32 = 0;
        let mut indicators = Vec::new();

        // 1. DNS Resolution
        if !dns.resolves {
            return ScoreCard { total: 0, label: "Inactive".to_string(), indicators };
        }
        score += 20;
        indicators.push("Active Live DNS Resolution".to_string());

        // 2. ASN / Infrastructure Reputation Weighting
        if let Some(asn) = &dns.asn_hint {
            let asn_upper = asn.to_uppercase();
            
            // Explicit check for bulletproof / abused cloud infra
            let abused_clouds = ["VULTR", "DIGITALOCEAN", "HOSTINGER", "TENCENT"];
            let mut cloud_matched = None;
            for &cloud in &abused_clouds {
                if asn_upper.contains(cloud) {
                    cloud_matched = Some(cloud);
                    break;
                }
            }

            if let Some(cloud) = cloud_matched {
                score += 20;
                indicators.push(format!("Heavily Abused Cloud Infra / Bulletproof Hosting Detected ({})", cloud));
            } else {
                let is_high_risk = HIGH_RISK_ASN_KEYWORDS
                    .iter()
                    .any(|&keyword| asn_upper.contains(keyword));

                if is_high_risk {
                    score += 20;
                    indicators.push(format!("High-Risk Infrastructure / ASN Detected ({})", asn));
                }
            }
        }

        // 3. MX Records (Active Phishing Capability)
        if mx_active {
            score += 30;
            indicators.push("Active Mail Exchanger (MX Records Setup)".to_string());
        }

        // 4. WHOIS Domain Age
        if let Some(w) = whois {
            if let Some(age) = w.age_days {
                if age < 30 {
                    score += 25;
                    indicators.push("Newly Registered Infrastructure (<30 days old)".to_string());
                } else if age < 90 {
                    score += 10;
                    indicators.push("Recent Domain Registration History (<90 days old)".to_string());
                }
            }
        }

        // 5. HTTP Brand Fingerprinting
        if let Some(h) = http {
            if h.similarity_score > 0.85 {
                score += 25;
                indicators.push(format!("High Brand Page Similarity Index ({:.1}%)", h.similarity_score * 100.0));
            }

            // Advanced Phishing Engine
            if h.brand_title_match {
                score += 10;
                indicators.push("Lookalike Domain Contains Brand Name in Page Title".to_string());
            }

            if h.has_login_form {
                score += 15;
                indicators.push("Credential Harvesting Form Signatures Detected (High-Confidence Phishing)".to_string());
            }

            if h.has_favicon {
                indicators.push("Custom Favicon Shortcut Detected".to_string());
            }
        }

        // 6. TLS / SSL Inspection
        if let Some(t) = tls {
            if t.san_mismatch {
                score += 10;
                indicators.push("TLS Subject Alternative Name Mismatch Encountered".to_string());
            }
        }

        // Calculate final classification
        let total = (score.min(100)) as u8;
        let label = match total {
            80..=100 => "Critical".to_string(),
            50..=79  => "High".to_string(),
            20..=49  => "Medium".to_string(),
            _        => "Low".to_string(),
        };

        ScoreCard { total, label, indicators }
    }
}
