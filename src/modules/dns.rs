// src/modules/dns.rs
// Asynchronous DNS resolution + MX record detection.
// MX presence is a high-confidence phishing infrastructure indicator.

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::debug;
use crate::modules::net;

// ─── Shared resolver (initialised once per process) ──────────────────────────
static RESOLVER: OnceCell<TokioAsyncResolver> = OnceCell::const_new();

async fn get_resolver() -> &'static TokioAsyncResolver {
    RESOLVER
        .get_or_init(|| async {
            let mut opts = ResolverOpts::default();
            opts.timeout  = Duration::from_secs(4);
            opts.attempts = 2;
            opts.cache_size = 4096;

            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
        })
        .await
}

// ─── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    /// Did the domain resolve to at least one A/AAAA record?
    pub resolves:   bool,
    /// All IP addresses discovered
    pub ips:        Vec<IpAddr>,
    /// Country-code lookup is intentionally deferred to an external GeoIP step;
    /// here we record the raw IPs for the intelligence engine to enrich.
    pub asn_hint:   Option<String>,   // populated by hosting detection (net.rs)
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Resolve A and AAAA records for a fully-qualified domain name.
pub async fn resolve(fqdn: &str) -> DnsInfo {
    let resolver = get_resolver().await;
    let mut ips: Vec<IpAddr> = Vec::new();

    // A records
    if let Ok(response) = resolver.lookup_ip(fqdn).await {
        for ip in response.iter() {
            ips.push(ip);
        }
    }

    debug!(fqdn = %fqdn, resolves = !ips.is_empty(), ips = ?ips, "DNS lookup");

    let mut asn_hint = None;
    if let Some(first_ip) = ips.first() {
        if let Ok(client) = net::build_http_client(5) {
            asn_hint = net::lookup_asn(first_ip, &client).await;
        }
    }

    DnsInfo {
        resolves:  !ips.is_empty(),
        ips,
        asn_hint,
    }
}

/// Check for MX records — presence indicates active mail infrastructure,
/// which is a primary vector for brand phishing.
pub async fn check_mx(fqdn: &str) -> bool {
    let resolver = get_resolver().await;
    match resolver.mx_lookup(fqdn).await {
        Ok(records) => {
            let has_mx = records.iter().next().is_some();
            debug!(fqdn = %fqdn, has_mx = has_mx, "MX lookup");
            has_mx
        }
        Err(_) => false,
    }
}