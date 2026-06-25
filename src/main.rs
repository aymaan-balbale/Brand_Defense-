// src/main.rs
// BrandGuard — DRPS/EASM Typosquatting & Lookalike Domain Detector
// © 2024 Griffin / FolSec — MIT License

mod modules;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use modules::{
    report,
    risk::{RiskEngine, ScanResult},
    typo::TypoGenerator,
};
use std::{path::PathBuf, sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};

// ─── CLI Definition ──────────────────────────────────────────────────────────

/// BrandGuard — Typosquatting & Lookalike Domain Intelligence Scanner
#[derive(Parser, Debug)]
#[command(
    name    = "brandguard",
    version = env!("CARGO_PKG_VERSION"),
    about   = "DRPS/EASM module: generates typo-variants of a brand domain and \
               analyses their active threat infrastructure.",
    long_about = None,
)]
struct Cli {
    /// Target brand domain  (e.g. brandefense.io)
    #[arg(short = 'd', long)]
    domain: String,

    /// Maximum concurrent network workers
    #[arg(short = 'c', long, default_value_t = 64)]
    concurrency: usize,

    /// HTTP timeout per request (seconds)
    #[arg(short = 't', long, default_value_t = 8)]
    timeout: u64,

    /// Output HTML report path
    #[arg(short = 'o', long, default_value = "brandguard_report.html")]
    output: PathBuf,

    /// Only report variants with risk score ≥ this threshold (0–100)
    #[arg(long, default_value_t = 20)]
    min_score: u8,

    /// Fetch target homepage and enable similarity fingerprinting
    #[arg(long, default_value_t = true)]
    fingerprint: bool,

    /// Verbose logging (set RUST_LOG=debug for full traces)
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Optional Proxy URL for HTTP requests (e.g. http://127.0.0.1:8080)
    #[arg(short = 'p', long)]
    proxy: Option<String>,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise structured logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .compact()
        .init();

    let start = Instant::now();

    info!(target = %cli.domain, "BrandGuard scan started");

    // ── 1. Typo generation ──────────────────────────────────────────────────
    let generator = TypoGenerator::new(&cli.domain);
    let variants  = generator.generate_all();
    info!("Generated {} typo-variants", variants.len());

    // ── 2. Optionally fetch baseline homepage for fingerprinting ────────────
    let baseline_html: Option<String> = if cli.fingerprint {
        fetch_baseline(&cli.domain, cli.timeout, cli.proxy.as_deref()).await
    } else {
        None
    };

    // ── 3. Concurrent infrastructure analysis ───────────────────────────────
    let semaphore  = Arc::new(Semaphore::new(cli.concurrency));
    let risk_engine = Arc::new(RiskEngine::new());
    let http_client = Arc::new(
        modules::net::build_http_client(cli.timeout, cli.proxy.as_deref())
            .context("Failed to build HTTP client")?,
    );
    let baseline   = Arc::new(baseline_html);

    let pb = ProgressBar::new(variants.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            " {spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏  "),
    );

    let mut tasks = Vec::with_capacity(variants.len());
    let brand_domain = Arc::new(cli.domain.clone());

    for variant in variants {
        let sem        = Arc::clone(&semaphore);
        let engine     = Arc::clone(&risk_engine);
        let client     = Arc::clone(&http_client);
        let baseline_c = Arc::clone(&baseline);
        let pb_c       = pb.clone();
        let timeout    = cli.timeout;
        let brand_c    = Arc::clone(&brand_domain);

        // Simple concurrency throttle: thread sleep delay inside the asynchronous network worker loop
        // This guarantees outbound requests are spread out cleanly and avoids remote rate-limiting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            pb_c.set_message(format!("{}", variant.fqdn));
            let result = analyse_variant(variant, &client, &engine, &baseline_c, timeout, &brand_c).await;
            pb_c.inc(1);
            result
        }));
    }

    let raw: Vec<ScanResult> = futures::future::join_all(tasks)
        .await
        .into_iter()
        .filter_map(|r| r.ok().flatten())    // drop join errors and None
        .filter(|r| r.risk_score >= cli.min_score)
        .collect();

    pb.finish_with_message("Scan complete");

    let elapsed = start.elapsed();
    info!(
        results    = raw.len(),
        elapsed_s  = elapsed.as_secs_f32(),
        "Infrastructure analysis finished"
    );

    // ── 4. Sort by descending risk score ────────────────────────────────────
    let mut results = raw;
    results.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    // ── 5. Render HTML report ───────────────────────────────────────────────
    report::render(&cli.domain, &results, &cli.output, elapsed)
        .context("Report rendering failed")?;

    println!(
        "\n✅  Report saved → {}  ({} flagged variants, {:.1?})\n",
        cli.output.display(),
        results.len(),
        elapsed
    );

    Ok(())
}

// ─── Per-variant analysis orchestration ──────────────────────────────────────

async fn analyse_variant(
    variant: modules::typo::DomainVariant,
    client:  &reqwest::Client,
    engine:  &RiskEngine,
    baseline: &Option<String>,
    timeout: u64,
    brand_domain: &str,
) -> Option<ScanResult> {
    let fqdn = variant.fqdn.clone();

    // DNS
    let dns = modules::dns::resolve(&fqdn, client).await;

    // Only proceed with deeper checks if the domain resolves
    let mx = if dns.resolves {
        modules::dns::check_mx(&fqdn).await
    } else {
        false
    };

    // TLS / SSL
    let tls = if dns.resolves {
        modules::tls::inspect(&fqdn, timeout).await.ok()
    } else {
        None
    };

    // WHOIS
    let whois = modules::whois::query(&fqdn).await.ok();

    // HTTP fingerprint
    let http = if dns.resolves {
        modules::http::fetch_and_fingerprint(&fqdn, client, baseline, timeout, brand_domain).await.ok()
    } else {
        None
    };

    // Risk scoring
    let score_card = engine.score(&dns, mx, &tls, &whois, &http);

    if score_card.total == 0 && !dns.resolves {
        // Skip completely dead, zero-risk variants to keep output clean
        return None;
    }

    Some(ScanResult {
        variant,
        dns,
        mx_active: mx,
        tls,
        whois,
        http,
        risk_score:  score_card.total,
        risk_label:  score_card.label,
        indicators:  score_card.indicators,
        scanned_at:  chrono::Utc::now(),
    })
}

// ─── Fetch baseline homepage ──────────────────────────────────────────────────

async fn fetch_baseline(domain: &str, timeout: u64, proxy: Option<&str>) -> Option<String> {
    let url = format!("https://{}", domain);
    let client = modules::net::build_http_client(timeout, proxy).ok()?;
    match client.get(&url).send().await {
        Ok(resp) => resp.text().await.ok(),
        Err(e) => {
            warn!("Could not fetch baseline for {}: {}", domain, e);
            None
        }
    }
}