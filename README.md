# BrandGuard — DRPS/EASM Intelligence Engine

> **Digital Risk Protection | External Attack Surface Management | Phishing Infrastructure Detection**

A high-performance, fully asynchronous domain threat intelligence engine written in **pure Rust**. BrandGuard proactively generates typosquatting permutations of a target brand, resolves live infrastructure telemetry concurrently across hundreds of variants, and performs deep HTML application-layer analysis to detect active credential harvesting pages — producing a self-contained, analyst-ready HTML dashboard with zero external dependencies.

```
cargo run --release -- --domain brandefense.io --concurrency 32 -o report.html
```

![BrandGuard Dashboard](assets/dashboard_preview.png)

---

## Why BrandGuard

Most typosquatting scanners stop at DNS. BrandGuard doesn't.

The industry shift in phishing is from **network-layer staging** to **application-layer deception** — attackers now spin up lookalike pages in under 10 minutes using CDN-backed infrastructure that passes basic DNS/SSL checks. BrandGuard's v2 heuristic engine detects this by inspecting live HTML for credential harvesting signatures, fuzzy title matching, and favicon reuse — the same signals a Tier-2 analyst would look for manually, automated at machine scale.

---

## Features

### Multi-Vector Permutation Engine
Generates **400+ lookalike domain variants** per target using the full dnstwist mutation heuristic set:

| Technique | Example (`brandefense.io`) |
|---|---|
| Transposition | `barandefense.io` |
| Omission | `brandefens.io` |
| Insertion | `branddefense.io` |
| Substitution | `br4ndefense.io` |
| Homoglyph / Punycode | `brаndefense.io` *(Cyrillic а)* |
| TLD Swap | `brandefense.com`, `.net`, `.app` |
| Subdomain Prefix | `login.brandefense.com` |
| Keyboard Adjacent | `vrandefense.io` |
| Bit-Squat | single-bit ASCII flip variants |
| Double Char / Hyphen | `brannddefense.io`, `brand-efense.io` |

### Massively Concurrent Telemetry Engine
Uses `tokio` + bounded semaphore concurrency to probe hundreds of domains simultaneously:
- **DNS A/AAAA resolution** — confirms live presence
- **MX record detection** — flags domains prepped for email phishing (+20 risk)
- **TLS certificate inspection** — extracts issuer, SAN list, cert age, and detects mismatches
- **WHOIS domain age** — newly registered domains get elevated scoring

### V2 Application-Layer Phishing Heuristics
Shifts analysis past the network layer into live HTML inspection:
- **Credential harvesting detection** — tracks `<input type="password">`, unauthorized `<form>` redirect targets, and auth endpoint paths (`/login`, `/signin`, `/verify`)
- **Fuzzy title & brand matching** — Jaro-Winkler similarity (`strsim`) on `<title>` tags
- **Favicon tracking** — identifies assets linking back to the legitimate brand's CDN

### Risk Scoring Engine

| Indicator | Score Modifier |
|---|---|
| Active DNS resolution | Base trigger |
| Active MX record | +20 |
| Abused ASN (Vultr, DigitalOcean, Hostinger) | +20 |
| Brand name in `<title>` | +10 |
| Credential harvesting input detected | +15 |
| Newly registered domain (< 30 days) | +15 |
| TLS issuer mismatch / self-signed | +10 |
| Favicon points to brand CDN | +10 |

Domains matching multiple signals scale to **100/100 Critical** and surface at the top of the analyst view.

### Self-Contained HTML Dashboard
Single portable `.html` file with:
- Dark-mode SOC-ready UI
- Color-coded severity rows (Critical / High / Medium / Low)
- Expandable forensic detail per variant
- **Export to CSV** and **Copy as JSON** for SIEM/SOAR integration — all vanilla JS, no external dependencies

---

## Tech Stack

| Component | Crate |
|---|---|
| Async runtime | `tokio` (multi-threaded) |
| HTTP client | `reqwest` (connection pooling, rustls) |
| DNS resolver | `hickory-resolver` |
| TLS inspection | `rustls` + `x509-parser` |
| WHOIS | `whois-rust` |
| String similarity | `strsim` (Jaro-Winkler) |
| Report templating | `tera` |
| CLI | `clap` v4 |

---

## Getting Started

**Prerequisites:** Rust stable (`cargo` 1.70+), any OS.

```bash
# Clone
git clone https://github.com/aymaan-balbale/Brand_Defense-.git
cd Brand_Defense-

# Build release binary
cargo build --release
```

### Usage

```
USAGE:
    brandguard --domain <DOMAIN> [OPTIONS]

OPTIONS:
    --domain          Target brand domain to analyze  [e.g. google.com]
    --concurrency     Parallel workers for concurrent probes  [default: 32]
    --timeout         Per-request network timeout in seconds  [default: 5]
    --min-score       Only report variants at or above this risk score  [default: 20]
    --proxy           HTTP/HTTPS proxy URL  [e.g. http://127.0.0.1:8080]
    -o                Output HTML report filename  [default: brandguard_report.html]
    -v                Verbose logging
```

### Examples

```bash
# Standard brand scan
cargo run --release -- --domain brandefense.io -o brandefense_report.html

# High-concurrency enterprise scan with proxy routing
cargo run --release -- --domain google.com --concurrency 64 --proxy http://127.0.0.1:8080 -o google_report.html

# Only surface High/Critical (score ≥ 50)
cargo run --release -- --domain stripe.com --min-score 50 -o stripe_critical.html
```

---

## Architecture

```
src/
├── main.rs              # CLI, tokio runtime, scan orchestration
└── modules/
    ├── typo.rs          # Permutation engine (400+ variants)
    ├── dns.rs           # Async DNS resolution + MX checks
    ├── tls.rs           # TLS/SSL certificate inspection
    ├── whois.rs         # WHOIS domain age + registrar extraction
    ├── http.rs          # HTTP fetch + HTML phishing heuristics
    ├── net.rs           # Shared HTTP client, ASN/hosting detection
    ├── risk.rs          # Weighted risk scoring engine + ScanResult type
    └── report.rs        # Tera-templated self-contained HTML report
```

The pipeline per variant: **Typo generation → DNS → MX → TLS → WHOIS → HTTP fingerprint → Risk score → Report**

All network stages run concurrently under a bounded `tokio::sync::Semaphore` with configurable worker count. A 50ms task-stagger is applied to avoid triggering remote rate limits (e.g. `ip-api.com` ASN lookups).

---

## Intelligence Output Format

Each `ScanResult` is structured for direct ingestion by an enterprise intelligence engine or SIEM:

```json
{
  "fqdn": "brandefanse.io",
  "variant_kind": "Substitution",
  "technique": "substitute 'e' → 'a' at position 10",
  "dns": { "resolves": true, "ips": ["104.21.x.x"] },
  "mx_active": true,
  "tls": { "issuer": "Let's Encrypt", "days_old": 3, "san_mismatch": false },
  "whois": { "registered_days_ago": 7, "registrar": "Namecheap" },
  "http": { "title_similarity": 0.91, "has_password_field": true, "status": 200 },
  "risk_score": 100,
  "risk_label": "Critical",
  "indicators": ["Active MX", "Newly Registered", "Credential Harvesting Input", "Brand Title Match"],
  "scanned_at": "2025-01-15T14:32:00Z"
}
```

---

## Author

**Griffin (Aymaan Balbale)** — Backend Developer & Security Researcher  
[github.com/aymaan-balbale](https://github.com/aymaan-balbale) · [hackerone.com/mikhail22](https://hackerone.com/mikhail22)

---

## License

MIT — see [LICENSE](LICENSE)
