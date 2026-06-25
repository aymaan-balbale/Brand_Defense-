use crate::modules::risk::ScanResult;
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;
use tera::{Context as TeraContext, Tera};

pub fn render(domain: &str, results: &[ScanResult], output: &Path, elapsed: Duration) -> Result<()> {
    let mut tera = Tera::default();
    
    // An enterprise-grade template mimicking a sleek dark mode dashboard
    let template = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>BrandGuard Report - {{ domain }}</title>
        <style>
            :root {
                --bg: #0f172a;
                --surface: #1e293b;
                --text: #f8fafc;
                --text-muted: #94a3b8;
                --primary: #3b82f6;
                --danger: #ef4444;
                --warning: #f59e0b;
                --success: #10b981;
                --border: #334155;
            }
            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background-color: var(--bg);
                color: var(--text);
                margin: 0;
                padding: 2rem;
            }
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid var(--border);
                padding-bottom: 1.5rem;
                margin-bottom: 2rem;
            }
            .header-left h1 {
                margin: 0;
                font-size: 1.5rem;
                font-weight: 600;
                color: var(--text);
            }
            .header-left span {
                color: var(--primary);
            }
            .header-right {
                color: var(--text-muted);
                font-size: 0.875rem;
            }
            .summary-cards {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }
            .card {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 0.5rem;
                padding: 1.5rem;
            }
            .card h3 {
                margin: 0 0 0.5rem 0;
                color: var(--text-muted);
                font-size: 0.875rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            .card .value {
                font-size: 2rem;
                font-weight: 700;
                margin: 0;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background: var(--surface);
                border-radius: 0.5rem;
                overflow: hidden;
                border: 1px solid var(--border);
            }
            th, td {
                padding: 1rem;
                text-align: left;
                border-bottom: 1px solid var(--border);
            }
            th {
                background: #1e293b;
                color: var(--text-muted);
                font-size: 0.875rem;
                font-weight: 600;
                text-transform: uppercase;
            }
            .risk-high { color: var(--danger); font-weight: bold; }
            .risk-medium { color: var(--warning); font-weight: bold; }
            .risk-low { color: var(--success); font-weight: bold; }
            
            .badge {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                font-weight: 600;
                background: rgba(59, 130, 246, 0.1);
                color: var(--primary);
                margin-right: 0.25rem;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="header-left">
                <h1>BrandGuard <span>DRPS/EASM</span></h1>
                <p>Typosquatting Intelligence Report for <strong>{{ domain }}</strong></p>
            </div>
            <div class="header-right">
                <p>Generated: {{ timestamp }}</p>
                <p>Scan Duration: {{ elapsed_secs }}s</p>
            </div>
        </div>

        <div class="summary-cards">
            <div class="card">
                <h3>Total Flagged Variants</h3>
                <p class="value">{{ results | length }}</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Variant</th>
                    <th>Kind</th>
                    <th>Risk Score</th>
                    <th>Risk Label</th>
                    <th>DNS Resolves</th>
                    <th>MX Active</th>
                    <th>Indicators</th>
                </tr>
            </thead>
            <tbody>
                {% for r in results %}
                <tr>
                    <td><strong>{{ r.variant.fqdn }}</strong></td>
                    <td><span class="badge">{{ r.variant.kind }}</span></td>
                    <td>{{ r.risk_score }}</td>
                    <td class="
                        {% if r.risk_label == 'High' %}risk-high
                        {% elif r.risk_label == 'Medium' %}risk-medium
                        {% else %}risk-low{% endif %}
                    ">{{ r.risk_label }}</td>
                    <td>{{ r.dns.resolves }}</td>
                    <td>{{ r.mx_active }}</td>
                    <td>
                        {% for i in r.indicators %}
                            <span class="badge">{{ i }}</span>
                        {% endfor %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </body>
    </html>
    "#;
    
    tera.add_raw_template("report", template).context("Failed to parse report template")?;
    
    let mut context = TeraContext::new();
    context.insert("domain", domain);
    context.insert("results", results);
    context.insert("elapsed_secs", &elapsed.as_secs_f32());
    context.insert("timestamp", &chrono::Utc::now().to_rfc3339());
    
    let html = tera.render("report", &context).context("Failed to render HTML")?;
    
    std::fs::write(output, html).context("Failed to write report to file")?;
    
    Ok(())
}
