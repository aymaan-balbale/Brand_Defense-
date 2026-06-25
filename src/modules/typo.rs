// src/modules/typo.rs
// Typo Generation Engine — dnstwist-style permutation logic
// Produces: transpositions, omissions, insertions, substitutions,
//           homoglyphs, bit-squatting, TLD swaps, subdomain prefixes,
//           hyphen insertions, double-character repeats.

use serde::{Deserialize, Serialize};

// ─── Homoglyph map (Latin → visually confusable Unicode / ASCII) ─────────────
// Covers the most-abused confusables used in phishing campaigns.
static HOMOGLYPHS: &[(&str, &[&str])] = &[
    ("a", &["à", "á", "â", "ä", "å", "ą", "ā", "ɑ", "а"]),   // Cyrillic а
    ("b", &["ḃ", "ƀ", "ɓ"]),
    ("c", &["ć", "č", "ç", "ĉ", "ċ"]),
    ("d", &["ď", "đ", "ḋ"]),
    ("e", &["è", "é", "ê", "ë", "ę", "ē", "е"]),               // Cyrillic е
    ("f", &["ƒ"]),
    ("g", &["ĝ", "ğ", "ġ", "ģ"]),
    ("h", &["ĥ", "ħ"]),
    ("i", &["ì", "í", "î", "ï", "į", "ī", "ı", "і"]),         // Cyrillic і
    ("j", &["ĵ"]),
    ("k", &["ķ", "ĸ"]),
    ("l", &["ĺ", "ļ", "ľ", "ł", "ḷ", "1"]),
    ("m", &["rn", "ṁ"]),
    ("n", &["ñ", "ń", "ņ", "ň"]),
    ("o", &["ò", "ó", "ô", "õ", "ö", "ø", "ō", "о", "0"]),   // Cyrillic о
    ("p", &["ƥ", "ṗ"]),
    ("r", &["ŕ", "ŗ", "ř"]),
    ("s", &["ś", "ŝ", "ş", "š", "ṡ", "$"]),
    ("t", &["ť", "ţ", "ṫ"]),
    ("u", &["ù", "ú", "û", "ü", "ů", "ū", "υ"]),
    ("v", &["ṿ", "ʋ"]),
    ("w", &["ŵ", "ẇ", "vv"]),
    ("x", &["ẋ"]),
    ("y", &["ý", "ÿ", "ŷ"]),
    ("z", &["ź", "ż", "ž"]),
    // Digit look-alikes
    ("0", &["o", "О"]),
    ("1", &["l", "I", "i"]),
];

// ─── Common TLD list for swap permutations ───────────────────────────────────
static TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "info", "biz", "app", "dev", "ai",
    "cloud", "security", "tech", "online", "site", "web", "live", "store",
    "shop", "co.uk", "com.br", "de", "fr", "ru", "cn", "in",
];

// ─── Common subdomain prefix variants (brand impersonation patterns) ──────────
static SUBDOMAIN_PREFIXES: &[&str] = &[
    "secure", "login", "auth", "account", "support", "help",
    "portal", "my", "web", "mail", "api", "app", "admin",
    "signin", "verify", "confirm", "update", "service",
];

// ─── Keyboard adjacency for substitution (QWERTY) ────────────────────────────
static KEYBOARD_ADJACENT: &[(&str, &[&str])] = &[
    ("a", &["q", "w", "s", "z"]),
    ("b", &["v", "g", "h", "n"]),
    ("c", &["x", "d", "f", "v"]),
    ("d", &["s", "e", "f", "r", "c", "x"]),
    ("e", &["w", "r", "s", "d"]),
    ("f", &["d", "r", "g", "t", "v", "c"]),
    ("g", &["f", "t", "h", "y", "v", "b"]),
    ("h", &["g", "y", "j", "u", "b", "n"]),
    ("i", &["u", "o", "j", "k"]),
    ("j", &["h", "u", "k", "i", "n", "m"]),
    ("k", &["j", "i", "l", "o", "m"]),
    ("l", &["k", "o", "p"]),
    ("m", &["n", "j", "k"]),
    ("n", &["b", "h", "j", "m"]),
    ("o", &["i", "p", "k", "l"]),
    ("p", &["o", "l"]),
    ("q", &["w", "a"]),
    ("r", &["e", "t", "d", "f"]),
    ("s", &["a", "w", "d", "x", "z"]),
    ("t", &["r", "y", "f", "g"]),
    ("u", &["y", "i", "h", "j"]),
    ("v", &["c", "f", "g", "b"]),
    ("w", &["q", "e", "a", "s"]),
    ("x", &["z", "s", "d", "c"]),
    ("y", &["t", "u", "g", "h"]),
    ("z", &["a", "s", "x"]),
];

// ─── Types ────────────────────────────────────────────────────────────────────

/// Category tag for each generated variant — useful for intelligence triage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VariantKind {
    Transposition,
    Omission,
    Insertion,
    Substitution,
    Homoglyph,
    BitSquat,
    TldSwap,
    SubdomainPrefix,
    HyphenInsertion,
    DoubleChar,
    KeyboardAdjacent,
    AddedDash,
    AddedDot,
}

impl std::fmt::Display for VariantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Transposition     => "Transposition",
            Self::Omission          => "Omission",
            Self::Insertion         => "Insertion",
            Self::Substitution      => "Substitution",
            Self::Homoglyph         => "Homoglyph / Punycode",
            Self::BitSquat          => "Bit-squat",
            Self::TldSwap           => "TLD Swap",
            Self::SubdomainPrefix   => "Subdomain Prefix",
            Self::HyphenInsertion   => "Hyphen Insertion",
            Self::DoubleChar        => "Double Character",
            Self::KeyboardAdjacent  => "Keyboard Adjacent",
            Self::AddedDash         => "Added Dash",
            Self::AddedDot          => "Added Dot",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVariant {
    /// Fully-qualified domain name
    pub fqdn:      String,
    /// Original label (without TLD)
    pub name:      String,
    /// TLD of this variant
    pub tld:       String,
    /// Classification tag
    pub kind:      VariantKind,
    /// Description of how variant was produced (for report forensics)
    pub technique: String,
}

// ─── Generator ───────────────────────────────────────────────────────────────

pub struct TypoGenerator {
    name:   String,
    tld:    String,
}

impl TypoGenerator {
    /// `domain` — e.g. "brandefense.io"
    pub fn new(domain: &str) -> Self {
        let (name, tld) = split_domain(domain);
        Self { name, tld }
    }

    /// Generate all variant categories; deduplicate by FQDN.
    pub fn generate_all(&self) -> Vec<DomainVariant> {
        let mut results: Vec<DomainVariant> = Vec::new();

        results.extend(self.transpositions());
        results.extend(self.omissions());
        results.extend(self.insertions());
        results.extend(self.substitutions());
        results.extend(self.homoglyphs());
        results.extend(self.bit_squats());
        results.extend(self.tld_swaps());
        results.extend(self.subdomain_prefixes());
        results.extend(self.hyphen_insertions());
        results.extend(self.double_chars());
        results.extend(self.keyboard_adjacent());

        // Deduplicate by FQDN, preserving first occurrence
        let mut seen = std::collections::HashSet::new();
        results.retain(|v| seen.insert(v.fqdn.clone()));

        // Filter: never return the legitimate domain itself
        let legit = format!("{}.{}", self.name, self.tld);
        results.retain(|v| v.fqdn != legit);

        results
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make(&self, name: &str, tld: &str, kind: VariantKind, technique: &str) -> DomainVariant {
        DomainVariant {
            fqdn:      format!("{}.{}", name, tld),
            name:      name.to_string(),
            tld:       tld.to_string(),
            kind,
            technique: technique.to_string(),
        }
    }

    fn make_sub(&self, prefix: &str, tld: &str, technique: &str) -> DomainVariant {
        let fqdn = format!("{}.{}.{}", prefix, self.name, tld);
        DomainVariant {
            fqdn:      fqdn.clone(),
            name:      format!("{}.{}", prefix, self.name),
            tld:       tld.to_string(),
            kind:      VariantKind::SubdomainPrefix,
            technique: technique.to_string(),
        }
    }

    // ── Permutation methods ───────────────────────────────────────────────────

    /// Swap adjacent character pairs: "brand" → "rbnd", "barnd", …
    fn transpositions(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 0..chars.len().saturating_sub(1) {
            let mut c = chars.clone();
            c.swap(i, i + 1);
            let name: String = c.into_iter().collect();
            out.push(self.make(
                &name, &self.tld,
                VariantKind::Transposition,
                &format!("swap positions {} and {}", i, i + 1),
            ));
        }
        out
    }

    /// Delete each character: "brand" → "rand", "band", "brd", …
    fn omissions(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 0..chars.len() {
            let name: String = chars.iter().enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, c)| *c)
                .collect();
            if name.len() < 2 { continue; }
            out.push(self.make(
                &name, &self.tld,
                VariantKind::Omission,
                &format!("omit char '{}' at position {}", chars[i], i),
            ));
        }
        out
    }

    /// Insert each lowercase letter at every position.
    fn insertions(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 0..=chars.len() {
            for ins in 'a'..='z' {
                let mut c = chars.clone();
                c.insert(i, ins);
                let name: String = c.into_iter().collect();
                out.push(self.make(
                    &name, &self.tld,
                    VariantKind::Insertion,
                    &format!("insert '{}' at position {}", ins, i),
                ));
            }
        }
        out
    }

    /// Replace each character with every other lowercase letter.
    fn substitutions(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 0..chars.len() {
            for sub in 'a'..='z' {
                if sub == chars[i] { continue; }
                let mut c = chars.clone();
                c[i] = sub;
                let name: String = c.into_iter().collect();
                out.push(self.make(
                    &name, &self.tld,
                    VariantKind::Substitution,
                    &format!("substitute '{}' → '{}' at position {}", chars[i], sub, i),
                ));
            }
        }
        out
    }

    /// Replace characters with their visual homoglyphs.
    /// Output uses ACE/Punycode-compatible ASCII when the homoglyph is ASCII;
    /// otherwise the Unicode label is recorded (browsers encode it).
    fn homoglyphs(&self) -> Vec<DomainVariant> {
        let name_lower = self.name.to_lowercase();
        let mut out    = Vec::new();

        for (original, replacements) in HOMOGLYPHS {
            if !name_lower.contains(original) { continue; }
            for replacement in *replacements {
                let new_name = name_lower.replacen(original, replacement, 1);
                if new_name == name_lower { continue; }
                out.push(self.make(
                    &new_name, &self.tld,
                    VariantKind::Homoglyph,
                    &format!("'{}' → '{}' (visual confusable)", original, replacement),
                ));
            }
        }
        out
    }

    /// Bit-squat: flip one bit in each ASCII character (classic CDN cache-poisoning vector).
    fn bit_squats(&self) -> Vec<DomainVariant> {
        let bytes = self.name.as_bytes();
        let mut out = Vec::new();
        for i in 0..bytes.len() {
            for bit in 0u8..8 {
                let flipped = bytes[i] ^ (1 << bit);
                if flipped == bytes[i] || flipped < b'a' || flipped > b'z' {
                    continue;
                }
                let mut b = bytes.to_vec();
                b[i] = flipped;
                if let Ok(name) = String::from_utf8(b) {
                    out.push(self.make(
                        &name, &self.tld,
                        VariantKind::BitSquat,
                        &format!("bit {} flipped in byte {} ('{}')", bit, i, bytes[i] as char),
                    ));
                }
            }
        }
        out
    }

    /// Swap TLD to every common alternative.
    fn tld_swaps(&self) -> Vec<DomainVariant> {
        TLDS.iter()
            .filter(|&&t| t != self.tld)
            .map(|&t| self.make(
                &self.name, t,
                VariantKind::TldSwap,
                &format!(".{} → .{}", self.tld, t),
            ))
            .collect()
    }

    /// Prepend common phishing subdomain prefixes.
    fn subdomain_prefixes(&self) -> Vec<DomainVariant> {
        let mut out = Vec::new();
        for &prefix in SUBDOMAIN_PREFIXES {
            // e.g. secure.brandefense.com
            out.push(self.make_sub(prefix, &self.tld, &format!("prefix '{}'", prefix)));
            // Also try with the original TLD and with .com
            if self.tld != "com" {
                out.push(self.make_sub(prefix, "com", &format!("prefix '{}' + .com TLD", prefix)));
            }
        }
        out
    }

    /// Insert hyphens between each pair of adjacent characters.
    fn hyphen_insertions(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 1..chars.len() {
            let name: String = format!(
                "{}-{}",
                &self.name[..i],
                &self.name[i..]
            );
            out.push(self.make(
                &name, &self.tld,
                VariantKind::HyphenInsertion,
                &format!("hyphen after position {}", i),
            ));
        }
        out
    }

    /// Repeat each character: "brand" → "bbrand", "braand", …
    fn double_chars(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 0..chars.len() {
            let name: String = format!(
                "{}{}{}",
                &self.name[..i],
                chars[i],
                &self.name[i..]
            );
            out.push(self.make(
                &name, &self.tld,
                VariantKind::DoubleChar,
                &format!("double char '{}' at position {}", chars[i], i),
            ));
        }
        out
    }

    /// Replace each character with QWERTY-adjacent keys.
    fn keyboard_adjacent(&self) -> Vec<DomainVariant> {
        let chars: Vec<char> = self.name.chars().collect();
        let mut out = Vec::new();
        for i in 0..chars.len() {
            let key = chars[i].to_string();
            let key_str = key.as_str();
            if let Some((_, neighbors)) = KEYBOARD_ADJACENT.iter().find(|(k, _)| *k == key_str) {
                for &neighbor in *neighbors {
                    let mut c = chars.clone();
                    // neighbor might be multi-char (e.g. the original is single), skip
                    let mut nchars = neighbor.chars();
                    if let Some(nc) = nchars.next() {
                        if nchars.next().is_some() { continue; } // skip multi-char
                        c[i] = nc;
                        let name: String = c.iter().collect();
                        out.push(self.make(
                            &name, &self.tld,
                            VariantKind::KeyboardAdjacent,
                            &format!("key '{}' → adjacent '{}' at position {}", chars[i], neighbor, i),
                        ));
                    }
                }
            }
        }
        out
    }
}

// ─── Utilities ───────────────────────────────────────────────────────────────

/// Split "brand.io" → ("brand", "io")
/// Handles multi-part TLDs like "co.uk" naively (takes last two labels).
fn split_domain(domain: &str) -> (String, String) {
    let parts: Vec<&str> = domain.splitn(2, '.').collect();
    if parts.len() == 2 {
        (parts[0].to_lowercase(), parts[1].to_lowercase())
    } else {
        (domain.to_lowercase(), "com".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_produces_variants() {
        let g = TypoGenerator::new("google.com");
        let vs = g.generate_all();
        assert!(!vs.is_empty(), "should produce variants");
        // Legitimate domain must not appear
        assert!(!vs.iter().any(|v| v.fqdn == "google.com"));
    }

    #[test]
    fn no_duplicate_fqdns() {
        let g  = TypoGenerator::new("example.com");
        let vs = g.generate_all();
        let mut seen = std::collections::HashSet::new();
        for v in &vs {
            assert!(seen.insert(v.fqdn.clone()), "duplicate: {}", v.fqdn);
        }
    }
}