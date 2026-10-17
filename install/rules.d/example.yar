// Example community YARA-X rule for yipyip.
//
// Drop *.yar / *.yara files like this into any of:
//   /usr/share/aur-scanner/rules.d/      (distro/package-shipped)
//   /etc/aur-scanner/rules.d/            (system administrator)
//   ~/.config/aur-scanner/rules.d/       (per user; not read when running as root)
// or into the directory set as `rules_path` in config.toml.
//
// Contract (a file that breaks it is skipped with a warning on stderr):
//   * it must compile with YARA-X on its own;
//   * EVERY rule needs  meta: severity = "critical|high|medium|low|info";
//   * rule identifiers must be unique across the built-in rules and every other
//     rules.d file (first definition wins; a rule can add a detection, never
//     replace or lower an existing one). Use your own prefix, e.g. ACME_...;
//   * optional meta: description, recommendation, cwe (e.g. "CWE-78");
//   * the file must be a regular file (symlinks are ignored) and <= 256 KiB.
//
// Rules run against the PKGBUILD text AFTER the script normalizer has appended
// decoded base64 payloads and flattened `bash < <(curl ...)` into a pipe.

rule EXAMPLE_YARA_Mentions_Example_Dot_Com {
    meta:
        severity = "info"
        description = "Demonstration rule. Flags any PKGBUILD that references example.com."
        recommendation = "This is only an example rule; delete or replace it."
    strings:
        $host = "example.com"
    condition:
        $host
}
