# YARA-X rules in yipyip

yipyip runs a [YARA-X](https://virustotal.github.io/yara-x/) engine over each
scanned PKGBUILD in addition to the upstream analyzers. The text is first passed
through the script normalizer, which appends decoded `echo "…" | base64 -d`
payloads (marked `# [DECODED_INLINE_PAYLOAD]`) and flattens
`bash < <(curl …)` into `curl … | bash`.

## Where rules come from

| Source | Location |
|---|---|
| Built-in | `crates/aur-scanner-core/src/yara_rules/builtin.yar`, embedded in the binary |
| System / user | `*.yar` / `*.yara` in the same `rules.d` directories as the TOML rules (`/usr/share/aur-scanner/rules.d`, `/etc/aur-scanner/rules.d`, `~/.config/aur-scanner/rules.d`; the per-user one is not read when running as root) |
| Configured | `*.yar` / `*.yara` in the directory set as `rules_path` |

All rules are compiled **once**, when the scanner is created, and the compiled
set is reused for every file and package scanned (`system` audits included).

## Rule file contract

A file that breaks any of these is skipped, with a warning on stderr; other
files and the built-in rules are unaffected.

1. It compiles on its own.
2. Every rule has `meta: severity = "critical" | "high" | "medium" | "low" | "info"`.
   (A rule without a valid severity is rejected rather than defaulting to a low
   one, so it cannot silently hide a match.)
3. Rule identifiers are unique across the built-in rules, the built-in TOML
   rules and codes, and every earlier file. First definition wins, so a
   `rules.d` file can add detections but never replace or lower one.
4. It is a regular file (symlinks are not followed) of at most 256 KiB.

Optional meta: `description`, `recommendation`, `cwe`. Findings report the
origin of the rule (`builtin` or the file path) in `metadata.source`.

See `install/rules.d/example.yar` for a template.
