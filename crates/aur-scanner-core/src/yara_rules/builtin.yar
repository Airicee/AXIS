// yipyip built-in YARA-X rules (compiled into the binary via include_str!).
//
// Every rule MUST carry `severity` meta (critical|high|medium|low|info).
// Optional meta: `description`, `recommendation`, `cwe`.
// Community/extra rules do NOT go here: drop *.yar files into rules.d
// (see docs/yara-rules.md).
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
