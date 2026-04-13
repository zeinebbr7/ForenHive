rule Linux_Backdoor_Generic {
    meta:
        description = "Generic Linux backdoor indicators"
        severity = "high"
    strings:
        $s1 = "/bin/sh" ascii
        $s2 = "socket" ascii
        $s3 = "connect" ascii
        $s4 = "execve" ascii
        $b64 = "base64" ascii nocase
    condition:
        4 of them
}
rule Diamorphine_Rootkit {
    meta:
        description = "Diamorphine Linux rootkit"
        severity = "critical"
    strings:
        $s1 = "diamorphine" ascii nocase
        $s2 = "hide_module" ascii
        $s3 = "is_invisible" ascii
    condition:
        2 of them
}
