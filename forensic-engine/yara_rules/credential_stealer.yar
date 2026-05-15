rule Credential_Stealer {
    meta:
        description = "Credential harvesting / password stealing"
        author      = "ForenHive"
        severity    = "high"

    strings:
        // Common credential targets
        $f1  = "/etc/shadow" ascii
        $f2  = "/etc/passwd" ascii
        $f3  = ".ssh/id_rsa" ascii
        $f4  = ".ssh/authorized_keys" ascii
        $f5  = "id_rsa" ascii
        $f6  = "known_hosts" ascii
        $f7  = ".bash_history" ascii
        $f8  = ".aws/credentials" ascii
        $f9  = ".docker/config.json" ascii

        // Browser credential paths
        $b1  = "Login Data" ascii wide
        $b2  = "Cookies" ascii wide
        $b3  = "Web Data" ascii wide
        $b4  = "chrome" ascii nocase
        $b5  = "firefox" ascii nocase

        // Mimikatz / Windows credential dumping
        $m1  = "mimikatz" ascii wide nocase
        $m2  = "sekurlsa" ascii wide nocase
        $m3  = "lsadump" ascii wide nocase
        $m4  = "privilege::debug" ascii wide nocase
        $m5  = "kerberos::list" ascii wide nocase
        $m6  = "NTLM" ascii wide
        $m7  = "SAM" ascii wide

        // Credential exfil patterns
        $e1  = "curl -d" ascii
        $e2  = "wget --post-data" ascii
        $e3  = "base64 -d" ascii

    condition:
        3 of ($f*)
        or (2 of ($b*) and filesize < 10MB)
        or 2 of ($m*)
        or (1 of ($f*) and 1 of ($e*))
}

rule SSH_Brute_Tool {
    meta:
        description = "SSH brute force tool / credential list"
        author      = "ForenHive"
        severity    = "medium"

    strings:
        $t1 = "hydra" ascii nocase
        $t2 = "medusa" ascii nocase
        $t3 = "ncrack" ascii nocase
        $t4 = "patator" ascii nocase
        $c1 = "root:root" ascii
        $c2 = "admin:admin" ascii
        $c3 = "admin:password" ascii
        $c4 = "root:toor" ascii
        $c5 = "root:123456" ascii

    condition:
        any of ($t*)
        or 3 of ($c*)
}
