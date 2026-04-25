rule WannaCry_Ransomware {
    meta:
        description = "WannaCry / WannaCrypt ransomware"
        author      = "ForenHive"
        severity    = "critical"
        reference   = "CVE-2017-0144 (EternalBlue)"

    strings:
        $s1  = "WannaCryptor" ascii wide
        $s2  = "WannaCry" ascii wide
        $s3  = "WNCRY" ascii
        $s4  = "@WanaDecryptor@" ascii wide
        $s5  = "wannacry" ascii nocase
        $s6  = "tasksche.exe" ascii wide
        $s7  = "mssecsvc.exe" ascii wide
        $s8  = "Please Read Me!.txt" ascii wide
        $s9  = "!Please Read Me!.txt" ascii wide
        $s10 = ".wncry" ascii wide
        $s11 = "icacls . /grant Everyone:F /T /C /Q" ascii wide
        $ransom_note = "Ooops, your files have been encrypted!" ascii wide

        // EternalBlue/DoublePulsar shellcode marker
        $smb1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                  73 61 6d 62 61 00 }

    condition:
        (
            any of ($s*)
            or $ransom_note
        )
        or $smb1
}
