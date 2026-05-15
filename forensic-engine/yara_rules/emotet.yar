rule Emotet_Loader {
    meta:
        description = "Emotet banking trojan / loader"
        author      = "ForenHive"
        severity    = "critical"
        reference   = "TA542"

    strings:
        // Obfuscated PowerShell dropper patterns
        $ps1  = "powershell" ascii wide nocase
        $ps2  = "-EncodedCommand" ascii wide nocase
        $ps3  = "-WindowStyle Hidden" ascii wide nocase
        $ps4  = "IEX(" ascii wide
        $ps5  = "Invoke-Expression" ascii wide nocase

        // Emotet network C2 patterns
        $net1 = "Content-Type: application/x-www-form-urlencoded" ascii
        $net2 = "Cookie:" ascii
        $net3 = "Mozilla/4.0" ascii

        // Known Emotet string artifacts
        $e1   = "emotet" ascii nocase
        $e2   = "heodo" ascii nocase
        $e3   = "geodo" ascii nocase
        $e4   = "feodo" ascii nocase

        // Macro dropper artifacts (VBA)
        $vba1 = "AutoOpen" ascii wide
        $vba2 = "Document_Open" ascii wide
        $vba3 = "Shell(" ascii wide
        $vba4 = "CreateObject" ascii wide

    condition:
        (2 of ($ps*) and 1 of ($net*))
        or any of ($e*)
        or (2 of ($vba*) and 1 of ($ps*))
}
