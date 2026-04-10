rule AsyncRAT {
    meta:
        description = "AsyncRAT remote access trojan"
        severity = "high"
    strings:
        $s1 = "AsyncRAT" ascii
        $s2 = "Pastebin" ascii
        $s3 = "Install_" ascii
        $pdb = "AsyncClient.pdb" ascii
    condition:
        2 of them
}
rule QuasarRAT {
    meta:
        description = "Quasar RAT"
        severity = "high"
    strings:
        $s1 = "QuasarRAT" ascii
        $s2 = "Client.exe" ascii
        $pdb = "Quasar.Client.pdb" ascii
    condition:
        2 of them
}
