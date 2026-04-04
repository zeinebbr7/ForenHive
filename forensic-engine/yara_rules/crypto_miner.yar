rule CryptoMiner_XMRig {
    meta:
        description = "XMRig Monero cryptominer"
        author      = "ForenHive"
        severity    = "medium"

    strings:
        $s1  = "xmrig" ascii nocase
        $s2  = "XMRig" ascii
        $s3  = "monero" ascii nocase
        $s4  = "stratum+tcp://" ascii
        $s5  = "stratum+ssl://" ascii
        $s6  = "pool.supportxmr.com" ascii
        $s7  = "xmr.pool.minergate.com" ascii
        $s8  = "donate.xmrig.com" ascii
        $s9  = "cryptonight" ascii nocase
        $s10 = "randomx" ascii nocase
        $s11 = "\"coin\": \"xmr\"" ascii nocase
        $s12 = "\"algo\": \"rx/0\"" ascii nocase

        // Monero wallet address pattern (XMR addresses start with 4)
        $wallet = /4[0-9A-Za-z]{94}/

    condition:
        2 of ($s*)
        or $wallet
        or (
            $s4 and $s9
        )
}

rule CryptoMiner_Generic {
    meta:
        description = "Generic cryptominer indicators"
        author      = "ForenHive"
        severity    = "medium"

    strings:
        $p1 = "stratum+tcp://" ascii
        $p2 = "stratum+ssl://" ascii
        $p3 = "--donate-level" ascii
        $p4 = "--cpu-priority" ascii
        $p5 = "--threads" ascii
        $p6 = "mining pool" ascii nocase
        $p7 = "hashrate" ascii nocase

    condition:
        3 of them
}
