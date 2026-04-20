rule Mirai_Botnet {
    meta:
        description = "Mirai IoT botnet binary"
        author      = "ForenHive"
        severity    = "critical"
        reference   = "CVE-2016-10401"

    strings:
        $str1  = "busybox" ascii
        $str2  = "MIRAI" ascii
        $str3  = "/bin/busybox" ascii
        $str4  = "selfrep" ascii
        $str5  = "telnet" ascii
        $str6  = "scanner" ascii
        $str7  = "/proc/net/tcp" ascii
        $str8  = "LZRD" ascii
        $str9  = "ECCHI" ascii
        $str10 = "nigger" ascii nocase  // known Mirai taunting string
        $c2_1  = "syn" ascii
        $c2_2  = "ack" ascii
        $c2_3  = "stomp" ascii
        $c2_4  = "greip" ascii
        $c2_5  = "udpplain" ascii

    condition:
        uint32(0) == 0x464c457f  // ELF magic
        and (
            3 of ($str*)
            or 2 of ($c2*)
        )
}
