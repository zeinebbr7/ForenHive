rule Generic_Reverse_Shell {
    meta:
        description = "Generic reverse shell / bind shell patterns"
        author      = "ForenHive"
        severity    = "high"

    strings:
        // Common reverse shell one-liners
        $rs1  = "bash -i >& /dev/tcp/" ascii
        $rs2  = "/dev/tcp/" ascii
        $rs3  = "0>&1" ascii
        $rs4  = "exec 5<>/dev/tcp/" ascii
        $rs5  = "nc -e /bin/sh" ascii
        $rs6  = "nc -e /bin/bash" ascii
        $rs7  = "ncat -e" ascii
        $rs8  = "socat exec:" ascii
        $rs9  = "python -c 'import socket,subprocess" ascii wide
        $rs10 = "python3 -c 'import socket" ascii wide
        $rs11 = "perl -e 'use Socket" ascii wide

        // PHP reverse shells
        $php1 = "<?php system(" ascii
        $php2 = "<?php passthru(" ascii
        $php3 = "<?php shell_exec(" ascii
        $php4 = "<?php exec(" ascii
        $php5 = "fsockopen(" ascii

        // MSF/meterpreter markers
        $msf1 = "meterpreter" ascii nocase
        $msf2 = "metasploit" ascii nocase

    condition:
        any of ($rs*)
        or 2 of ($php*)
        or any of ($msf*)
}

rule Webshell_Generic {
    meta:
        description = "Generic web shell"
        author      = "ForenHive"
        severity    = "high"

    strings:
        $ws1 = "eval(base64_decode(" ascii
        $ws2 = "eval(gzinflate(" ascii
        $ws3 = "eval(str_rot13(" ascii
        $ws4 = "assert($_" ascii
        $ws5 = "passthru($_" ascii
        $ws6 = "system($_" ascii
        $ws7 = "shell_exec($_" ascii
        $ws8 = "preg_replace(\"/.*/e\"" ascii
        $ws9 = "preg_replace('/.*/' , $_" ascii

    condition:
        2 of them
}
