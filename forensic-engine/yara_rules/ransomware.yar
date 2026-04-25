rule LockBit_Ransomware {
    meta:
        description = "LockBit 2.0/3.0 ransomware"
        severity = "critical"
    strings:
        $s1 = "LockBit" ascii nocase
        $s2 = ".lockbit" ascii nocase
        $s3 = "lockbit3" ascii nocase
        $mutex = "Global\\{F18E8A5C" ascii
    condition:
        2 of them
}
rule BlackCat_ALPHV {
    meta:
        description = "BlackCat/ALPHV ransomware"
        severity = "critical"
    strings:
        $s1 = "ALPHV" ascii
        $s2 = ".alphv" ascii nocase
        $s3 = "blackcat" ascii nocase
    condition:
        2 of them
}
rule Clop_Ransomware {
    meta:
        description = "Clop ransomware"
        severity = "critical"
    strings:
        $s1 = ".clop" ascii nocase
        $s2 = "ClopReadMe" ascii
        $s3 = "CLOP^_" ascii
    condition:
        2 of them
}
