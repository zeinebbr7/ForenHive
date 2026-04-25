/*
 * WannaCry / WannaCrypt detection rule.
 *
 * Defensive YARA signature only — does not contain any executable payload.
 * Covers:
 *   - mutex strings ("WNcry@2ol7", "WannaDecryptor")
 *   - kill-switch domain (Marcus Hutchins's sinkhole pattern)
 *   - MZ / PE section markers (sample is a Windows PE)
 *   - encrypted-file extension (.WNCRY)
 *
 * Reference: CVE-2017-0144 (EternalBlue) / CVE-2017-0145.
 */

rule WannaCry_Ransomware
{
    meta:
        description = "WannaCry / WannaCrypt ransomware family signature"
        author      = "ForenHive"
        severity    = "critical"
        family      = "wannacry"
        reference   = "CVE-2017-0144"
        date        = "2026-04-25"

    strings:
        // ── Mutex strings ────────────────────────────────────────────────
        $mutex1 = "WNcry@2ol7"            ascii wide
        $mutex2 = "MsWinZonesCacheCounterMutexA" ascii wide
        $mutex3 = "Global\\MsWinZonesCacheCounterMutexA" ascii wide

        // ── Tool / decryptor names ───────────────────────────────────────
        $name1 = "WannaDecryptor"         ascii wide nocase
        $name2 = "@WanaDecryptor@.exe"    ascii wide
        $name3 = "WannaCryptor"           ascii wide
        $name4 = "WannaCry"               ascii wide nocase
        $name5 = "tasksche.exe"           ascii wide
        $name6 = "mssecsvc.exe"           ascii wide
        $name7 = "@Please_Read_Me@.txt"   ascii wide

        // ── Kill-switch sinkhole domains ────────────────────────────────
        $ks1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
        $ks2 = "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
        $ks3 = "ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com" ascii wide nocase

        // ── Encrypted file extensions ────────────────────────────────────
        $ext1 = ".WNCRY"                  ascii wide
        $ext2 = ".wncry"                  ascii wide
        $ext3 = ".WNCRYT"                 ascii wide
        $ext4 = ".WCRY"                   ascii wide

        // ── Ransom note fragments ────────────────────────────────────────
        $note1 = "Ooops, your files have been encrypted!" ascii wide
        $note2 = "Send $300 worth of bitcoin"             ascii wide
        $note3 = "Wana Decrypt0r"                          ascii wide

        // ── PE / MZ structural markers ──────────────────────────────────
        $mz   = { 4D 5A }                       // "MZ" — DOS header magic
        $pe   = { 50 45 00 00 }                 // "PE\0\0" — NT header
        // Common WannaCry PE sections
        $sec1 = ".text" ascii
        $sec2 = ".rdata" ascii
        $sec3 = ".data" ascii
        $sec4 = ".rsrc" ascii

        // ── Privilege-escalation ACL command observed in WannaCry ───────
        $cmd1 = "icacls . /grant Everyone:F /T /C /Q" ascii wide
        $cmd2 = "attrib +h ." ascii wide
        $cmd3 = "vssadmin delete shadows /all /quiet" ascii wide

    condition:
        // Strong indicators on their own:
        any of ($mutex*) or
        any of ($name1, $name2, $name3, $name7) or
        any of ($ks*) or
        $note1 or $note3 or
        // Otherwise require a Windows PE *and* at least one weaker WannaCry token:
        (
            $mz at 0
            and $pe
            and 2 of ($sec*)
            and (any of ($ext*) or any of ($cmd*) or $name4 or $name5 or $name6 or $note2)
        )
}
