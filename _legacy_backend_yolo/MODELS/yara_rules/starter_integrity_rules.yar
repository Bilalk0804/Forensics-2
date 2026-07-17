rule EncodedPowerShellPayload
{
    meta:
        description = "Potential encoded PowerShell command or in-memory payload pattern"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "FromBase64String(" nocase
        $ps4 = "IEX(" nocase
    condition:
        2 of ($ps*)
}

rule SuspiciousScriptDropperPattern
{
    meta:
        description = "Script behavior often seen in droppers or persistence scripts"
        severity = "medium"
    strings:
        $s1 = "WScript.Shell" nocase
        $s2 = "Scripting.FileSystemObject" nocase
        $s3 = "cmd /c" nocase
        $s4 = "rundll32" nocase
        $s5 = "mshta" nocase
    condition:
        2 of ($s*)
}

rule RansomwareNotePhrase
{
    meta:
        description = "Common ransomware note phrase markers"
        severity = "high"
    strings:
        $r1 = "your files are encrypted" nocase
        $r2 = "decrypt your files" nocase
        $r3 = "bitcoin wallet" nocase
        $r4 = "contact us to recover" nocase
    condition:
        any of ($r*)
}
