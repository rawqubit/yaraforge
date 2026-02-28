/*
 * Ransomware Detection Rules
 * Category: Ransomware
 * Author: rawqubit
 */

rule GenericRansomwareNote
{
    meta:
        description = "Detects common ransomware note patterns"
        severity = "critical"
        tags = "ransomware, ransom-note"

    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "All your files are encrypted" nocase
        $note3 = "To decrypt your files" nocase
        $note4 = "pay the ransom" nocase
        $note5 = "Bitcoin address" nocase
        $note6 = "DO NOT try to recover" nocase
        $note7 = "unique decryption key" nocase

    condition:
        2 of them
}

rule RansomwareFileExtensionModification
{
    meta:
        description = "Detects code patterns used to rename files with ransomware extensions"
        severity = "critical"
        tags = "ransomware, file-modification"

    strings:
        $rename1 = "MoveFileEx" nocase
        $rename2 = "rename(" nocase
        $rename3 = "os.rename" nocase
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypt" nocase
        $ext4 = ".enc" nocase
        $ext5 = ".WNCRY" nocase

    condition:
        any of ($rename*) and any of ($ext*)
}

rule RansomwareCryptoAPIUsage
{
    meta:
        description = "Detects Windows CryptoAPI usage patterns common in ransomware"
        severity = "high"
        tags = "ransomware, crypto, windows-api"

    strings:
        $mz = { 4D 5A }
        $crypt_gen  = "CryptGenRandom" nocase
        $crypt_enc  = "CryptEncrypt" nocase
        $crypt_key  = "CryptGenKey" nocase
        $aes_str    = "AES" nocase
        $rsa_str    = "RSA" nocase

    condition:
        $mz at 0 and 2 of ($crypt_gen, $crypt_enc, $crypt_key) and ($aes_str or $rsa_str)
}

rule WannaCryIndicators
{
    meta:
        description = "Detects WannaCry ransomware indicators"
        severity = "critical"
        tags = "ransomware, wannacry, eternalblue"
        reference = "https://www.cisa.gov/wannacry"

    strings:
        $mutex    = "Global\\WannaDecryptor" nocase
        $killswitch = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" nocase
        $service  = "mssecsvc2.0" nocase
        $wncry    = ".WNCRY" nocase
        $tasksche = "tasksche.exe" nocase

    condition:
        2 of them
}
