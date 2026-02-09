/*
    Cereberus YARA Rules - Ransomware Indicators
    Detects ransom note content, ransomware file extension patterns,
    encryption behavior, shadow copy deletion, and known ransomware families.
*/

import "pe"
import "math"

// ---------------------------------------------------------------------------
// Ransom Note Detection
// ---------------------------------------------------------------------------

rule Ransom_Note_Generic_Strings {
    meta:
        author = "Cereberus"
        description = "Detects files containing common ransom note phrases"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware"
    strings:
        $note1 = "your files have been encrypted" ascii nocase
        $note2 = "your important files" ascii nocase
        $note3 = "all your files" ascii nocase
        $note4 = "files are encrypted" ascii nocase
        $note5 = "to decrypt your files" ascii nocase
        $note6 = "decrypt your data" ascii nocase
        $note7 = "recover your files" ascii nocase
        $note8 = "files will be lost" ascii nocase
        $note9 = "pay the ransom" ascii nocase
        $note10 = "bitcoin wallet" ascii nocase
        $note11 = "send bitcoin" ascii nocase
        $note12 = "BTC to the following" ascii nocase
        $note13 = "personal decryption key" ascii nocase
        $note14 = "unique decryption key" ascii nocase
        $note15 = "decryption tool" ascii nocase
        $note16 = "purchase decryption" ascii nocase
        $note17 = "private key will be destroyed" ascii nocase
        $deadline1 = "you have 72 hours" ascii nocase
        $deadline2 = "you have 48 hours" ascii nocase
        $deadline3 = "time is running out" ascii nocase
        $deadline4 = "deadline" ascii nocase
        $tor1 = ".onion" ascii nocase
        $tor2 = "tor browser" ascii nocase
        $tor3 = "torproject.org" ascii nocase
        $crypto1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii  // Bitcoin address
        $crypto2 = /0x[0-9a-fA-F]{40}/ ascii  // Ethereum address
    condition:
        (3 of ($note*)) or
        (2 of ($note*) and 1 of ($deadline*)) or
        (2 of ($note*) and 1 of ($tor*)) or
        (2 of ($note*) and 1 of ($crypto*))
}

rule Ransom_Note_Known_Filenames {
    meta:
        author = "Cereberus"
        description = "Detects files with names matching known ransom note filenames"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware"
    strings:
        $fn1 = "README_TO_DECRYPT" ascii nocase
        $fn2 = "HOW_TO_DECRYPT" ascii nocase
        $fn3 = "HOW_TO_RECOVER" ascii nocase
        $fn4 = "DECRYPT_INSTRUCTIONS" ascii nocase
        $fn5 = "RECOVER_FILES" ascii nocase
        $fn6 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase
        $fn7 = "_readme.txt" ascii nocase
        $fn8 = "HELP_DECRYPT" ascii nocase
        $fn9 = "DECRYPT_INFORMATION" ascii nocase
        $fn10 = "RESTORE_FILES" ascii nocase
        $fn11 = "#DECRYPT#" ascii nocase
        $fn12 = "!README!" ascii nocase
        $fn13 = "_RECOVERY_+" ascii nocase
        $fn14 = "ATTENTION!!!" ascii nocase
        $fn15 = "READ_ME_FOR_DECRYPT" ascii nocase
    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Ransomware Extension Patterns
// ---------------------------------------------------------------------------

rule Ransomware_Extension_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects ransomware-associated file extension strings in binaries (extension appending logic)"
        severity = "high"
        mitre_technique = "T1486"
        category = "ransomware"
    strings:
        $ext1 = ".locked" ascii nocase
        $ext2 = ".encrypted" ascii nocase
        $ext3 = ".enc" ascii
        $ext4 = ".crypted" ascii nocase
        $ext5 = ".crypt" ascii nocase
        $ext6 = ".locky" ascii nocase
        $ext7 = ".cerber" ascii nocase
        $ext8 = ".zepto" ascii nocase
        $ext9 = ".thor" ascii nocase
        $ext10 = ".aesir" ascii nocase
        $ext11 = ".sage" ascii nocase
        $ext12 = ".dharma" ascii nocase
        $ext13 = ".phobos" ascii nocase
        $ext14 = ".rapid" ascii nocase
        $ext15 = ".ryuk" ascii nocase
        $ext16 = ".sodinokibi" ascii nocase
        $ext17 = ".revil" ascii nocase
        $ext18 = ".conti" ascii nocase
        $ext19 = ".blackmatter" ascii nocase
        $ext20 = ".lockbit" ascii nocase
        $ext21 = ".hive" ascii nocase
        $ext22 = ".babuk" ascii nocase
        $ext23 = ".avaddon" ascii nocase
        $ext24 = ".blackcat" ascii nocase
        $ext25 = ".alphv" ascii nocase
        $ext26 = ".royal" ascii nocase
        $ext27 = ".akira" ascii nocase
        // Rename pattern strings
        $rename1 = "MoveFileEx" ascii
        $rename2 = "MoveFileW" ascii
        $rename3 = "rename" ascii
    condition:
        2 of ($ext*) and 1 of ($rename*)
}

// ---------------------------------------------------------------------------
// Ransomware Encryption Behavior
// ---------------------------------------------------------------------------

rule Ransomware_Crypto_API_Usage {
    meta:
        author = "Cereberus"
        description = "Detects executables using crypto APIs in patterns consistent with ransomware file encryption"
        severity = "high"
        mitre_technique = "T1486"
        category = "ransomware"
    strings:
        // Windows CryptoAPI
        $capi1 = "CryptAcquireContext" ascii
        $capi2 = "CryptGenRandom" ascii
        $capi3 = "CryptEncrypt" ascii
        $capi4 = "CryptImportKey" ascii
        $capi5 = "CryptExportKey" ascii
        $capi6 = "CryptGenKey" ascii
        $capi7 = "CryptDeriveKey" ascii
        // BCrypt (newer API)
        $bcrypt1 = "BCryptEncrypt" ascii
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii
        $bcrypt3 = "BCryptImportKeyPair" ascii
        $bcrypt4 = "BCryptGenerateKeyPair" ascii
        // Algorithm identifiers
        $algo1 = "RSA" ascii
        $algo2 = "AES" ascii
        $algo3 = "CALG_AES_256" ascii
        $algo4 = "CALG_RSA_KEYX" ascii
        $algo5 = "Microsoft Enhanced RSA" ascii
        // File enumeration (needed for mass encryption)
        $enum1 = "FindFirstFileW" ascii
        $enum2 = "FindNextFileW" ascii
        $enum3 = "FindFirstFileA" ascii
        $enum4 = "FindNextFileA" ascii
        // File I/O
        $io1 = "ReadFile" ascii
        $io2 = "WriteFile" ascii
        $io3 = "CreateFileW" ascii
        $io4 = "SetFilePointer" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($capi*) or 2 of ($bcrypt*)) and
        1 of ($algo*) and
        1 of ($enum*) and
        2 of ($io*)
}

rule Ransomware_High_Entropy_Executable {
    meta:
        author = "Cereberus"
        description = "Detects PE with embedded high-entropy blob (embedded encrypted payload or key material) plus file enumeration"
        severity = "medium"
        mitre_technique = "T1486"
        category = "ransomware"
    strings:
        $enum1 = "FindFirstFile" ascii
        $enum2 = "FindNextFile" ascii
        $write = "WriteFile" ascii
        $crypt = "Crypt" ascii
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 7.0 and
        1 of ($enum*) and
        $write and $crypt
}

// ---------------------------------------------------------------------------
// Shadow Copy Deletion (Pre-Encryption)
// ---------------------------------------------------------------------------

rule Ransomware_Shadow_Copy_Deletion {
    meta:
        author = "Cereberus"
        description = "Detects commands used to delete Volume Shadow Copies, a hallmark of ransomware pre-encryption"
        severity = "critical"
        mitre_technique = "T1490"
        category = "ransomware"
    strings:
        $vss1 = "vssadmin delete shadows" ascii nocase
        $vss2 = "vssadmin.exe delete shadows" ascii nocase
        $vss3 = "vssadmin Delete Shadows /All /Quiet" ascii nocase
        $vss4 = "vssadmin resize shadowstorage" ascii nocase
        $wmic1 = "wmic shadowcopy delete" ascii nocase
        $wmic2 = "Win32_ShadowCopy" ascii nocase
        $ps1 = "Get-WmiObject Win32_Shadowcopy" ascii nocase
        $ps2 = "Delete-WmiObject" ascii nocase
        $bcdedit1 = "bcdedit /set {default} recoveryenabled No" ascii nocase
        $bcdedit2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
        $wbadmin1 = "wbadmin delete catalog" ascii nocase
        $wbadmin2 = "wbadmin delete systemstatebackup" ascii nocase
        $diskshadow = "diskshadow /s" ascii nocase
    condition:
        any of them
}

rule Ransomware_Recovery_Sabotage {
    meta:
        author = "Cereberus"
        description = "Detects multiple recovery sabotage techniques used together (backup deletion, safe mode manipulation, firewall changes)"
        severity = "critical"
        mitre_technique = "T1490"
        category = "ransomware"
    strings:
        $vss = "vssadmin" ascii nocase
        $bcd = "bcdedit" ascii nocase
        $wba = "wbadmin" ascii nocase
        $rec1 = "recoveryenabled" ascii nocase
        $rec2 = "bootstatuspolicy" ascii nocase
        $fw1 = "netsh advfirewall set" ascii nocase
        $fw2 = "netsh firewall set" ascii nocase
        $safeboot = "safeboot" ascii nocase
        $cipher = "cipher /w:" ascii nocase
        $format1 = "format" ascii nocase
        $del1 = "del /s /f /q" ascii nocase
    condition:
        3 of them
}

// ---------------------------------------------------------------------------
// Known Ransomware Families
// ---------------------------------------------------------------------------

rule Ransomware_LockBit_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects indicators associated with LockBit ransomware family"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware_family"
    strings:
        $lb1 = "LockBit" ascii nocase
        $lb2 = ".lockbit" ascii nocase
        $lb3 = "Restore-My-Files.txt" ascii nocase
        $lb4 = "LockBit_Ransomware" ascii nocase
        $lb5 = "lockbit3" ascii nocase
        $lb6 = "LockBit Black" ascii nocase
        $lb7 = "LockBit Green" ascii nocase
        $mutex1 = "Global\\{" ascii
        $svc1 = "sc stop" ascii nocase
        $svc2 = "sc delete" ascii nocase
        // LockBit 3.0 API hashing
        $hash1 = { 8B 44 24 ?? 33 C9 0F B6 10 C1 C9 0D 03 CA }
    condition:
        2 of ($lb*) or
        ($hash1 and 1 of ($lb*))
}

rule Ransomware_BlackCat_ALPHV_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects indicators associated with BlackCat/ALPHV ransomware (Rust-based)"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware_family"
    strings:
        $bc1 = "alphv" ascii nocase
        $bc2 = "blackcat" ascii nocase
        $bc3 = "access-key" ascii nocase
        $bc4 = "--access-token" ascii nocase
        $bc5 = "RECOVER-" ascii
        $bc6 = "-FILES.txt" ascii
        // Rust compilation artifacts
        $rust1 = ".rdata$" ascii
        $rust2 = "core::fmt" ascii
        $rust3 = "core::panicking" ascii
        $cfg1 = "\"config\":" ascii
        $cfg2 = "\"extension\":" ascii
        $cfg3 = "\"note_file_name\":" ascii
        $cfg4 = "\"credential\":" ascii
    condition:
        2 of ($bc*) or
        (2 of ($rust*) and 2 of ($cfg*))
}

rule Ransomware_Conti_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects indicators associated with Conti ransomware"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware_family"
    strings:
        $c1 = "CONTI" ascii
        $c2 = ".conti" ascii nocase
        $c3 = "readme.txt" ascii nocase
        $c4 = "CONTI_README" ascii
        $mutex1 = "hsfjuukjzloqu28oajh727190" ascii
        $mutex2 = "jkshgjkdshg83724jshgf" ascii
        // Known Conti API resolution pattern
        $api_hash = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? 68 ?? ?? ?? ?? 50 E8 }
        $str1 = "HOW TO CONTACT" ascii nocase
        $str2 = "YOU SHOULD BE AWARE" ascii nocase
    condition:
        2 of ($c*) or
        1 of ($mutex*) or
        ($api_hash and 1 of ($str*))
}

rule Ransomware_REvil_Sodinokibi_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects indicators associated with REvil/Sodinokibi ransomware"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware_family"
    strings:
        $r1 = "sodinokibi" ascii nocase
        $r2 = "REvil" ascii nocase
        $r3 = "Sodin" ascii nocase
        $cfg1 = "\"pk\":" ascii
        $cfg2 = "\"pid\":" ascii
        $cfg3 = "\"sub\":" ascii
        $cfg4 = "\"dbg\":" ascii
        $cfg5 = "\"wht\":" ascii
        $cfg6 = "\"fld\":" ascii
        $cfg7 = "\"ext\":" ascii
        $cfg8 = "\"nbody\":" ascii
        $cfg9 = "\"nname\":" ascii
        $note1 = "{EXT}-readme.txt" ascii nocase
        $note2 = "Welcome. Read carefully." ascii nocase
        $note3 = "Your files are encrypted by" ascii nocase
    condition:
        1 of ($r*) or
        4 of ($cfg*) or
        2 of ($note*)
}

rule Ransomware_Ryuk_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects indicators associated with Ryuk ransomware"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware_family"
    strings:
        $ryuk1 = "RyukReadMe" ascii nocase
        $ryuk2 = ".ryk" ascii nocase
        $ryuk3 = "UNIQUE_ID_DO_NOT_REMOVE" ascii
        $ryuk4 = "RYK" ascii
        $ryuk5 = "HERMES" ascii
        $note1 = "balance of the shadow universe" ascii nocase
        $note2 = "No system is safe" ascii nocase
        $note3 = "protonmail.com" ascii nocase
        $note4 = "tutanota.com" ascii nocase
        // Known Ryuk import resolution
        $marker = { 52 59 55 4B }  // "RYUK" marker
    condition:
        2 of ($ryuk*) or
        ($marker and 1 of ($note*)) or
        3 of ($note*)
}

rule Ransomware_Akira_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects indicators associated with Akira ransomware"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware_family"
    strings:
        $a1 = "akira" ascii nocase
        $a2 = ".akira" ascii nocase
        $a3 = "akira_readme.txt" ascii nocase
        $note1 = "Hi friend" ascii
        $note2 = "Whatever who you are" ascii
        $note3 = "akira" ascii nocase
        $note4 = "data breach" ascii nocase
        $tor1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion" ascii
        $chacha = "ChaCha" ascii
        $rsa = "RSA" ascii
    condition:
        2 of ($a*) or
        ($tor1) or
        (2 of ($note*) and ($chacha or $rsa))
}

// ---------------------------------------------------------------------------
// Ransomware Behavioral Patterns
// ---------------------------------------------------------------------------

rule Ransomware_Service_Killer {
    meta:
        author = "Cereberus"
        description = "Detects attempts to stop security services and databases before encryption"
        severity = "critical"
        mitre_technique = "T1489"
        category = "ransomware"
    strings:
        $sc1 = "sc stop" ascii nocase
        $sc2 = "net stop" ascii nocase
        $sc3 = "taskkill /f /im" ascii nocase
        // Targeted services
        $svc1 = "vss" ascii nocase
        $svc2 = "sql" ascii nocase
        $svc3 = "svc$" ascii nocase
        $svc4 = "memtas" ascii nocase
        $svc5 = "mepocs" ascii nocase
        $svc6 = "sophos" ascii nocase
        $svc7 = "veeam" ascii nocase
        $svc8 = "backup" ascii nocase
        $svc9 = "GxVss" ascii nocase
        $svc10 = "GxBlr" ascii nocase
        $svc11 = "GxFWD" ascii nocase
        $svc12 = "GxCVD" ascii nocase
        $svc13 = "GxCIMgr" ascii nocase
        // Targeted processes
        $proc1 = "sqlservr.exe" ascii nocase
        $proc2 = "mysqld.exe" ascii nocase
        $proc3 = "oracle.exe" ascii nocase
        $proc4 = "ocssd.exe" ascii nocase
        $proc5 = "dbsnmp.exe" ascii nocase
        $proc6 = "synctime.exe" ascii nocase
        $proc7 = "agntsvc.exe" ascii nocase
        $proc8 = "isqlplussvc.exe" ascii nocase
        $proc9 = "xfssvccon.exe" ascii nocase
        $proc10 = "encsvc.exe" ascii nocase
        $proc11 = "msftesql.exe" ascii nocase
    condition:
        1 of ($sc*) and (3 of ($svc*) or 3 of ($proc*))
}

rule Ransomware_Mass_File_Rename {
    meta:
        author = "Cereberus"
        description = "Detects PE files combining directory traversal, file renaming, and cryptographic operations indicative of ransomware"
        severity = "critical"
        mitre_technique = "T1486"
        category = "ransomware"
    strings:
        // Directory traversal
        $dir1 = "FindFirstFileW" ascii
        $dir2 = "FindNextFileW" ascii
        $dir3 = "FindFirstFileA" ascii
        $dir4 = "FindNextFileA" ascii
        // File renaming
        $ren1 = "MoveFileW" ascii
        $ren2 = "MoveFileExW" ascii
        $ren3 = "MoveFileA" ascii
        $ren4 = "MoveFileExA" ascii
        // Crypto
        $cry1 = "CryptEncrypt" ascii
        $cry2 = "BCryptEncrypt" ascii
        $cry3 = "CryptGenKey" ascii
        $cry4 = "BCryptGenerateSymmetricKey" ascii
        // File header read (checking magic bytes before encrypting)
        $hdr1 = "ReadFile" ascii
        $hdr2 = "SetFilePointer" ascii
        // Skip list indicators (ransomware avoids encrypting system files)
        $skip1 = ".exe" ascii
        $skip2 = ".dll" ascii
        $skip3 = ".sys" ascii
        $skip4 = "Windows" ascii
        $skip5 = "Program Files" ascii
    condition:
        uint16(0) == 0x5A4D and
        1 of ($dir*) and
        1 of ($ren*) and
        1 of ($cry*) and
        1 of ($hdr*) and
        3 of ($skip*)
}

rule Ransomware_Wallpaper_Change {
    meta:
        author = "Cereberus"
        description = "Detects ransomware behavior of changing the desktop wallpaper to display ransom message"
        severity = "high"
        mitre_technique = "T1491.001"
        category = "ransomware"
    strings:
        $wall1 = "SystemParametersInfoW" ascii
        $wall2 = "SystemParametersInfoA" ascii
        $wall3 = "SPI_SETDESKWALLPAPER" ascii
        $wall4 = { 14 00 00 00 }  // SPI_SETDESKWALLPAPER constant value 0x14
        $note1 = "encrypted" ascii nocase
        $note2 = "ransom" ascii nocase
        $note3 = "decrypt" ascii nocase
        $note4 = "bitcoin" ascii nocase
        $img1 = ".bmp" ascii nocase
        $img2 = ".jpg" ascii nocase
        $img3 = ".png" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        1 of ($wall*) and
        1 of ($note*) and
        1 of ($img*)
}

// ---------------------------------------------------------------------------
// Double Extortion / Data Theft Before Encryption
// ---------------------------------------------------------------------------

rule Ransomware_Data_Staging {
    meta:
        author = "Cereberus"
        description = "Detects data collection and staging behavior typical of double-extortion ransomware"
        severity = "high"
        mitre_technique = "T1560.001"
        category = "ransomware"
    strings:
        // Archive creation
        $arc1 = "7z.exe" ascii nocase
        $arc2 = "7za.exe" ascii nocase
        $arc3 = "rar.exe" ascii nocase
        $arc4 = "zip" ascii nocase
        $arc5 = "tar" ascii nocase
        // Compression flags
        $flag1 = " a -p" ascii  // 7z/rar password-protected archive
        $flag2 = "-mhe=on" ascii  // 7z encrypted headers
        $flag3 = "-hp" ascii  // rar header password
        // Targeted file types
        $doc1 = ".docx" ascii nocase
        $doc2 = ".xlsx" ascii nocase
        $doc3 = ".pdf" ascii nocase
        $doc4 = ".sql" ascii nocase
        $doc5 = ".mdb" ascii nocase
        $doc6 = ".pst" ascii nocase
        $doc7 = ".dwg" ascii nocase
        $doc8 = ".vmdk" ascii nocase
        // Upload indicators
        $up1 = "rclone" ascii nocase
        $up2 = "mega-cmd" ascii nocase
        $up3 = "megasync" ascii nocase
        $up4 = "filezilla" ascii nocase
        $up5 = "winscp" ascii nocase
    condition:
        (1 of ($arc*) and 1 of ($flag*)) or
        (1 of ($arc*) and 3 of ($doc*) and 1 of ($up*))
}
