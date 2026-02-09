/*
    Cereberus YARA Rules - Suspicious Strings
    Detects credential harvesting tools, crypto miners, data exfiltration
    patterns, and other suspicious string indicators.
*/

// ---------------------------------------------------------------------------
// Credential Harvesting
// ---------------------------------------------------------------------------

rule CredHarvest_Browser_Password_Theft {
    meta:
        author = "Cereberus"
        description = "Detects tools that steal credentials from browser password stores"
        severity = "critical"
        mitre_technique = "T1555.003"
        category = "credential_theft"
    strings:
        // Chrome credential paths and DB
        $chrome1 = "Login Data" ascii nocase
        $chrome2 = "\\Google\\Chrome\\User Data\\" ascii nocase
        $chrome3 = "logins" ascii
        $chrome4 = "password_value" ascii
        $chrome5 = "origin_url" ascii
        // Firefox credential files
        $ff1 = "signons.sqlite" ascii
        $ff2 = "logins.json" ascii
        $ff3 = "key3.db" ascii
        $ff4 = "key4.db" ascii
        $ff5 = "cert9.db" ascii
        // Edge
        $edge1 = "\\Microsoft\\Edge\\User Data\\" ascii nocase
        // Crypto API for decryption
        $crypt1 = "CryptUnprotectData" ascii
        $crypt2 = "BCryptDecrypt" ascii
        $crypt3 = "Dpapi" ascii nocase
        // Generic password store access
        $gen1 = "SELECT origin_url, username_value, password_value FROM logins" ascii nocase
        $gen2 = "SELECT host, name, value, encrypted_value FROM cookies" ascii nocase
    condition:
        (2 of ($chrome*) and 1 of ($crypt*)) or
        (2 of ($ff*)) or
        (1 of ($edge*) and 1 of ($crypt*)) or
        1 of ($gen*)
}

rule CredHarvest_Windows_Credential_Access {
    meta:
        author = "Cereberus"
        description = "Detects attempts to access Windows credential stores (SAM, LSA, DPAPI)"
        severity = "critical"
        mitre_technique = "T1003"
        category = "credential_theft"
    strings:
        // SAM database
        $sam1 = "\\SAM" ascii
        $sam2 = "\\SYSTEM" ascii
        $sam3 = "reg save HKLM\\SAM" ascii nocase
        $sam4 = "reg save HKLM\\SYSTEM" ascii nocase
        // LSA secrets
        $lsa1 = "LsaRetrievePrivateData" ascii
        $lsa2 = "LsaOpenPolicy" ascii
        $lsa3 = "SECURITY\\Policy\\Secrets" ascii
        // DPAPI
        $dpapi1 = "CryptUnprotectData" ascii
        $dpapi2 = "Microsoft\\Protect\\" ascii
        $dpapi3 = "Microsoft\\Credentials\\" ascii
        // NTDS
        $ntds1 = "ntds.dit" ascii nocase
        $ntds2 = "ntdsutil" ascii nocase
        $ntds3 = "NTDS.dit" ascii
        // Shadow copy for offline SAM
        $shadow1 = "vssadmin create shadow" ascii nocase
        $shadow2 = "wmic shadowcopy call create" ascii nocase
    condition:
        ($sam3 or $sam4) or
        ($sam1 and $sam2 and 1 of ($dpapi*)) or
        2 of ($lsa*) or
        1 of ($ntds*) or
        1 of ($shadow*)
}

rule CredHarvest_Keylogger_Strings {
    meta:
        author = "Cereberus"
        description = "Detects strings commonly found in keylogger implementations"
        severity = "high"
        mitre_technique = "T1056.001"
        category = "keylogger"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookExA" ascii
        $api3 = "SetWindowsHookExW" ascii
        $api4 = "GetKeyState" ascii
        $api5 = "GetKeyboardState" ascii
        $api6 = "MapVirtualKey" ascii
        $api7 = "GetForegroundWindow" ascii
        $api8 = "GetWindowText" ascii
        $hook1 = "WH_KEYBOARD" ascii
        $hook2 = "WH_KEYBOARD_LL" ascii
        $log1 = "keylog" ascii nocase
        $log2 = "keystroke" ascii nocase
        $log3 = "[ENTER]" ascii
        $log4 = "[BACKSPACE]" ascii
        $log5 = "[TAB]" ascii
        $log6 = "[SHIFT]" ascii
        $log7 = "[CTRL]" ascii
    condition:
        (2 of ($api*) and 1 of ($hook*)) or
        (2 of ($api*) and 2 of ($log*)) or
        4 of ($log*)
}

rule CredHarvest_Email_Credentials {
    meta:
        author = "Cereberus"
        description = "Detects tools that harvest email client credentials"
        severity = "high"
        mitre_technique = "T1555"
        category = "credential_theft"
    strings:
        $outlook1 = "Software\\Microsoft\\Office\\Outlook" ascii nocase
        $outlook2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" ascii nocase
        $outlook3 = "SMTP Password" ascii nocase
        $outlook4 = "POP3 Password" ascii nocase
        $outlook5 = "IMAP Password" ascii nocase
        $thunder1 = "\\Thunderbird\\Profiles\\" ascii nocase
        $thunder2 = "signons.sqlite" ascii
        $generic1 = "smtp_password" ascii nocase
        $generic2 = "imap_password" ascii nocase
        $generic3 = "pop3_password" ascii nocase
        $generic4 = "mail_password" ascii nocase
    condition:
        2 of ($outlook*) or
        2 of ($thunder*) or
        3 of ($generic*)
}

rule CredHarvest_WiFi_Passwords {
    meta:
        author = "Cereberus"
        description = "Detects extraction of saved WiFi passwords"
        severity = "medium"
        mitre_technique = "T1555"
        category = "credential_theft"
    strings:
        $wifi1 = "netsh wlan show profiles" ascii nocase
        $wifi2 = "netsh wlan show profile" ascii nocase
        $wifi3 = "key=clear" ascii nocase
        $wifi4 = "WlanGetProfile" ascii
        $wifi5 = "Wlansvc" ascii
        $wifi6 = "wlan_profile" ascii nocase
        $wifi7 = "WiFiPasswordReveal" ascii nocase
    condition:
        2 of them
}

// ---------------------------------------------------------------------------
// Crypto Miner Detection
// ---------------------------------------------------------------------------

rule CryptoMiner_Stratum_Protocol {
    meta:
        author = "Cereberus"
        description = "Detects cryptocurrency mining stratum protocol indicators"
        severity = "high"
        mitre_technique = "T1496"
        category = "cryptominer"
    strings:
        $stratum1 = "stratum+tcp://" ascii nocase
        $stratum2 = "stratum+ssl://" ascii nocase
        $stratum3 = "stratum+udp://" ascii nocase
        $method1 = "mining.subscribe" ascii
        $method2 = "mining.authorize" ascii
        $method3 = "mining.submit" ascii
        $method4 = "mining.notify" ascii
        $method5 = "mining.set_difficulty" ascii
        $method6 = "mining.set_extranonce" ascii
        $pool1 = "pool.minergate.com" ascii nocase
        $pool2 = "xmrpool.eu" ascii nocase
        $pool3 = "pool.hashvault.pro" ascii nocase
        $pool4 = "mine.moneropool.com" ascii nocase
        $pool5 = "pool.supportxmr.com" ascii nocase
        $pool6 = "monerohash.com" ascii nocase
        $pool7 = "nanopool.org" ascii nocase
        $pool8 = "2miners.com" ascii nocase
    condition:
        1 of ($stratum*) or
        2 of ($method*) or
        1 of ($pool*)
}

rule CryptoMiner_XMRig_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects XMRig and its variants (most common Monero miner)"
        severity = "high"
        mitre_technique = "T1496"
        category = "cryptominer"
    strings:
        $xmr1 = "xmrig" ascii nocase
        $xmr2 = "XMRig" ascii
        $xmr3 = "randomx" ascii nocase
        $xmr4 = "RandomX" ascii
        $xmr5 = "cryptonight" ascii nocase
        $xmr6 = "cn/r" ascii
        $xmr7 = "rx/0" ascii
        $xmr8 = "argon2" ascii nocase
        $cfg1 = "\"algo\"" ascii
        $cfg2 = "\"coin\"" ascii
        $cfg3 = "\"url\"" ascii
        $cfg4 = "\"user\"" ascii
        $cfg5 = "\"pass\"" ascii
        $cfg6 = "\"rig-id\"" ascii
        $wallet = /4[0-9AB][0-9a-zA-Z]{93}/ ascii  // Monero wallet address pattern
    condition:
        2 of ($xmr*) or
        (4 of ($cfg*) and 1 of ($xmr*)) or
        ($wallet and 1 of ($xmr*))
}

rule CryptoMiner_Browser_Based {
    meta:
        author = "Cereberus"
        description = "Detects browser-based cryptocurrency mining scripts (cryptojacking)"
        severity = "high"
        mitre_technique = "T1496"
        category = "cryptojacking"
    strings:
        $coinhive1 = "coinhive.min.js" ascii nocase
        $coinhive2 = "CoinHive.Anonymous" ascii
        $coinhive3 = "CoinHive.Token" ascii
        $generic1 = "cryptonight.wasm" ascii nocase
        $generic2 = "miner.start" ascii
        $generic3 = "startMining" ascii
        $generic4 = "CryptoLoot" ascii
        $generic5 = "coin-hive" ascii
        $generic6 = "deepMiner" ascii
        $generic7 = "jsecoin" ascii nocase
        $generic8 = "authedmine" ascii nocase
        $generic9 = "WebAssembly.instantiate" ascii
        $wasm1 = "crypto-loot.com" ascii
        $wasm2 = "webmine.pro" ascii
        $wasm3 = "ppoi.org" ascii
    condition:
        2 of them
}

rule CryptoMiner_Generic_Indicators {
    meta:
        author = "Cereberus"
        description = "Detects generic cryptocurrency miner indicators by algorithm and behavior strings"
        severity = "medium"
        mitre_technique = "T1496"
        category = "cryptominer"
    strings:
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "ethash" ascii nocase
        $algo3 = "equihash" ascii nocase
        $algo4 = "kawpow" ascii nocase
        $algo5 = "progpow" ascii nocase
        $algo6 = "scrypt" ascii nocase
        $algo7 = "sha256d" ascii nocase
        $algo8 = "randomx" ascii nocase
        $behav1 = "hashrate" ascii nocase
        $behav2 = "hash rate" ascii nocase
        $behav3 = "hashes/s" ascii nocase
        $behav4 = "kH/s" ascii
        $behav5 = "MH/s" ascii
        $behav6 = "GH/s" ascii
        $behav7 = "accepted share" ascii nocase
        $behav8 = "rejected share" ascii nocase
        $behav9 = "pool_address" ascii nocase
        $behav10 = "wallet_address" ascii nocase
        $gpu1 = "cuda" ascii nocase
        $gpu2 = "opencl" ascii nocase
        $gpu3 = "nvml" ascii nocase
    condition:
        (1 of ($algo*) and 2 of ($behav*)) or
        (1 of ($algo*) and 1 of ($gpu*) and 1 of ($behav*))
}

// ---------------------------------------------------------------------------
// Data Exfiltration Indicators
// ---------------------------------------------------------------------------

rule Exfiltration_DNS_Tunneling {
    meta:
        author = "Cereberus"
        description = "Detects tools and scripts used for DNS tunneling data exfiltration"
        severity = "high"
        mitre_technique = "T1048.003"
        category = "exfiltration"
    strings:
        $dns1 = "dnscat" ascii nocase
        $dns2 = "iodine" ascii nocase
        $dns3 = "dns2tcp" ascii nocase
        $dns4 = "dnsexfiltrator" ascii nocase
        $dns5 = "DNSExfil" ascii nocase
        $tech1 = "TXT record" ascii nocase
        $tech2 = "nslookup" ascii
        $tech3 = "Resolve-DnsName" ascii
        $tech4 = ".burpcollaborator.net" ascii nocase
        $tech5 = "dns_exfil" ascii nocase
        $tech6 = "subdomain" ascii nocase
        $encode1 = "base32" ascii nocase
        $encode2 = "base64" ascii nocase
    condition:
        1 of ($dns*) or
        (2 of ($tech*) and 1 of ($encode*))
}

rule Exfiltration_Cloud_Upload {
    meta:
        author = "Cereberus"
        description = "Detects patterns suggesting data exfiltration via cloud storage services"
        severity = "medium"
        mitre_technique = "T1567.002"
        category = "exfiltration"
    strings:
        $cloud1 = "dropbox.com/oauth2" ascii nocase
        $cloud2 = "content.dropboxapi.com" ascii nocase
        $cloud3 = "drive.google.com" ascii nocase
        $cloud4 = "googleapis.com/upload" ascii nocase
        $cloud5 = "graph.microsoft.com" ascii nocase
        $cloud6 = "onedrive.live.com" ascii nocase
        $cloud7 = "api.mega.nz" ascii nocase
        $cloud8 = "transfer.sh" ascii nocase
        $cloud9 = "file.io" ascii nocase
        $cloud10 = "anonfiles.com" ascii nocase
        $action1 = "upload" ascii nocase
        $action2 = "PUT /files/" ascii
        $action3 = "multipart/form-data" ascii
        $staging1 = "compress" ascii nocase
        $staging2 = "archive" ascii nocase
        $staging3 = "ZipFile" ascii nocase
    condition:
        (1 of ($cloud*) and 1 of ($action*) and 1 of ($staging*))
}

// ---------------------------------------------------------------------------
// Reconnaissance / Discovery
// ---------------------------------------------------------------------------

rule Recon_System_Enumeration {
    meta:
        author = "Cereberus"
        description = "Detects scripts or tools performing aggressive local system enumeration"
        severity = "medium"
        mitre_technique = "T1082"
        category = "discovery"
    strings:
        $cmd1 = "systeminfo" ascii nocase
        $cmd2 = "whoami /all" ascii nocase
        $cmd3 = "net user" ascii nocase
        $cmd4 = "net localgroup" ascii nocase
        $cmd5 = "ipconfig /all" ascii nocase
        $cmd6 = "netstat -an" ascii nocase
        $cmd7 = "tasklist /v" ascii nocase
        $cmd8 = "wmic qfe" ascii nocase
        $cmd9 = "schtasks /query" ascii nocase
        $cmd10 = "arp -a" ascii nocase
        $cmd11 = "route print" ascii nocase
        $cmd12 = "netsh firewall show" ascii nocase
        $cmd13 = "wmic product get" ascii nocase
        $cmd14 = "net share" ascii nocase
        $cmd15 = "net view" ascii nocase
        $cmd16 = "nltest /domain_trusts" ascii nocase
    condition:
        5 of them
}

rule Recon_Network_Scanning {
    meta:
        author = "Cereberus"
        description = "Detects network scanning tools and patterns"
        severity = "medium"
        mitre_technique = "T1046"
        category = "discovery"
    strings:
        $tool1 = "nmap" ascii nocase
        $tool2 = "masscan" ascii nocase
        $tool3 = "zmap" ascii nocase
        $tool4 = "Advanced IP Scanner" ascii nocase
        $tool5 = "Angry IP Scanner" ascii nocase
        $scan1 = "SYN scan" ascii nocase
        $scan2 = "port scan" ascii nocase
        $scan3 = "TCP connect" ascii nocase
        $scan4 = "-sS -sV" ascii
        $scan5 = "-p 1-65535" ascii
        $scan6 = "open ports" ascii nocase
        $net1 = "ICMP echo" ascii nocase
        $net2 = "ping sweep" ascii nocase
    condition:
        2 of ($tool*) or
        (1 of ($tool*) and 2 of ($scan*)) or
        (3 of ($scan*) and 1 of ($net*))
}

// ---------------------------------------------------------------------------
// Persistence Mechanisms
// ---------------------------------------------------------------------------

rule Persistence_Registry_Run_Keys {
    meta:
        author = "Cereberus"
        description = "Detects manipulation of registry Run keys for persistence"
        severity = "high"
        mitre_technique = "T1547.001"
        category = "persistence"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii nocase
        $reg3 = "CurrentVersion\\RunServices" ascii nocase
        $reg4 = "CurrentVersion\\Policies\\Explorer\\Run" ascii nocase
        $reg5 = "CurrentVersion\\Explorer\\Shell Folders" ascii nocase
        $reg6 = "CurrentVersion\\Explorer\\User Shell Folders" ascii nocase
        $reg7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
        $api3 = "reg add" ascii nocase
        $ps1 = "Set-ItemProperty" ascii
        $ps2 = "New-ItemProperty" ascii
    condition:
        1 of ($reg*) and (1 of ($api*) or 1 of ($ps*))
}

rule Persistence_Scheduled_Task_Creation {
    meta:
        author = "Cereberus"
        description = "Detects creation of scheduled tasks for persistence"
        severity = "high"
        mitre_technique = "T1053.005"
        category = "persistence"
    strings:
        $schtask1 = "schtasks /create" ascii nocase
        $schtask2 = "schtasks.exe /create" ascii nocase
        $schtask3 = "Register-ScheduledTask" ascii
        $schtask4 = "New-ScheduledTaskAction" ascii
        $schtask5 = "New-ScheduledTaskTrigger" ascii
        $schtask6 = "ITaskService" ascii
        $schtask7 = "ITaskDefinition" ascii
        $com1 = "Schedule.Service" ascii
        $com2 = "GetFolder" ascii
        $com3 = "RegisterTaskDefinition" ascii
    condition:
        1 of ($schtask*) or
        (2 of ($com*))
}

// ---------------------------------------------------------------------------
// Anti-Analysis / Evasion
// ---------------------------------------------------------------------------

rule AntiAnalysis_VM_Detection {
    meta:
        author = "Cereberus"
        description = "Detects anti-VM and sandbox evasion techniques"
        severity = "medium"
        mitre_technique = "T1497"
        category = "evasion"
    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "VBOX" ascii
        $vm4 = "QEMU" ascii
        $vm5 = "Xen" ascii
        $vm6 = "Hyper-V" ascii nocase
        $vm7 = "vmtoolsd" ascii nocase
        $vm8 = "vboxservice" ascii nocase
        $vm9 = "sbiedll.dll" ascii nocase
        $vm10 = "dbghelp.dll" ascii nocase
        $reg1 = "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum" ascii nocase
        $reg2 = "SOFTWARE\\VMware, Inc." ascii nocase
        $reg3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii nocase
        $mac1 = "00:0C:29" ascii  // VMware MAC prefix
        $mac2 = "00:50:56" ascii  // VMware MAC prefix
        $mac3 = "08:00:27" ascii  // VirtualBox MAC prefix
        $hw1 = "Red Hat VirtIO" ascii
        $hw2 = "BOCHS" ascii
    condition:
        4 of them
}

rule AntiAnalysis_Debugger_Detection {
    meta:
        author = "Cereberus"
        description = "Detects anti-debugging techniques"
        severity = "medium"
        mitre_technique = "T1622"
        category = "evasion"
    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
        $api5 = "QueryPerformanceCounter" ascii
        $api6 = "GetTickCount" ascii
        $api7 = "rdtsc" ascii
        $api8 = "NtSetInformationThread" ascii
        $api9 = "ZwQuerySystemInformation" ascii
        $int1 = { CC }  // INT3
        $int2 = { CD 03 }  // INT 0x03
        $proc1 = "ollydbg" ascii nocase
        $proc2 = "x64dbg" ascii nocase
        $proc3 = "windbg" ascii nocase
        $proc4 = "ida.exe" ascii nocase
        $proc5 = "processhacker" ascii nocase
    condition:
        3 of ($api*) or
        (1 of ($api*) and 2 of ($proc*))
}

// ---------------------------------------------------------------------------
// Suspicious Encoded Content
// ---------------------------------------------------------------------------

rule Suspicious_PowerShell_Encoded {
    meta:
        author = "Cereberus"
        description = "Detects suspicious PowerShell encoded commands and obfuscation patterns"
        severity = "high"
        mitre_technique = "T1059.001"
        category = "execution"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "-e JAB" ascii nocase
        $enc4 = "-e SQBF" ascii nocase
        $enc5 = "-e SQBu" ascii nocase
        $enc6 = "-e cwB" ascii nocase
        $obf1 = "[Convert]::FromBase64String" ascii nocase
        $obf2 = "[System.Text.Encoding]::Unicode.GetString" ascii nocase
        $obf3 = "iex(" ascii nocase
        $obf4 = "Invoke-Expression" ascii nocase
        $obf5 = "New-Object System.Net.WebClient" ascii nocase
        $obf6 = ".DownloadString(" ascii nocase
        $obf7 = ".DownloadFile(" ascii nocase
        $obf8 = "Net.WebRequest" ascii nocase
        $bypass1 = "Set-ExecutionPolicy Bypass" ascii nocase
        $bypass2 = "-ExecutionPolicy Bypass" ascii nocase
        $bypass3 = "-ep bypass" ascii nocase
        $amsi1 = "AmsiUtils" ascii
        $amsi2 = "amsiInitFailed" ascii
        $amsi3 = "AmsiScanBuffer" ascii
    condition:
        (1 of ($enc*) and 1 of ($obf*)) or
        (2 of ($obf*) and 1 of ($bypass*)) or
        1 of ($amsi*)
}
