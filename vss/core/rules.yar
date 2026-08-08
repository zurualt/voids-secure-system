rule miner_xmrig {
    meta:
        severity = "critical"
        category = "miner"
        desc = "XMRig miner signature (Monero)"
    strings:
        $a = "xmrig" nocase
        $b = "--donate-level" nocase
        $c = "--cpu-priority" nocase
        $d = "randomx_create_vm" nocase
        $e = "stratum+tcp://" nocase
        $f = "\"rx/0\"" nocase
    condition:
        2 of them
}

rule miner_pool_protocol {
    meta:
        severity = "high"
        category = "miner"
        desc = "Mining pool protocol / stratum login"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
        $c = "mining.subscribe" nocase
        $d = "mining.authorize" nocase
        $e = "\"job_id\"" nocase
        $f = "\"blob\"" nocase
    condition:
        2 of them
}

rule miner_pool_hosts {
    meta:
        severity = "high"
        category = "miner"
        desc = "Known mining pool domains"
    strings:
        $a = "pool.supportxmr.com" nocase
        $b = "xmr.nanopool.org" nocase
        $c = "gulf.moneroocean.stream" nocase
        $d = "pool.minexmr.com" nocase
        $e = "randomxmonero.hashvault.pro" nocase
        $f = "nicehash.com" nocase
        $g = "pool.hashvault.pro" nocase
    condition:
        any of them
}

rule packer_upx {
    meta:
        severity = "low"
        category = "packer"
        desc = "Packed with UPX"
    strings:
        $a = "UPX0"
        $b = "UPX1"
        $c = "UPX!"
    condition:
        2 of them
}

rule packer_themida_winlicense {
    meta:
        severity = "medium"
        category = "packer"
        desc = "Themida / WinLicense protector"
    strings:
        $a = "Themida"
        $b = ".themida"
        $c = "WinLicense"
        $d = ".winlice"
    condition:
        any of them
}

rule packer_vmprotect {
    meta:
        severity = "medium"
        category = "packer"
        desc = "VMProtect protector"
    strings:
        $a = ".vmp0"
        $b = ".vmp1"
        $c = "VMProtect"
    condition:
        any of them
}

rule packer_enigma_mpress {
    meta:
        severity = "medium"
        category = "packer"
        desc = "Enigma / MPRESS / ASPack protector"
    strings:
        $a = "Enigma"
        $b = ".enigma1"
        $c = ".MPRESS1"
        $d = ".aspack"
        $e = ".adata"
    condition:
        any of them
}

rule stealer_browser_paths {
    meta:
        severity = "high"
        category = "stealer"
        desc = "Access to browser credentials"
    strings:
        $a = "\\User Data\\Default\\Login Data" nocase
        $b = "\\Login Data For Account" nocase
        $c = "encrypted_key" nocase
        $d = "\\Network\\Cookies" nocase
        $e = "moz_cookies" nocase
    condition:
        2 of them
}

rule stealer_wallets {
    meta:
        severity = "high"
        category = "stealer"
        desc = "Access to cryptocurrency wallets"
    strings:
        $a = "wallet.dat" nocase
        $b = "\\Electrum\\wallets" nocase
        $c = "\\Exodus\\exodus.wallet" nocase
        $d = "Ethereum\\keystore" nocase
        $e = "MetaMask" nocase
    condition:
        2 of them
}

rule stealer_telegram_exfil {
    meta:
        severity = "high"
        category = "stealer"
        desc = "Exfiltration via Telegram bot"
    strings:
        $a = "api.telegram.org/bot" nocase
        $b = "sendDocument" nocase
        $c = "sendMessage?chat_id" nocase
    condition:
        $a and 1 of ($b, $c)
}

rule inject_process_hollowing {
    meta:
        severity = "high"
        category = "injection"
        desc = "Typical injection / process hollowing APIs"
    strings:
        $a = "NtUnmapViewOfSection"
        $b = "ZwUnmapViewOfSection"
        $c = "SetThreadContext"
        $d = "WriteProcessMemory"
        $e = "NtWriteVirtualMemory"
        $f = "QueueUserAPC"
    condition:
        3 of them
}

rule script_powershell_cradle {
    meta:
        severity = "high"
        category = "dropper"
        desc = "Obfuscated PowerShell / download and execute"
    strings:
        $a = "FromBase64String" nocase
        $b = "-EncodedCommand" nocase
        $c = "IEX(New-Object" nocase
        $d = "DownloadString" nocase
        $e = "-WindowStyle Hidden" nocase
        $f = "Invoke-Expression" nocase
    condition:
        2 of them
}

rule script_lolbin_abuse {
    meta:
        severity = "medium"
        category = "dropper"
        desc = "Abuse of legitimate binaries (LOLBins)"
    strings:
        $a = "certutil -urlcache" nocase
        $b = "certutil -decode" nocase
        $c = "bitsadmin /transfer" nocase
        $d = "mshta http" nocase
        $e = "regsvr32 /s /u /i:" nocase
    condition:
        any of them
}

rule anti_analysis_sandbox {
    meta:
        severity = "medium"
        category = "evasion"
        desc = "Virtual machine / sandbox detection"
    strings:
        $a = "VBoxGuest" nocase
        $b = "VBoxService" nocase
        $c = "vmware" nocase
        $d = "SbieDll.dll" nocase
        $e = "vboxtray" nocase
        $f = "\\\\.\\VBoxMiniRdrDN" nocase
    condition:
        2 of them
}

rule anti_debug_checks {
    meta:
        severity = "low"
        category = "evasion"
        desc = "Anti-debug checks"
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "NtQueryInformationProcess"
        $d = "OutputDebugString"
    condition:
        3 of them
}

rule persistence_registry_run {
    meta:
        severity = "medium"
        category = "persistence"
        desc = "Registry / scheduled-task persistence"
    strings:
        $a = "\\CurrentVersion\\Run" nocase
        $b = "schtasks /create" nocase
        $c = "\\Start Menu\\Programs\\Startup" nocase
        $d = "New-ScheduledTask" nocase
    condition:
        any of them
}

rule ransomware_indicators {
    meta:
        severity = "critical"
        category = "ransomware"
        desc = "Ransomware indicators"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wbadmin delete catalog" nocase
        $c = "bcdedit /set {default} recoveryenabled no" nocase
        $d = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $e = ".onion" nocase
    condition:
        ($a or $b or $c) or ($d and $e)
}

rule crack_steam_emulator {
    meta:
        severity = "info"
        category = "crack"
        desc = "Steam emulator (common crack, not malware)"
    strings:
        $emu1 = "steam_emu.ini" nocase
        $emu2 = "Goldberg" nocase
        $emu3 = "SmartSteamEmu" nocase
        $emu4 = "ALI213" nocase
        $emu5 = "valve_steamworks_emu" nocase
        $if1 = "SteamClient017" nocase
        $if2 = "STEAMAPPS_INTERFACE_VERSION" nocase
    condition:
        any of ($emu*) and any of ($if*)
}
