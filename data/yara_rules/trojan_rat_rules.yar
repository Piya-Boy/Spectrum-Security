rule Trojan_Keylogger_Behavior
{
    meta:
        family = "Keylogger"
        severity = "High"
        description = "Keyboard capture APIs combined with persistence or networking"
    strings:
        $k1 = "GetAsyncKeyState" ascii wide nocase
        $k2 = "GetKeyboardState" ascii wide nocase
        $k3 = "SetWindowsHookEx" ascii wide nocase
        $p1 = "CurrentVersion\\Run" ascii wide nocase
        $p2 = "Startup" ascii wide nocase
        $n1 = "InternetOpen" ascii wide nocase
        $n2 = "WinHttpOpen" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($k*) and 1 of ($p*, $n*)
}

rule Trojan_RAT_Remote_Control
{
    meta:
        family = "RAT"
        severity = "High"
        description = "Remote-control, injection, or command-execution APIs"
    strings:
        $i1 = "CreateRemoteThread" ascii wide nocase
        $i2 = "WriteProcessMemory" ascii wide nocase
        $i3 = "OpenProcess" ascii wide nocase
        $c1 = "cmd.exe" ascii wide nocase
        $c2 = "powershell" ascii wide nocase
        $n1 = "WSAStartup" ascii wide nocase
        $n2 = "InternetConnect" ascii wide nocase
        $n3 = "WinHttpConnect" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($i*) and 1 of ($n*, $c*) or 2 of ($n*) and 1 of ($c*))
}

rule Trojan_Credential_Stealer_Browser
{
    meta:
        family = "Stealer"
        severity = "High"
        description = "Browser credential storage paths combined with exfiltration APIs"
    strings:
        $b1 = "Login Data" ascii wide nocase
        $b2 = "Local State" ascii wide nocase
        $b3 = "Cookies" ascii wide nocase
        $b4 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $b5 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $n1 = "HttpSendRequest" ascii wide nocase
        $n2 = "InternetReadFile" ascii wide nocase
        $n3 = "WinHttpSendRequest" ascii wide nocase
        $x1 = "CryptUnprotectData" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($b*) and 1 of ($n*, $x1)
}

rule Trojan_Persistence_RunKey
{
    meta:
        family = "Backdoor"
        severity = "Medium"
        description = "Startup persistence strings combined with stealth or network behavior"
    strings:
        $p1 = "CurrentVersion\\Run" ascii wide nocase
        $p2 = "RegSetValue" ascii wide nocase
        $p3 = "RegCreateKey" ascii wide nocase
        $p4 = "schtasks" ascii wide nocase
        $s1 = "ShowWindow" ascii wide nocase
        $s2 = "SW_HIDE" ascii wide nocase
        $n1 = "InternetOpen" ascii wide nocase
        $n2 = "WinHttpOpen" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($p*) and 1 of ($s*, $n*)
}

rule Trojan_AntiAnalysis_VM_Debugger
{
    meta:
        family = "Suspicious Trojan"
        severity = "Medium"
        description = "Anti-debug or VM checks combined with other suspicious behavior"
    strings:
        $a1 = "IsDebuggerPresent" ascii wide nocase
        $a2 = "CheckRemoteDebuggerPresent" ascii wide nocase
        $a3 = "VirtualBox" ascii wide nocase
        $a4 = "VMware" ascii wide nocase
        $a5 = "VBoxService" ascii wide nocase
        $n1 = "InternetOpen" ascii wide nocase
        $i1 = "VirtualAlloc" ascii wide nocase
        $i2 = "VirtualProtect" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 1 of ($n*, $i*)
}
