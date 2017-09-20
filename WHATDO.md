# PookiePack Detailed Description

## What does PookiePack do?

Creates a restore point so the user can roll back.

Configure explorer.exe properly: 
* Enables hidden files, always shows file extension, etc
* Configure default launch options for dangerous file types to open in sublime, N++, or notepad.exe

Do everything we can against responder with good network settings: 
* Turns off MDNS, LLMNR, WPAD, IPV6, BROWSER service, NETBIOS, UPNP, SMBV1/2, enables SMBv3 signing

Do everything we can for mimikatz:
* Configures hardened EMET settings for most applications in the microsoft guidelines 
* Prevent logon from going to wdigest and harden LSASS to prevent cleartext mimikatz returns

Do what we can against provider insight:
* Historically I use microsoft or google DNS, this configures all local net adapters to openDNS.
* This is also super handy for blocking malware domains and delegating both TI and processing power
* Disables Windows 10 telemetry and Microsoft BS

Log everything for when grandma is popped:
* CIS-compliant logging standards which overlaps well with every other framework I have seen.
* Also sysmon service configured with @SwiftonSecurity profile
* Powershell transcript, and scriptblock logginh

Control software under normal operation:
* Locally baselined Software Restriction Policy and desktop shortcuts to manage
* Block old script interpreters both in registry and in SRP while it is on
* This effectively breaks any loader chain for ransomware variant malware
* Disables a bunch of unecessary services including powershellv2 to prevent those rel1k downgrade attacks

SRP Operation:
* Turn off by running the srp-off shortcut
* Make system changes, install software, try an untrusted app if you want
* Turn on by running the srp-on shortcut
* If a new application doesn't launch properly, re-baseline the system with srp-set


Most settings are applied and removed via a 'set' and 'clear' function respectively. These functions are called in the install() and remove() functions in get-pp.ps1. If you have problems with anything in particular the best way to troubleshoot is to remove pookiepack entirely, comment out the setting in install() with '#' and try installing again. If you have problems with the software restriction policy it can be skipped by commenting ~line 77 which calls srp.ps1 to set the baseline SRP and line ~86 which removes these settings. 
