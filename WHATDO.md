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


PookiePack currently leverages the following 3rd party tools:

1. Microsoft EMET 5.5: https://www.microsoft.com/en-us/download/details.aspx?id=50766
2. Sysinternals Suite:https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx - https://github.com/SwiftOnSecurity/sysmon-config is applied as the baseline.

Lots of guidance considered and applied from:

http://hardenwindows10forsecurity.com/index.html 

http://adsecurity.org/?p=3299 

https://iwrconsultancy.co.uk/softwarepolicy

https://www.malwarearchaeology.com/logging/

https://gist.github.com/halkyon/b73fb75e61c37b7ba5f65bb6f3979f00