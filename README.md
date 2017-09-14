# PookiePack

PookiePack is a set of powershell configuration scripts configure a Windows10 system with reasonably secure defaults.

## To install, please clone repo or download and extract the zip archive.

1. press windows key
2. type 'powershell.exe' > right-click, select 'Run as Administrator'
3. cd to the directory you extracted the files to (e.g. 'cd C:\pp-master')
4. type 'set-executionpolicy unrestricted' in the prompt and hit enter enter 'A' afterwards
5. type '.\get-pp.ps1 -install' and hit enter (or -remove to remove)
6. SIT BACK!
7. type 'restart-computer' in the powershell prompt, or reboot via other means

After the install, you should have 3 new desktop icons that control the local software policy on the machine. To install new software or drivers, toggle it off with the 'srp-off' shortcut. After you make changes you can turn it back on with 'srp-on'. If you have any issues running new programs under the enforced policy, try re-baselining your system with 'srp-set'.

If you decide PookiePack is not the protection profile for you, you can uninstall buy running 'get-pp.ps1 -remove' from a privileged prompt.

PookiePack currently leverages the following 3rd party tools:

1. Microsoft EMET 5.5: https://www.microsoft.com/en-us/download/details.aspx?id=50766
2. Sysinternals Suite:https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx - https://github.com/SwiftOnSecurity/sysmon-config is applied as the baseline.

Lots of guidance considered and applied from:

http://hardenwindows10forsecurity.com/index.html 

http://adsecurity.org/?p=3299 

https://iwrconsultancy.co.uk/softwarepolicy

https://www.malwarearchaeology.com/logging/

https://gist.github.com/halkyon/b73fb75e61c37b7ba5f65bb6f3979f00
