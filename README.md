# Welcome to PookiePack!!!

PookiePack is a set of powershell configuration scripts configure a Windows10 system with reasonably secure defaults.

## To install, please clone repo or download and extract the zip archive.

1. press windows key
2. type 'powershell.exe' > right-click, select 'Run as Administrator'
3. cd to the directory you extracted the files to (e.g. 'cd C:\pp-master')
4. type 'set-executionpolicy unrestricted' in the prompt and hit enter enter 'A' afterwards
5. type '.\get-pp.ps1 -install' and hit enter (or -remove to remove)
6. SIT BACK!
7. type 'restart-computer' in the powershell prompt, or reboot via other means

If you decide PookiePack is not the protection profile for you, you can uninstall buy running 'get-pp.ps1 -remove' from a privileged prompt.

PookiePack currently leverages the following tools:

1. Malware Archaeology configuration scripts for logging:
    * https://www.malwarearchaeology.com/logging/
    * These guys make windows logging easy, kudos to them open-sourcing quality resources for windows logging compliance. 

2. Blackbird to disable windows 10 telemetry, block ad domains, etc:
      * http://www.getblackbird.net/
      * Really solid utility, I highly recommend reading the documentation if you need to perform a manual removal or tweak. 
      * 'blackbird.exe -r' to remove all settings applied. 

3. Microsoft EMET 5.5:
      * https://www.microsoft.com/en-us/download/details.aspx?id=50766
      * Nothing beats a good EMET profile for exploit mitigation, Pookie applies a custom baseline he uses regularly.

4. Sysinternals Suite:
      * https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx
      * https://github.com/SwiftOnSecurity/sysmon-config is applied as the baseline, Pookie looks forward to future enhancements.

5. Lots of guidance applied and considered from http://hardenwindows10forsecurity.com/index.html http://adsecurity.org/?p=3299 https://iwrconsultancy.co.uk/softwarepolicy
