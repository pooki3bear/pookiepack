################################################
# General Download, install, configure modules
################################################
$wd = $SCRIPT:MyInvocation.MyCommand.path | Split-Path -Parent

function new-restore(){
    enable-computerrestore -drive C:\
    checkpoint-computer -description "pre-pookiepack"
}

function clear-psv2{
    Enable-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2 -Online | Out-Null
    Write-Host "powershellv2:" (get-psv2).State.tostring()
}

function set-odns{
    #Enumerates all network adapters and sets Opendns as resolver
    (Get-NetAdapter).ifIndex | % {
    try{
        $odns = "208.67.222.222","208.67.220.220"
        Set-DnsClientServerAddress -InterfaceIndex $_ -ServerAddresses $odns -Validate -ErrorAction SilentlyContinue
    }

    catch{
        $Error[0]
    }
    finally{}
    }
}

function clear-odns{
    (Get-NetAdapter).ifIndex | % {
    try{
        $gdns = "8.8.8.8","8.8.4.4"
        Set-DnsClientServerAddress -InterfaceIndex $_ -ServerAddresses $gdns -Validate -ErrorAction SilentlyContinue
    }
    catch{
        $Error[0]
    }
    finally{}
    }
}

function set-network(){
    try
    {
        reg add HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters /t REG_DWORD /d 0xff /v DisabledComponents /f
        reg add HKLM\Software\Microsoft\DirectplayNATHelp\DPNHUPnP /t REG_DWORD /d 2 /v UPnPMode /f
        Set-SmbServerConfiguration -EnableSMB2Protocol $False -Force
        Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force
        Set-SmbClientConfiguration -EnableSecuritySignature $true -Force
        Write-debug "successfully applied network settings"
    }
    catch {Write-debug "error applying network settings"}
    finally {}
}

function clear-network(){
    try
    {
        reg delete HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters /v DisabledComponents /f
        reg delete HKLM\Software\Microsoft\DirectplayNATHelp\DPNHUPnP /v UPnPMode /f
        Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force
        Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force
        Set-SmbClientConfiguration -EnableSecuritySignature $False -Force
        Write-debug "successfully removed network reg keys"
    }
    catch {Write-debug "error removing network settings"}
    finally {}	
}

function set-profile(){
$prodir = "$env:windir\system32\WindowsPowerShell\v1.0\profile.ps1"
$pro_settings = '$LogCommandHealthEvent = $true 
$LogCommandLifecycleEvent = $true 
$PSLogScriptBlockExecution = $true
$PSLogScriptBlockExecutionVerbose = $true
Start-transcript -path "C:\Users\$env:username\Documents\PowerShell_transcript.txt" -force -noclobber -append
$transcript.Path
$PSVersionTable.PSVersion'

    if (Test-Path $prodir){
        $profile = gc $prodir
            if ($profile -match 'start-transcript'){
                Write-Debug "looks like transcript is on, exiting"
                return
            }
            else {
                $profile += $pro_settings
                $profile | Set-Content $prodir -Force
            }
    }
    else {
        New-Item -Path $prodir
        $pro_settings | Set-Content $prodir
    }

}

function clear-profile(){
$prodir = "$env:windir\system32\WindowsPowerShell\v1.0\profile.ps1"
    if (Test-Path $prodir){
        Remove-Item $prodir -ErrorAction SilentlyContinue
    }
    else {
        Write-Debug "No profile to remove!"
    }
}

function set-log(){
    set-profile
    #iwr -uri "https://codeload.github.com/SwiftOnSecurity/sysmon-config/zip/master" -OutFile "$wd\tswiz.zip"
	Expand-Archive -path "$wd\tswiz.zip" -DestinationPath "$wd\tswiz" -force
    #iwr "https://download.sysinternals.com/files/Sysmon.zip" -outfile "$wd\Sysmon.zip"
	Expand-Archive -path "$wd\Sysmon.zip" -DestinationPath "$wd\Sysmon" -force
	Copy-Item "$wd\Sysmon\*" "C:\Windows\System32\" -Force
	Start-Process C:\windows\system32\sysmon.exe -ArgumentList "-accepteula -i $wd\tswiz\sysmon-config-master\sysmonconfig-export.xml" -ErrorAction SilentlyContinue
	set-auditpol
}

function clear-log(){
    clear-profile
	Start-Process C:\windows\system32\sysmon.exe -ArgumentList "-accepteula -u" -ErrorAction SilentlyContinue
	write-debug "you can't unconfigure logging stupid, you get this one forever!"
}

function set-bb(){
	iwr http://www.getblackbird.net/download/BlackbirdV6_v0.9.98-x64.zip -OutFile "$wd\BlackbirdV6_v0.9.98-x64.zip"
    expand-archive -path "$wd\BlackbirdV6_v0.9.98-x64.zip" -destinationpath $wd\ -force
	$wshell = New-Object -ComObject wscript.shell;
    $wshell.Run("$wd\blackbird_v0.9.98_64\blackbird.exe -s")
}

function clear-bb(){
	$wshell = New-Object -ComObject wscript.shell;
    $wshell.Run("$wd\blackbird_v0.9.98_64\blackbird.exe -r")
    sleep 3
    $wshell.AppActivate("blackbird")
    $wshell.SendKeys('~')
}

function set-sysinternals(){
    #iwr "https://download.sysinternals.com/files/Autoruns.zip" -outfile "$wd\Autoruns.zip"
	Expand-Archive -path "$wd\Autoruns.zip" -DestinationPath "$wd\Autoruns" -force
    Copy-Item "$wd\Autoruns\*" "C:\Windows\System32\" -Force
    
    #iwr "https://download.sysinternals.com/files/ProcessMonitor.zip" -outfile "$wd\ProcessMonitor.zip"
	Expand-Archive -path "$wd\ProcessMonitor.zip" -DestinationPath "$wd\ProcessMonitor" -force
    Copy-Item "$wd\ProcessMonitor\*" "C:\Windows\System32\" -Force
    
    #iwr "https://download.sysinternals.com/files/ProcessExplorer.zip" -outfile "$wd\ProcessExplorer.zip"
	Expand-Archive -path "$wd\ProcessExplorer.zip" -DestinationPath "$wd\ProcessExplorer" -force
    Copy-Item "$wd\ProcessExplorer\*" "C:\Windows\System32\" -Force
}

function clear-sysinternals() {
    #iwr "https://download.sysinternals.com/files/Autoruns.zip" -outfile "$wd\Autoruns.zip"
	Expand-Archive -path "$wd\Autoruns.zip" -DestinationPath "$wd\Autoruns" -force
    (gci "$wd\Autoruns\").name | %{
    Remove-Item "C:\Windows\System32\$_" -ErrorAction SilentlyContinue
    }
    
    #iwr "https://download.sysinternals.com/files/ProcessMonitor.zip" -outfile "$wd\ProcessMonitor.zip"
	Expand-Archive -path "$wd\ProcessMonitor.zip" -DestinationPath "$wd\ProcessMonitor" -force
    (gci "$wd\ProcessMonitor\").name | %{
    Remove-Item "C:\Windows\System32\$_" -ErrorAction SilentlyContinue
    }

    #iwr "https://download.sysinternals.com/files/ProcessExplorer.zip" -outfile "$wd\ProcessExplorer.zip"
	Expand-Archive -path "$wd\ProcessExplorer.zip" -DestinationPath "$wd\ProcessExplorer" -force
    (gci "$wd\ProcessExplorer\").name | %{
    Remove-Item "C:\Windows\System32\$_" -ErrorAction SilentlyContinue
    }
}

function set-wpad(){
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v "WpadOverride” /f /t REG_DWORD /d "1"
    Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled
}

function clear-wpad(){
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad” /v "WpadOverride" /f
}

function set-compbrows(){
    Stop-Service -Name Browser
    Set-Service -Name Browser -StartupType Disabled
}

function clear-compbrows(){
    Set-Service -Name Browser -StartupType Automatic
    Stop-Service -Name Browser
}

function set-llmnr(){
    reg add ”HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ”EnableMulticast” /f /t REG_DWORD /d “0” 
}

function clear-llmnr(){
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /f /v "EnableMulticast"
}

function set-wdigest(){
    reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\Wdigest\" /v "UseLogonCredential" /f /t REG_DWORD /d "0"
}

function clear-wdigest(){
    reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\Wdigest\" /v "UseLogonCredential" /f /t REG_DWORD /d "1"
}

function set-font(){
    echo 'yes' | reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "MitigationOptions" /t REG_QWORD /d "0x1000000000000" /reg:64
}

function clear-font(){
    echo 'yes' | reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "MitigationOptions" /t REG_QWORD /d "0x2000000000000" /reg:64
}

function set-netbios(){
    #iwr "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b/file/165596/1/NetCease.zip" -OutFile "$wd\netcease.zip" -ErrorAction SilentlyContinue
    Expand-Archive $wd\netcease.zip -DestinationPath $wd\Netcease -Force
    & "$wd\netcease\NetCease.ps1"
}

function clear-netbios(){
    & "$wd\netcease\NetCease.ps1" -revert
}

################################################
# Wscript modules to drive the UI and configure system settings
################################################

$shifttab = "+{TAB}"
$enter = "~"
$tab = "{TAB}"
$right = "{RIGHT}"
$left = "{LEFT}"
$up ="{UP}"
$down = "{DOWN}"

function set-explore(){
    $wshell = New-Object -ComObject wscript.shell;
    $wshell.Run("control folders")
    sleep 1
    $wshell.AppActivate("File Explorer Options")
    $wshell.SendKeys($shifttab+$right+($tab*2)+($down*8)+" "+($down*2)+" "+$enter)
}

function clear-explore(){
    $wshell = New-Object -ComObject wscript.shell;
    $wshell.Run("control folders")
    sleep 1
    $wshell.AppActivate("File Explorer Options")
    $wshell.SendKeys($shifttab+$right+($tab*3)+$enter+$tab+$enter)
}

################################################
# EMET toggle module
################################################

function set-emet{
Param(
  [system.array]$hostlist,
  [ValidateSet('install','uninstall')]
  [string]$command
)
$appset = @{
"*\Internet Explorer\iexplore.exe"                 = "+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2"
"*\Windows NT\Accessories\wordpad.exe"             = ""
"*\OFFICE1*\OUTLOOK.exe"                           = ""
"*\OFFICE1*\WINWORD.exe"                           = "-SimExecFlow +ASR asr_modules:flash*.ocx" 
"*\OFFICE1*\EXCEL.exe"                             = "+ASR asr_modules:flash*.ocx" 
"*\OFFICE1*\POWERPNT.exe"                          = "+ASR asr_modules:flash*.ocx"
"*\OFFICE1*\MSACCESS.exe"                          = ""
"*\OFFICE1*\MSPUB.exe"                             = ""
"*\OFFICE1*\INFOPATH.exe"                          = ""
"*\OFFICE1*\VISIO.exe"                             = ""
"*\OFFICE1*\VPREVIEW.exe"                          = ""
"*\OFFICE1*\LYNC.exe"                              = ""
"*\OFFICE1*\PPTVIEW.exe"                           = ""
"*\OFFICE1*\OIS.exe"                               = ""
"*\Adobe\*\Reader\AcroRd32.exe"                    = "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api"
"*\Adobe\Acrobat*\Acrobat\Acrobat.exe"             = "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api"
"*\Java\jre*\bin\java.exe"                         = "-HeapSpray"
"*\Java\jre*\bin\javaw.exe"                        = "-HeapSpray" 
"*\Java\jre*\bin\javaws.exe"                       = "-HeapSpray"
"*\Windows Media Player\wmplayer.exe"              = "-EAF -MandatoryASLR"
"*\Skype\Phone\Skype.exe"                          = "-EAF"
"*\Microsoft Lync\communicator.exe"                = ""
"*\Windows Live\Photo Gallery\WLXPhotoGallery.exe" = ""
"*\Windows Live\Mail\wlmail.exe"                   = ""
"*\Windows Live\Writer\WindowsLiveWriter.exe"      = ""
"*\SkyDrive\SkyDrive.exe"                          = ""
"*\Google\Chrome\Application\chrome.exe"           = "-eaf+ eaf_modules:chrome_child.dll"
"*\Google\Google Talk\googletalk.exe"              = "-DEP" 
"*\Mozilla Firefox\firefox.exe"                    = "+EAF+ eaf_modules:mozjs.dll;xul.dll"
"*\Mozilla Firefox\plugin-container.exe"           = ""
"*\Mozilla Thunderbird\thunderbird.exe"            = ""
"*\Mozilla Thunderbird\plugin-container.exe"       = ""
"*\Adobe\Adobe Photoshop CS*\Photoshop.exe"        = ""
"*\Winamp\winamp.exe"                              = ""
"*\Opera\opera.exe"                                = ""
"*\Opera\*\opera.exe"                              = ""
"*\WinRAR\winrar.exe"                              = ""
"*\WinRAR\rar.exe"                                 = ""
"*\WinRAR\unrar.exe"                               = ""
"*\WinZip\winzip32.exe"                            = ""
"*\WinZip\winzip64.exe"                            = ""
"*\VideoLAN\VLC\vlc.exe"                           = ""
"*\Real\RealPlayer\realconverter.exe"              = ""
"*\Real\RealPlayer\realplay.exe"                   = ""
"*\mIRC\mirc.exe"                                  = ""
"*\7-Zip\7z.exe"                                   = "-EAF"
"*\7-Zip\7zG.exe"                                  = "-EAF"
"*\7-Zip\7zFM.exe"                                 = "-EAF"
"*\Safari\Safari.exe"                              = ""
"*\QuickTime\QuickTimePlayer.exe"                  = ""
"*\iTunes\iTunes.exe"                              = ""
"*\Pidgin\pidgin.exe"                              = ""
"*\Foxit Reader\Foxit Reader.exe"                  = ""
}
$sysset = @{
"DEP" = "2"
"ASLR" = "3"
"SEHOP" = "2"
"DeepHooks" = "1"
"AntiDetours" = "1"
"BannedFunctions" = "1"
}
$baseset = @{
"ReportingSettings" = "6"
"AntiDetours" = "1"
"DeepHooks" = "1"
"BannedFunctions" = "1"
"ExploitAction" = "1"
"EMET_CE" = "iexplore.exe"
}
$appsettings = New-Object psobject -Property $appset
$syssettings = New-Object psobject -Property $sysset
$basesettings = New-Object psobject -Property $baseset
$fontset = New-Object psobject -Property @{"MitigationOptions" = "1000000000000"}
$fontset | Add-Member -Name "Type" -Value "REG_QWORD" -MemberType NoteProperty

$install = {
$invokeargs = @"
    /i C:\tools\pookiepack\EMET_Setup.msi /qn
"@
$proc = Get-Process | Where-Object {$_.ProcessName -match "EMET_Service"}
if ($proc)
{
Write-Host "EMET already running on $env:COMPUTERNAME"
}
else {
    if(!(Test-Path C:\temp))
    {
    New-Item -Path C:\temp -ItemType Directory
    }
    #$wc = New-Object System.Net.WebClient
    #$wc.DownloadFile("https://download.microsoft.com/download/8/E/E/8EEFD9FC-46B1-4A8B-9B5D-13B4365F8CA0/EMET%20Setup.msi","C:\temp\EMET_Setup.msi")
    Start-Process -FilePath msiexec -Wait -ArgumentList $invokeargs
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\EMET\Defaults -Type Directory -ErrorAction SilentlyContinue
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\EMET\SysSettings -Type Directory -ErrorAction SilentlyContinue
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\EMET\AppSettings -Type Directory -ErrorAction SilentlyContinue
    New-Item -Path "HKLM:\CurrentControlSet\Control\Session Manager\Kernel" -Type Directory -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\"  -name "MitigationOptions" -Value ("281474976710656") -type "QWord" -Force
    $args[0] | set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\EMET\Defaults" -Force
    $args[1] | set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\EMET\SysSettings" -Force
    $args[2] | set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\EMET\AppSettings" -Force
    $args[3] | Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\EMET" -Force    
    $proc = Get-Process | Where-Object {$_.ProcessName -match "EMET_Service"}
    if (!$proc)
    {Start-Service EMET_Service}
    Get-Process | Where-Object {$_.ProcessName -match "EMET_Service"}
    #Remove-Item -Path C:\temp\EMET_Setup.msi
}
}
$uninstall = {
$instguid = (Get-WmiObject Win32_Product | Where-Object -Property Name -Match "EMET").IdentifyingNumber
$arglist = "/x $instguid /qn"
Get-Process | Where-Object {$_.ProcessName -match "EMET"} | Stop-Process -Force
Start-Process -FilePath msiexec -ArgumentList $arglist -Wait
Get-Process | Where-Object {$_.ProcessName -match "EMET"}
}

if ($hostlist){
    switch ($command){
    'install' {
    foreach ($server in $hostlist) {
    Invoke-Command -ScriptBlock $install -ComputerName $server -ArgumentList $appsettings,$syssettings,$appsettings,$basesettings,$fontset
    }
    }
    'uninstall' {
    foreach ($server in $hostlist) {
    Invoke-Command -ScriptBlock $uninstall -ComputerName $server
    }
    }
    Default {write-host "plz give command"}
}
}
else {
    switch ($command){
    'install' {
   Invoke-Command -ScriptBlock $install -ArgumentList $appsettings,$syssettings,$appsettings,$basesettings,$fontset
    }
    'uninstall' {
    Invoke-Command -ScriptBlock $uninstall
    }
    
    Default {write-host "plz give command"}
}
}
}

function set-ftype(){
$notepad = "c:\windows\system32\notepad.exe"
$sublime = "C:\Program Files\Sublime Text 3\sublime_text.exe"
$npp = "C:\Program Files (x86)\Notepad++\notepad++.exe"
if (Test-Path $sublime){
    $program = $sublime
}
elseif (Test-Path $npp){
    $program = $npp
}
elseif (Test-Path $notepad){
    $program = $notepad
}

$definition = @"
batfile="$program" "%1"
cmdfile="$program" "%1"
comfile="$program" "%1"
cplfile="$program" "%1"
htafile="$program" "%1"
inffile="$program" "%1"
JobObject="$program" "%1"
JSEFile="$program" "%1"
JSFile="$program" "%1"
Microsoft.PowerShellConsole.1="$program" "%1"
Microsoft.PowerShellData.1="$program" "%1"
Microsoft.PowerShellModule.1="$program" "%1"
Microsoft.PowerShellScript.1="$program" "%1"
Microsoft.PowerShellXMLData.1="$program" "%1"
regfile="$program" "%1"
scrfile="$program" "%1"
scriptletfile="$program" "%1"
SHCmdFile="$program" "%1"
VBEFile="$program" "%1"
VBSFile="$program" "%1"
VisualStudio.vb.14.0="$program" "%1"
Windows.CompositeFont="$program" "%1"
WSFFile="$program" "%1"
WSHFile="$program" "%1"
"@ -split "\n"

$definition | % {
    $cmd = "ftype $_"
    cmd /c $cmd | Out-Null
}
}

function set-auditpol(){
    reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v "ProcessCreationIncludeCmdLine_Enabled" /f /t REG_DWORD /d 1
    Reg add "hklm\System\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /f /t REG_DWORD /d 1 

    wevtutil sl Security /ms:540100100
    wevtutil sl Application /ms:540100100
    wevtutil sl Setup /ms:256000100
    wevtutil sl System /ms:256000100
    wevtutil sl "Windows Powershell" /ms:256000100
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:540100100

#######################################################################
# Account Logon
#######################################################################

    Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    Auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable
    Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable
    Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

#######################################################################
# ACCOUNT MANAGEMENT
####################################################################### 
    # Sets - the entire category 
    Auditpol /set /category:"Account Management" /success:enable /failure:enable
    # but just in case...
    Auditpol /set /subcategory:"Application Group Management" /success:disable /failure:disable
    Auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
    Auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
    Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    Auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
    Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

#######################################################################
# Detailed Tracking
####################################################################### 

    Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
    Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
    Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

#######################################################################
# DS Access
####################################################################### 

    Auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable
    Auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable
    Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    Auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable

#######################################################################
# Logon/Logoff
####################################################################### 

    Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:disable
    Auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable
    Auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable
    Auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable
    Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
    Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
    Auditpol /set /subcategory:"Network Policy Server" /success:disable /failure:disable
    Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
    Auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable

#######################################################################
# Object Access
#######################################################################

    Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
    Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    Auditpol /set /subcategory:"Detailed File Share" /success:enable

    # Will generate a lot of events if Files and Reg keys are audited so only audit locations that are not noisy

    Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    Auditpol /set /subcategory:"File System" /success:enable /failure:enable

    <#
     WARNING:  This next item is a VERY noisy items and requires the Windows Firewall to be in at least an ALLOW ALLOW configuration in Group Ploicy
    Auditpol /set /subcategory:"Filtering Platform Connection" /success:disabled /failure:disable

    Auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
    Auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
    Auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
    Auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
    Auditpol /set /subcategory:"Registry" /success:enable
    Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
    #>

#######################################################################
# Policy Change
####################################################################### 

    Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
    Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
    Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
    Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
    Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable /failure:disable
    Auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:disable

#######################################################################
# Privilege Use
####################################################################### 

    Auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable
    Auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable
    Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

#######################################################################
# SYSTEM
####################################################################### 

    Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
    Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
    Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
    Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

}

#######################################################################
# Disables Win10 Telemetry
####################################################################### 

function set-teloff(){

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

# Disable some of the "new" features of Windows 10, such as forcibly installing apps you don't want, and the new annoying animation for first time login.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'CloudContent' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -PropertyType DWord -Value '0' -Force

# Set some commonly changed settings for the current user. The interesting one here is "NoTileApplicationNotification" which disables a bunch of start menu tiles.
New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\' -Name 'PushNotifications' -erroraction silentlycontinue
New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoTileApplicationNotification' -PropertyType DWord -Value '1' -Force
New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\' -Name 'CabinetState' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' -Name 'FullPath' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSyncProviderNotifications' -PropertyType DWord -Value '0' -Force

# Remove all Windows 10 apps, including Windows Store. You may not want this, but I don't ever use any of the apps or the start menu tiles.
# This makes Windows 10 similar to Windows 7. Don't forget to unpin all the tiles after installation to trim down the start menu!
Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
#Get-AppxPackage | Remove-AppxPackage

# Disable Cortana, and disable any kind of web search or location settings.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -PropertyType DWord -Value '0' -Force

# Remove OneDrive, and stop it from showing in Explorer side menu.
#C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall
#Remove-Item -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse
#Remove-Item -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse

# Disable data collection and telemetry settings.
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -PropertyType String -Value 'Off' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -PropertyType DWord -Value '0' -Force

# Disable Windows Defender submission of samples and reporting.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\' -Name 'Spynet' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SubmitSamplesConsent' -PropertyType DWord -Value '2' -Force

# Ensure updates are downloaded from Microsoft instead of other computers on the internet.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'DeliveryOptimization' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'SystemSettingsDownloadMode' -PropertyType DWord -Value '0' -Force
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\' -Name 'Config' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -PropertyType DWord -Value '0' -Force

Write-Host 'Disabling services...'
$services = @(
    # See https://virtualfeller.com/2017/04/25/optimize-vdi-windows-10-services-original-anniversary-and-creator-updates/

    # CDPSvc doesn't seem to do anything useful, that I found. See note on CDPUserSvc further down the script
    'CDPSvc',

    # Connected User Experiences and Telemetry
    'DiagTrack',

    # Data Usage service
    'DusmSvc',

    # Peer-to-peer updates
    'DoSvc',

    # AllJoyn Router Service (IoT)
    'AJRouter',

    # SSDP Discovery (UPnP)
    'SSDPSRV',
    'upnphost',

    # Superfetch
    'SysMain',

    # http://www.csoonline.com/article/3106076/data-protection/disable-wpad-now-or-have-your-accounts-and-private-data-compromised.html
    'iphlpsvc',
    'WinHttpAutoProxySvc',

    # Black Viper 'Safe for DESKTOP' services.
    # See http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/
    'tzautoupdate',
    'AppVClient',
    'RemoteRegistry',
    'RemoteAccess',
    'shpamsvc',
    'SCardSvr',
    'UevAgentService',
    'ALG',
    'PeerDistSvc',
    'NfsClnt',
    'dmwappushservice',
    'MapsBroker',
    'lfsvc',
#    'HvHost',
    'vmickvpexchange',
    'vmicguestinterface',
    'vmicshutdown',
    'vmicheartbeat',
    'vmicvmsession',
    'vmicrdv',
    'vmictimesync',
    'vmicvss',
    'irmon',
    'SharedAccess',
    'MSiSCSI',
    'SmsRouter',
    'CscService',
    'SEMgrSvc',
    'PhoneSvc',
    'RpcLocator',
    'RetailDemo',
    'SensorDataService',
    'SensrSvc',
    'SensorService',
    'ScDeviceEnum',
    'SCPolicySvc',
    'SNMPTRAP',
    'TabletInputService',
    'WFDSConSvc',
    'FrameServer',
    'wisvc',
    'icssvc',
#    'WinRM',
    'WwanSvc',
    'XblAuthManager',
    'XblGameSave',
    'XboxNetApiSvc'
)
foreach ($service in $services) {
    Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# CDPUserSvc is a mysterious service that just seems to throws errors in the event viewer. I haven't seen any problems with it disabled.
# See https://social.technet.microsoft.com/Forums/en-US/c165a54a-4a69-441c-94a7-b5712b54385d/what-is-the-cdpusersvc-for-?forum=win10itprogeneral
# Note that the related service CDPSvc is also disabled in the above services loop. CDPUserSvc can't be disabled by Set-Service, due to a random
# hash after the service name, but disabling via the registry is perfectly fine.
Write-Host 'Disabling CDPUserSvc...'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' -Name 'Start' -Value '4'

Write-Host 'Disabling hibernate...'
powercfg -h off

# Disables all of the known enabled-by-default optional features. There are some particulary bad defaults like SMB1. Sigh.
Write-Host 'Disabling optional features...'
$features = @(
    'MediaPlayback',
    #'SMB1Protocol',
    'Xps-Foundation-Xps-Viewer',
    'WorkFolders-Client',
    #'WCF-Services45',
    'NetFx4-AdvSrvs',
    'Printing-Foundation-Features',
    'Printing-PrintToPDFServices-Features',
    'Printing-XPSServices-Features',
    'MSRDC-Infrastructure',
    'MicrosoftWindowsPowerShellV2',
    'MicrosoftWindowsPowerShellV2Root',
    'Internet-Explorer-Optional-amd64'
)
foreach ($feature in $features) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
}
}

function set-telon(){

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

# Disable some of the "new" features of Windows 10, such as forcibly installing apps you don't want, and the new annoying animation for first time login.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'CloudContent' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -PropertyType DWord -Value '1' -Force

# Set some commonly changed settings for the current user. The interesting one here is "NoTileApplicationNotification" which disables a bunch of start menu tiles.
New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\' -Name 'PushNotifications' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoTileApplicationNotification' -PropertyType DWord -Value '0' -Force
New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\' -Name 'CabinetState' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' -Name 'FullPath' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSyncProviderNotifications' -PropertyType DWord -Value '1' -Force

# Remove all Windows 10 apps, including Windows Store. You may not want this, but I don't ever use any of the apps or the start menu tiles.
# This makes Windows 10 similar to Windows 7. Don't forget to unpin all the tiles after installation to trim down the start menu!
Get-AppxProvisionedPackage -Online | Add-AppxProvisionedPackage -Online
#Get-AppxPackage | Remove-AppxPackage

# Disable Cortana, and disable any kind of web search or location settings.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -PropertyType DWord -Value '1' -Force

# Remove OneDrive, and stop it from showing in Explorer side menu.
#C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall
#Remove-Item -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse
#Remove-Item -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse

# Disable data collection and telemetry settings.
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -PropertyType String -Value 'On' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -PropertyType DWord -Value '1' -Force

# Disable Windows Defender submission of samples and reporting.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\' -Name 'Spynet' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SubmitSamplesConsent' -PropertyType DWord -Value '2' -Force

# Ensure updates are downloaded from Microsoft instead of other computers on the internet.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'DeliveryOptimization' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -PropertyType DWord -Value '1' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'SystemSettingsDownloadMode' -PropertyType DWord -Value '1' -Force
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\' -Name 'Config' -ErrorAction SilentlyContinue
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -PropertyType DWord -Value '1' -Force

Write-Host 'Disabling services...'
$services = @(
    # See https://virtualfeller.com/2017/04/25/optimize-vdi-windows-10-services-original-anniversary-and-creator-updates/

    # CDPSvc doesn't seem to do anything useful, that I found. See note on CDPUserSvc further down the script
    'CDPSvc',

    # Connected User Experiences and Telemetry
    'DiagTrack',

    # Data Usage service
    'DusmSvc',

    # Peer-to-peer updates
    'DoSvc',

    # AllJoyn Router Service (IoT)
    'AJRouter',

    # SSDP Discovery (UPnP)
    'SSDPSRV',
    'upnphost',

    # Superfetch
    'SysMain',

    # http://www.csoonline.com/article/3106076/data-protection/disable-wpad-now-or-have-your-accounts-and-private-data-compromised.html
    'iphlpsvc',
    'WinHttpAutoProxySvc',

    # Black Viper 'Safe for DESKTOP' services.
    # See http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/
    'tzautoupdate',
    'AppVClient',
    'RemoteRegistry',
    'RemoteAccess',
    'shpamsvc',
    'SCardSvr',
    'UevAgentService',
    'ALG',
    'PeerDistSvc',
    'NfsClnt',
    'dmwappushservice',
    'MapsBroker',
    'lfsvc',
#    'HvHost',
    'vmickvpexchange',
    'vmicguestinterface',
    'vmicshutdown',
    'vmicheartbeat',
    'vmicvmsession',
    'vmicrdv',
    'vmictimesync',
    'vmicvss',
    'irmon',
    'SharedAccess',
    'MSiSCSI',
    'SmsRouter',
    'CscService',
    'SEMgrSvc',
    'PhoneSvc',
    'RpcLocator',
    'RetailDemo',
    'SensorDataService',
    'SensrSvc',
    'SensorService',
    'ScDeviceEnum',
    'SCPolicySvc',
    'SNMPTRAP',
    'TabletInputService',
    'WFDSConSvc',
    'FrameServer',
    'wisvc',
    'icssvc',
#    'WinRM',
    'WwanSvc',
    'XblAuthManager',
    'XblGameSave',
    'XboxNetApiSvc'
)
foreach ($service in $services) {
    Set-Service $service -StartupType Automatic -ErrorAction SilentlyContinue
}

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' -Name 'Start' -Value '2'

powercfg -h off

# Disables all of the known enabled-by-default optional features. There are some particulary bad defaults like SMB1. Sigh.
Write-Host 'Disabling optional features...'
$features = @(
    'MediaPlayback',
    #'SMB1Protocol',
    'Xps-Foundation-Xps-Viewer',
    'WorkFolders-Client',
    'WCF-Services45',
    'NetFx4-AdvSrvs',
    'Printing-Foundation-Features',
    'Printing-PrintToPDFServices-Features',
    'Printing-XPSServices-Features',
    'MSRDC-Infrastructure',
    'MicrosoftWindowsPowerShellV2',
    'MicrosoftWindowsPowerShellV2Root',
    'Internet-Explorer-Optional-amd64'
)
foreach ($feature in $features) {
    Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
}
}
