<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
Param
(
    # Param1 help description
    [Parameter(Mandatory=$true,
    Position=0)]
    [ValidateSet("set","unset","tog-on", "tog-off")]
    $arg
)

$scriploc = $SCRIPT:MyInvocation.MyCommand.path
$wd = $SCRIPT:MyInvocation.MyCommand.path | Split-Path -Parent

$osarch = if ([System.IntPtr]::Size -eq 4) { "32" } else { "64" }

$global_whitelist = "C:\Program Files (x86)",
"C:\Program Files",
"C:\Windows",
"C:\Windows\SysWOW64",
"C:\Windows\*.exe",
"C:\Windows\SysWOW64\*.exe",
"C:\boot\",
$wd

$global_blacklist = "C:\Windows\debug\WIA",
"C:\Windows\Registration\CRMLog",
"C:\Windows\System32\catroot2\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
"C:\Windows\System32\com\dmp",
"C:\Windows\System32\FxsTmp",
"C:\Windows\System32\spool\PRINTERS",
"C:\Windows\System32\spool\drivers\color",
"C:\Windows\System32\Tasks",
"C:\Windows\Tasks",
"C:\Windows\Temp",
"C:\Windows\tracing",
"C:\Windows\SysWOW64\com\dmp",
"C:\Windows\SysWOW64\FxsTmp",
"C:\Windows\SysWOW64\Tasks",
"mshta.exe",
"cscript.exe",
"wscript.exe",
"iexplore.exe"

function get-softpath(){
    $pathlist = @()
    $ldisk = Get-WmiObject win32_logicaldisk | Where-Object {$_.DriveType -eq ‘3’}
    $ldisk | % {
        $fsmap = (gci ($_.DeviceID + "\") -Force -Recurse -ErrorAction SilentlyContinue).FullName
        #$dllz = $fsmap | Where-Object {$_ -match "\.dll$"} | Where-Object {$_ -notmatch ":\\Windows\\"} | Where-Object {$_ -notmatch "Program Files"}
        $exez = $fsmap | Where-Object {$_ -match "\.exe$"} | Where-Object {$_ -notmatch ":\\Windows\\"} | Where-Object {$_ -notmatch "Program Files"} | Where-Object {$_ -notmatch "Downloads"} | Where-Object {$_ -notmatch "Documents"}
        $exez | % {$pathlist += $_}
        #$dllz | % {$pathlist += $_}
    }
$pathlist
}

function remove-candidate($candidate,$list){
    $list = $list | Select-String -NotMatch ($candidate -replace '\\','\\'-replace '\+','\+' -replace '\$','\$' -replace '\s','\s')
    $list
}

function get-unique($pathz){
    $masterpath = @()
    1..$pathz.Count | foreach {
    if ($pathz){
    $candidate = Split-Path $pathz[0]
    $pathz = remove-candidate -candidate $candidate -list $pathz
    $masterpath += $candidate
    }
    }
    $masterpath
}

#generator for SRP Registry GUIDs
function get-guidz($rnum){
$gprefix = "0016bbe0-a716-428b-822e-"
$guidarray = @()
1..$rnum | % {
    $guidarray += ('{' + $gprefix + ((New-Guid).Guid -split '\-')[4].toupper() + '}' )
}
    if ($guidarray.Count -eq ($guidarray | Sort-Object -Unique).count){
        return $guidarray
    }
    else{
        throw "Duplicate found!"
    }
}

function find-code(){
    Write-Debug "Scanning your machine for code"
    Write-Debug "This may take a while, pookie is a bad programmer"
    $existing_code = get-unique -pathz (get-softpath | Sort-Object)
    New-Item -Path HKLM:\SOFTWARE\SRPBAK\software -Force
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "Code" -Value $existing_code -Type MultiString

}

function make-key($codepath, $guid, $act){

    switch ($osarch)
    {
        #64-bit make-key
        '64' {
            switch ($act)
            {
                '0' {
                    New-Item -Path HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\paths\$guid -Force | Out-Null
                    Set-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\$guid -Name 'ItemData' -Value $codepath
                }
                '262144' {
                    New-Item -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\paths\$guid -Force | Out-Null
                    Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\paths\$guid -Name 'ItemData' -Value $codepath
                }
                Default {Write-Debug "Need allow or disallow param"}
            }
        }
        #32-bit make-key
        '32' {
            switch ($act)
            {
                '0' {
                    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\paths\$guid -Force | Out-Null
                    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\$guid -Name 'ItemData' -Value $codepath
                }
                '262144' {
                    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\paths\$guid -Force | Out-Null
                    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\paths\$guid -Name 'ItemData' -Value $codepath
                }
                Default {Write-Debug "Need allow or disallow param"}
            }
        }
        Default {write-debug "need OS Arch param"}
    }
}

function backup-srp(){
    New-Item -ItemType Directory -Path HKLM:\SOFTWARE\SRPBAK\0\Paths -Force | Out-Null
    New-Item -ItemType Directory -Path HKLM:\SOFTWARE\SRPBAK\262144\Paths -Force | Out-Null
    New-Item -Path HKLM:\SOFTWARE\SRPBAK\CodeIdentifiers -Force | Out-Null
    sleep -Milliseconds 500
    Copy-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Destination HKLM:\SOFTWARE\SRPBAK\ -Force -ErrorAction SilentlyContinue
    Copy-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\* -Destination HKLM:\SOFTWARE\SRPBAK\0\Paths\ -Force -ErrorAction SilentlyContinue
    Copy-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\* -Destination HKLM:\SOFTWARE\SRPBAK\262144\Paths\ -Force -ErrorAction SilentlyContinue
    Copy-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Destination HKLM:\SOFTWARE\SRPBAK\ -Force -ErrorAction SilentlyContinue
}

function restore-srp(){
    switch ($osarch)
    {
        '64' {
            New-Item -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Force | Out-Null
            New-Item -ItemType Directory -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\ -Force | Out-Null
            New-Item -ItemType Directory -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\ -Force | Out-Null
            sleep -Milliseconds 500
            Copy-Item -Path HKLM:\SOFTWARE\SRPBAK\CodeIdentifiers -Destination HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\ -Force -ErrorAction SilentlyContinue
            Copy-Item -Path HKLM:\SOFTWARE\SRPBAK\0\Paths\* -Destination HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\ -Force -ErrorAction SilentlyContinue
            Copy-Item -Path HKLM:\SOFTWARE\SRPBAK\262144\Paths\* -Destination HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\ -Force -ErrorAction SilentlyContinue
        }
        '32' {
            New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Force | Out-Null
            New-Item -ItemType Directory -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\ -Force | Out-Null
            New-Item -ItemType Directory -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\ -Force | Out-Null
            sleep -Milliseconds 500
            Copy-Item -Path HKLM:\SOFTWARE\SRPBAK\CodeIdentifiers -Destination HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\ -Force -ErrorAction SilentlyContinue
            Copy-Item -Path HKLM:\SOFTWARE\SRPBAK\0\Paths\* -Destination HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\ -Force -ErrorAction SilentlyContinue
            Copy-Item -Path HKLM:\SOFTWARE\SRPBAK\262144\Paths\* -Destination HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths\ -Force -ErrorAction SilentlyContinue
        }
        Default {}
    }
}

function toggle-softpol($action){    
    switch ($action)
    {
        'on' {
            restore-srp
            switch ($osarch)
            {
                '64' {
                    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "0" /f
                    Set-ItemProperty -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name DefaultLevel -Value 0x0
                    if ((get-ItemProperty -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\).defaultlevel -eq '0x0'){Write-Host "toggle SRP on successful!"}
                    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "1"
                }
                '32' {
                    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "0" /f
                    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name DefaultLevel -Value 0x0
                    if ((get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\).defaultlevel -eq '0x0'){Write-Host "toggle SRP on successful!"}
                    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "1"
                }
                Default {}
            }        
        
        }
        'off' {
            reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "1" /f
            Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name DefaultLevel -Value 0x40000 -ErrorAction SilentlyContinue
            if ((get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\ -ErrorAction SilentlyContinue).defaultlevel -eq '0x40000'){Write-Host "toggle SRP off successful!"}
            Remove-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\* -Recurse -ErrorAction SilentlyContinue -Force
            Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "0"
        }
        Default {Write-Host "need -action 'on' or 'off'"}
    }
}

function set-enablekey(){
$enablekey = @{
'AuthenticodeEnabled'= 0x0
'DefaultLevel'= 0x0
'PolicyScope'= 0x0
'TransparentEnabled'= 0x1
'ExecutableTypes' = "A3X
BAT
CHM
CMD
COM
CPL
CRT
EXE
HLP
HTA
INF
INS
ISP
MSC
MSI
MSP
MST
OCX
PIF
REG
SCR
SHS
JS
JSE
VB
WSC
APPLICATION
XPI"
}
    $enablekeyobj = New-Object psobject -Property $enablekey
    $enablekeyobj | Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -ErrorAction SilentlyContinue -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name ExecutableTypes -PropertyType MultiString -Value $enablekey.ExecutableTypes -Force | Out-Null
}

function set-shortcut($shortcutname, $action){
    $shell = New-Object -COM WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutname)
    $shortcut.TargetPath = 'C:\windows\system32\windowspowershell\v1.0\powershell.exe'  ## Target Powershell
    $string = "Start-Process powershell.exe -argumentlist '-file $action' -Verb RunAs"
    $shortcut.Arguments = "$string"
    $shortcut.Description = "Super Safe Shortcut"  ## This is the "Comment" field
    $shortcut.Save()  ## Savep
}

function set-srp(){
    find-code
    Remove-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\ -Recurse -Force -ErrorAction SilentlyContinue
    $global_whitelist | % {
        make-key -codepath $_ -guid (get-guidz -rnum 1) -act 262144
    }
    
    (Get-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software).code | % {
        make-key -codepath $_ -guid (get-guidz -rnum 1) -act 262144
    }

    $global_blacklist | % {
        make-key -codepath $_ -guid (get-guidz -rnum 1) -act 0
    }
    set-enablekey
    set-shortcut -shortcutname "$env:ALLUSERSPROFILE\desktop\srp-on.lnk" -action "$wd\srp.ps1 tog-on"
    set-shortcut -shortcutname "$env:ALLUSERSPROFILE\desktop\srp-off.lnk" -action "$wd\srp.ps1 tog-off"
    set-shortcut -shortcutname "$env:ALLUSERSPROFILE\desktop\srp-set.lnk" -action "$wd\srp.ps1 set"
    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "0" /f
    backup-srp
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "1"
}

function unset-srp(){
    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "1" /f
    Remove-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\ -Recurse
    Remove-Item -Path "$env:ALLUSERSPROFILE\desktop\srp-on.lnk" -Force | Out-Null
    Remove-Item -Path "$env:ALLUSERSPROFILE\desktop\srp-off.lnk" -Force | Out-Null
    Remove-Item -Path "$env:ALLUSERSPROFILE\desktop\srp-set.lnk" -Force | Out-Null
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "0"
}

switch ($arg)
{
    'set' {
        set-srp
    }
    'unset' {
        unset-srp
    }
    'tog-on' {
        toggle-softpol -action on

    }
    'tog-off' {
        toggle-softpol -action off
    }
    Default {}
}