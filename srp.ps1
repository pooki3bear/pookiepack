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

$wd = $SCRIPT:MyInvocation.MyCommand.path | Split-Path -Parent
$osarch = if ([System.IntPtr]::Size -eq 4) { "32" } else { "64" }

$global_whitelist = "C:\Program Files (x86)",
"C:\Program Files",
"C:\Windows",
"C:\Windows\SysWOW64",
"C:\Windows\*.exe",
"C:\Windows\SysWOW64\*.exe",
"C:\boot\",
"$env:TEMP\*.ps1",
"$env:TEMP\*.psm1",
"$wd\*.ps1"

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
#find all EXE on filesystem except for filtered paths - these will be whiteliseted under SRP baseline
    $pathlist = @()
    $ldisk = Get-WmiObject win32_logicaldisk | Where-Object {$_.DriveType -eq ‘3’}
    $ldisk | % {
        $exez = (gci ($_.DeviceID + "\") -Force -Recurse -ErrorAction SilentlyContinue).FullName | Where-Object {$_ -match "\.exe$"}
        $filtered = $exez | Select-String -NotMatch ":\\Windows\\|Program Files|Downloads|Documents|Recycle\.bin|Temp"
        $filtered | % {$pathlist += $_}
        
    }
$pathlist
}

function get-guidz($rnum){
#generator for SRP Registry GUIDs
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
    $existing_code = get-softpath
    #$existing_code = get-unique -pathz (get-softpath | Sort-Object)
    if(!(Test-Path HKLM:\SOFTWARE\SRPBAK\software)){
    New-Item -Path HKLM:\SOFTWARE\SRPBAK\software -Force
    }
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "Code" -Value $existing_code -Type MultiString -force

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
                    reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v DenyUnspecified /f /t REG_DWORD /d 1
                }
                '32' {
                    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "0" /f
                    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name DefaultLevel -Value 0x0
                    if ((get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\).defaultlevel -eq '0x0'){Write-Host "toggle SRP on successful!"}
                    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "1"
                    reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v DenyUnspecified /f /t REG_DWORD /d 1
                }
                Default {}
            }        
        
        }
        'off' {
            reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "1" /f
            Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name DefaultLevel -Value 0x40000 -ErrorAction SilentlyContinue
            if ((get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\ -ErrorAction SilentlyContinue).defaultlevel -eq '0x40000'){Write-Host "toggle SRP off successful!"}
            Remove-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\* -Recurse -ErrorAction SilentlyContinue -Force
            Remove-Item -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\* -Recurse -ErrorAction SilentlyContinue -Force
            Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "0"
            reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v DenyUnspecified /f /t REG_DWORD /d 0
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

function set-localHID(){
    reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v AllowDeviceIDs /f /t REG_DWORD /d 1
    $devid += (Get-PnpDevice | Where-Object {$_.class -eq 'Mouse'} | Where-Object {$_.status -eq 'OK'}).instanceid
    $devid += (Get-PnpDevice | Where-Object {$_.class -eq 'Keyboard'} | Where-Object {$_.status -eq 'OK'}).instanceid
    $devid += (Get-PnpDevice | Where-Object {$_.class -eq 'HIDClass'} | Where-Object {$_.status -eq 'OK'}).instanceid
    New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs -Force
    $counter = 1
    $devid | % {
    
        Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs -Name $counter -Value $_
    $Counter++
    }
}

function set-srp(){
    Write-Host "Now scanning local system drives for code, this may take a while depending on your hardware"
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
    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "0" /f
    backup-srp
    set-localHID
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "1"
    reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v AllowAdminInstall /f /t REG_DWORD /d 1
    reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v DenyUnspecified /f /t REG_DWORD /d 1
}

function unset-srp(){
    reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /t REG_DWORD /v "Enabled" /d "1" /f
    Remove-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\ -Recurse -ErrorAction SilentlyContinue -Force
    Remove-Item -Path HKLM:\SOFTWARE\wow6432node\Policies\Microsoft\Windows\Safer\ -Recurse -ErrorAction SilentlyContinue -Force
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "SrpState" -Value "0"
    reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions /v DenyUnspecified /f /t REG_DWORD /d 0
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