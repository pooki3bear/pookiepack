# Escalate thru UAC and run PPGUI
$wd = $SCRIPT:MyInvocation.MyCommand.path | Split-Path -Parent
function IsAdministrator
{
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
    $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function IsUacEnabled
{
    (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System).EnableLua -ne 0
}

if (IsAdministrator){
    Start-Process PowerShell.exe -Verb Runas -WorkingDirectory $pwd -ArgumentList "-file $wd\ppgui-mod.ps1"
}
elseif (!(IsAdministrator))
{
    if (IsUacEnabled)
    {
        Start-Process PowerShell.exe -Verb Runas -WorkingDirectory $pwd -ArgumentList "-file $wd\ppgui-mod.ps1"
    }
    else
    {
        throw "You must be administrator to run this script"
    }
}
Stop-Process -Id $PID