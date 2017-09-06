<#
.Synopsis
   Installs or removes pookiepack
.DESCRIPTION
   An attempt is made to automatically whitelist appropriate directories for you!
.EXAMPLE
   .\get-pp.ps1 -install
   Installs Pookiepack
.EXAMPLE
   .\get-pp.ps1 -remove
    Removes Pookiepack
#>
[CmdletBinding()]
Param
(
    [switch]$remove,
    [switch]$install #,
    #[switch]$all,
    #[switch]$easy,
    #[switch]$browser
)

$wd = $SCRIPT:MyInvocation.MyCommand.path | Split-Path -Parent
Import-Module $wd\pp-mod.psm1

function check-pp($install,$remove){
    $PPstate = (get-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software\ -ErrorAction SilentlyContinue).PPState
    if($install -and ($PPstate -eq 1)){
        Write-Host -ForegroundColor Red "IT LOOKS LIKE POOKIEPACK IS ALREADY INSTALLED, ARE YOU SURE YOU WANT TO INSTALL AGAIN?"
        Write-Host -ForegroundColor Red "YOU SHOULD CONSIDER REMOVING POOKIEPACK FIRST WITH .\GET-PP -REMOVE"
        $resp = Read-Host -Prompt "ARE YOU SURE? (Y/N)"
        if ($resp -match "Y"){
        write-host "okie we doing it!"
        }
        elseif($resp -match "N"){
        write-host "great! try uninstalling first"
        exit
        }
        else{
        Write-Error "invalid answer, exiting..."
        exit
        }
    }
    elseif($remove -and ($PPstate -eq 0)){
        Write-Host -ForegroundColor Red "IT LOOKS LIKE POOKIEPACK ISNT INSTALLED, ARE YOU SURE YOU WANT TO REMOVE?"
        Write-Host -ForegroundColor Red "YOU SHOULD CONSIDER REMOVING POOKIEPACK FIRST WITH .\GET-PP -REMOVE"
        $resp = Read-Host -Prompt "ARE YOU SURE? (Y/N)"
        if ($resp -match "Y"){
        write-host "okie we doing it!"
        }
        elseif($resp -match "N"){
        write-host "great! try installing first"
        exit
        }
        else{
        Write-Error "invalid answer, exiting..."
        exit
        }
    }
}

function install(){
    new-restore
    set-psv2
    set-wpad
    set-wdigest
    set-netbios
    set-compbrows
    set-llmnr
    set-font
    set-explore
    set-network
    set-odns
    set-log
    set-ftype
    set-emet -command install
    set-bb
    & $wd\srp.ps1 set
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "PPState" -Value "1" -Force
    Wait-Process -Id (Get-Process -Name blackbird).Id
    Write-Host "Great, you should now have pookiepack installed!"
    Write-Host "You can 'unlock' the software policy by running the 'srp-off' shortcut and entering an admin password"
    Write-Host "Once system changes are made, lock the computer again by running the 'srp-on' shortcut"
    Write-Host "If you have problems running an application under the locked profile, try running the app and then resetting policy with the 'srp-set' shortcut"
}

function uninstall(){
    & $wd\srp.ps1 unset
    clear-psv2
    clear-explore
    clear-wpad
    clear-wdigest
    clear-netbios
    clear-compbrows
    clear-llmnr
    clear-font
    clear-bb
    set-emet -command uninstall
    clear-log
    clear-network
    clear-odns
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "PPState" -Value "0" -Force
    Write-Host ""
    Write-Host ""
    Write-Host "Great, you should now have pookiepack removed! I'm sorry if you don't like it but it is in its infancy"
    Write-Host "You may need to reboot your PC to restore network connectivity"
}

if($install){
    check-pp -install 1
    install
}
    
elseif($remove){
    check-pp -remove 1
    uninstall
}
else {
    write-host "need switches dummy! e.g. -install or -remove"
}