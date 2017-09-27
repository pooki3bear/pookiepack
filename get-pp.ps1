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
    $PPstate = (get-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -ErrorAction SilentlyContinue).PPState
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
    set-wpad
    set-wdigest
    set-netbios
    #set-compbrows
    set-llmnr
    set-font
    set-network
    set-odns
    set-log
    set-ftype
    set-emet -command install
    set-teloff
    & $wd\srp.ps1 set
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "PPState" -Value "1" -Force
    Write-Host "Great, you should now have pookiepack installed!"
}

function uninstall(){
    & $wd\srp.ps1 unset
    clear-wpad
    clear-wdigest
    #clear-netbios
    #clear-compbrows
    clear-llmnr
    clear-font
    set-emet -command uninstall
    clear-log
    clear-network
    clear-odns
    set-telon
    Set-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -Name "PPState" -Value "0" -Force
    Write-Host ""
    Write-Host ""
    Write-Host "You should now have pookiepack removed! I'm sorry if you don't like it but it is in its infancy"
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
    #write-host "need switches dummy! e.g. -install or -remove"
}
