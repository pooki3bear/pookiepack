# PP GUI!
# A hacky attempt at a gui for an even hackier windows project!
$wd = $SCRIPT:MyInvocation.MyCommand.path | Split-Path -Parent
Add-Type -AssemblyName System.Windows.Forms
Import-Module $wd\get-pp.ps1 -Force
Import-Module $wd\pp-mod.psm1 -Force

function get-all(){
$srpstate = (Get-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -ErrorAction SilentlyContinue).srpstate
$PPstate = (get-ItemProperty -Path HKLM:\SOFTWARE\SRPBAK\software -ErrorAction SilentlyContinue).PPState
    if ($srpstate -eq 1){
    $checkBox4.Checked = $true
    }
    else {
    $checkBox4.Checked = $false
    }
    if ($ppstate -eq 1){
        $checkBox5.Checked = $true
    }
    else {
        $checkBox5.Checked = $false
    }
}

function set-shortcut($shortcutname,$path){
    $shell = New-Object -COM WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutname)
    $shortcut.TargetPath = 'C:\windows\system32\windowspowershell\v1.0\powershell.exe'  ## Target Powershell
    $string = "Start-Process powershell.exe -argumentlist '-file $path'"
    $shortcut.Arguments = "$string"
    $shortcut.Description = "Super Safe Shortcut"  ## This is the "Comment" field
    $shortcut.Save()  ## Savep
}

function set-pp(){
    check-pp -install 1
    if ($wd -eq "C:\windows\system32\pookiepack"){
        write-host "Please Run invoke-ppgui.ps1 again from source files"
        sleep 5
        exit
    }
    elseif ($wd -ne "C:\windows\system32\pookiepack"){
        Copy-Item "$wd\*" "C:\Windows\System32\pookiepack" -Force -Recurse
    }
    install
    set-shortcut -shortcutname "$env:ALLUSERSPROFILE\desktop\PPGUI.lnk" -path "C:\windows\system32\pookiepack\invoke-ppgui.ps1"
    get-all
}

function clear-pp(){
& $wd\srp.ps1 unset  
uninstall
Remove-Item "$env:ALLUSERSPROFILE\desktop\PPGUI.lnk"
Remove-Item "C:\Windows\System32\pookiepack\" -Recurse -Force -ErrorAction SilentlyContinue
get-all
}

$ppcp = New-Object system.Windows.Forms.Form
$ppcp.Text = "PookiePack Control Pannel"
$ppcp.BackColor = "#000000"
#$ppcp.TopMost = $true
$ppcp.BackgroundImage = [system.drawing.image]::FromFile("$wd\giphy.gif")
$ppcp.Width = 570
$ppcp.Height = 630

$button2 = New-Object system.windows.Forms.Button
$button2.BackColor = "#ffffff"
$button2.Text = "Install"
$button2.Width = 120
$button2.Height = 80
$button2.Add_MouseClick({
    set-pp
})
$button2.location = new-object system.drawing.point(50,20)
$button2.Font = "Arial,10"
$ppcp.controls.Add($button2)

$button3 = New-Object system.windows.Forms.Button
$button3.BackColor = "#ffffff"
$button3.Text = "Remove"
$button3.Width = 120
$button3.Height = 80
$button3.Add_MouseClick({
    clear-pp
})
$button3.location = new-object system.drawing.point(50,140)
$button3.Font = "Arial,10"
$ppcp.controls.Add($button3)

$checkBox4 = New-Object system.windows.Forms.CheckBox
$checkBox4.BackColor = "#ffffff"
$checkBox4.Text = "Is SRP On?"
$checkBox4.Width = 140
$checkBox4.Height = 50
$checkBox4.location = new-object system.drawing.point(370,340)
$checkBox4.Font = "Arial,10"
$ppcp.controls.Add($checkBox4)

$checkBox5 = New-Object system.windows.Forms.CheckBox
$checkBox5.Text = "Is PookiePack Installed?"
$checkBox5.BackColor = "#ffffff"
$checkBox5.Width = 140
$checkBox5.Height = 50
$checkBox5.location = new-object system.drawing.point(370,40)
$checkBox5.Font = "Arial,10"
$ppcp.controls.Add($checkBox5)

$button6 = New-Object system.windows.Forms.Button
$button6.BackColor = "#ffffff"
$button6.Text = "Re-Baseline!"
$button6.Width = 120
$button6.Height = 80
$button6.Add_MouseClick({
 & $wd\srp.ps1 set
 get-all
})
$button6.location = new-object system.drawing.point(140,320)
$button6.Font = "Arial,10"
$ppcp.controls.Add($button6)

$button7 = New-Object system.windows.Forms.Button
$button7.BackColor = "#ffffff"
$button7.Text = "Toggle SRP on"
$button7.Width = 60
$button7.Height = 40
$button7.Add_MouseClick({
 & $wd\srp.ps1 tog-on
 get-all
})
$button7.location = new-object system.drawing.point(45,320)
$button7.Font = "Arial,10"
$ppcp.controls.Add($button7)

$button8 = New-Object system.windows.Forms.Button
$button8.BackColor = "#ffffff"
$button8.Text = "Toggle SRP off"
$button8.Width = 60
$button8.Height = 40
$button8.Add_MouseClick({
 & $wd\srp.ps1 tog-off
 get-all
})
$button8.location = new-object system.drawing.point(45,360)
$button8.Font = "Arial,10"
$ppcp.controls.Add($button8)

get-all

[void]$ppcp.ShowDialog()
$ppcp.Dispose()