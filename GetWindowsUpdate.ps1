<#
Powershell script to check Windows updates

Using PSWindowsUpdate module by Michal Gajda
https://www.powershellgallery.com/packages/PSWindowsUpdate

Sampo Seppänen 2020
#>

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

$PSWindowsUpdateUri = "https://psg-prod-eastus.azureedge.net/packages/pswindowsupdate.2.1.1.2.nupkg"
$PSWindowsUpdateFile = "$($ScriptPath)\PSWindowsUpdate.zip"
$PSWindowsUpdatePath = "$($ScriptPath)\PSWindowsUpdate"

Remove-Item -Path $PSWindowsUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $PSWindowsUpdateFile -Force -ErrorAction SilentlyContinue

# Download PSWindowsUpdate module
Try {
    Invoke-WebRequest -Uri $PSWindowsUpdateUri -OutFile $PSWindowsUpdateFile -ErrorAction Stop
    Expand-Archive -Path $PSWindowsUpdateFile -DestinationPath $PSWindowsUpdatePath -Force -ErrorAction Stop
    Write-Host "Windows Update module downloaded successfully"
} Catch {
    Write-Host $_
    Write-Host "Failed to download Windows Update module"
    Remove-Item -Path $PSWindowsUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $PSWindowsUpdateFile -Force -ErrorAction SilentlyContinue
    Exit 1
}

# Import PSWindowsUpdate module and check Windows updates
Try {
    Import-Module -Name "$($ScriptPath)\PSWindowsUpdate\PSWindowsUpdate.psd1" -Force -ErrorAction Stop
    Get-WindowsUpdate -Install -NotCategory "Drivers" -MicrosoftUpdate -IgnoreReboot -AcceptAll
    Write-Host "Windows Update module executed successfully"
    Remove-Item -Path $PSWindowsUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $PSWindowsUpdateFile -Force -ErrorAction SilentlyContinue
    Exit 0
} Catch {
    Write-Host $_
    Write-Host "Failed to execute Windows Update module"
    Remove-Item -Path $PSWindowsUpdatePath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $PSWindowsUpdateFile -Force -ErrorAction SilentlyContinue
    Exit 1
}
