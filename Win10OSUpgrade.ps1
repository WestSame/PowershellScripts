<#
Upgrade Windows 10 version using Windows Update Assistant and remove it after restart

Sampo Seppänen 2020
#>

Try {
    $TempDir = "C:\_Windows_FU"
    New-Item -Path $TempDir -ItemType Directory -Force -ErrorAction SilentlyContinue

    $WebClient = New-Object System.Net.WebClient
    $Uri = "https://go.microsoft.com/fwlink/?LinkID=799445"
    $Win10Upgrade = "$($TempDir)\Win10Upgrade.exe"
    $WebClient.DownloadFile($Uri,$Win10Upgrade)

    Write-Host "Windows upgrade assistant downloaded successfully"
} Catch {
    Write-Host "Failed to download Windows upgrade assistant"
    Exit 1
}

Try {
    Start-Process -FilePath $Win10Upgrade -ArgumentList "/SkipEULA /QuietInstall" -ErrorAction Stop
    
    $PSCfile = "$($env:SystemDrive)\`$GetCurrent\SafeOS\PartnerSetupComplete.cmd"
    While (!(Test-Path -Path $PSCfile)) {
        Start-Sleep -Seconds 5
    }
    $TempPSCfile =  "$($env:SystemDrive)\`$GetCurrent\SafeOS\PartnerSetupComplete.cmd.new"
    (Get-Content -Path $PSCfile) -Replace "/SkipSelfUpdate", "/ForceUninstall" | Add-Content -Path $TempPSCfile -Force
    Remove-Item -Path $PSCfile -Force
    Move-Item -Path $TempPSCfile -Destination $PSCfile -Force
    
    Do {
        Start-Sleep -Seconds 5
    } Until ((Get-Process -Name SetupPrep -ErrorAction SilentlyContinue).Count -gt 0 -and (Get-Process -Name SetupHost -ErrorAction SilentlyContinue).Count -gt 0 -and (Get-Process -Name Setup -ErrorAction SilentlyContinue).Count -gt 0)
    Write-Host "Windows upgrade in progress"
    
    Wait-Process -Name SetupPrep -ErrorAction SilentlyContinue
    Wait-Process -Name SetupHost -ErrorAction SilentlyContinue
    Wait-Process -Name Setup -ErrorAction SilentlyContinue
    
    Stop-Process -Name Windows10UpgraderApp -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Windows upgraded successfully"
    Exit 0
} Catch {
    Write-Host "Failed to upgrade Windows"
    Exit 1
}
