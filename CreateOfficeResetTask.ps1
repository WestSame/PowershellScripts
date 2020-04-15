<#
Powershell script to reset Office products logins

Sampo Seppänen 2020
#>

Param(       
    [Parameter(Mandatory=$true)]  
    [String]$ActivateTime,
    [Parameter(Mandatory=$true)]  
    [String]$ExpireTime
)

$ScriptBlock = {
    $ScriptVersion = "1.2"

    $UserSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    
    # Logging function
    Function WriteLog {
        Param([Parameter(Mandatory=$True)]$Value)
        $LogFile = "$env:TEMP\OfficeResetTask.log" 
        If (!(Test-Path -Path $LogFile)) {
            New-Item -Path $LogFile -ItemType File
        } Else {
            If ($LogFile.Length -gt 10mb) {
                Remove-Item $LogFile -Force
                New-Item -Path $LogFile -ItemType File
            }
        }
        $Date = Get-Date -Format "dd.MM.yyyy HH:mm"
        Foreach ($Line In $Value) {
            Add-Content -Path $LogFile -Value "$Date    $Line" -Force
        }
        Write-Host $Value
    }

    $StatusRegKey = "HKCU:\Software\Microsoft\Office\Reset\$($ScriptVersion)"
    $OfficeRegKey = "HKCU:\Software\Microsoft\Office\16.0"

    # Create registry keys for checking Office reset status
    If (!(Get-Item $StatusRegKey)) {
        Try {
            New-Item -Path $StatusRegKey -Force -ErrorAction Stop

            New-ItemProperty -Path $StatusRegKey -Name "Status" -PropertyType Dword -Value 0 -Force -Confirm:$false -ErrorAction Stop
            New-ItemProperty -Path $StatusRegKey -Name "OneDrive" -PropertyType Dword -Value 0 -Force -Confirm:$false -ErrorAction Stop
            New-ItemProperty -Path $StatusRegKey -Name "Outlook" -PropertyType Dword -Value 0 -Force -Confirm:$false -ErrorAction Stop
            New-ItemProperty -Path $StatusRegKey -Name "Skype" -PropertyType Dword -Value 0 -Force -Confirm:$false -ErrorAction Stop
            New-ItemProperty -Path $StatusRegKey -Name "Teams" -PropertyType Dword -Value 0 -Force -Confirm:$false -ErrorAction Stop

            WriteLog -Value "Registry values created for Office reset status"
        } Catch {
            $ErrorMessage = $_.Exception.Message
            WriteLog -Value "Failed to create registry values for Office reset status"
            WriteLog -Value $ErrorMessage

            Exit 1
        }
    }

    If ((Get-ItemPropertyValue -Path $StatusRegKey -Name "Status") -eq 0) {

        # Reset Outlook
        If ((Get-ItemPropertyValue -Path $StatusRegKey -Name "Outlook") -eq 0) {
            $OutlookProfileRegKey = Join-Path -Path "$OfficeRegKey" -ChildPath "Outlook\Profiles\Outlook"

            While ((Get-Process -Name OUTLOOK | Where-Object -Property SessionId -eq $UserSession).Count -gt 0) {
                $OutlookRunning = $true
                $OutlookExe = (Get-Process -Name OUTLOOK | Where-Object -Property SessionId -eq $UserSession).Path | Select-Object -First 1
                Get-Process -Name OUTLOOK | Where-Object -Property SessionId -eq $UserSession | Stop-Process -Force
                Start-Sleep -Milliseconds 500
            }

            Try {
                If (Test-Path -Path $OutlookProfileRegKey) {
                    $RemoveSuccess = 0
                    Do {
                        Try {
                            Remove-Item -Path $OutlookProfileRegKey -Recurse -Force -Confirm:$false -ErrorAction Stop
                            $RemoveSuccess = 1
                        } Catch {
                            $ErrorMessage = $_.Exception.Message
                            WriteLog -Value $ErrorMessage
                            $RemoveSuccess = 0
                        }
                    } Until ($RemoveSuccess -eq 1)
                }

                New-Item -Path "$OfficeRegKey\Outlook\Profiles\Outlook" -Force -Confirm:$false -ErrorAction Stop
                Set-ItemProperty -Path "$OfficeRegKey\Outlook" -Name "DefaultProfile" -Value "Outlook" -Force -Confirm:$false -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "$OfficeRegKey\Outlook\Setup" -Name "First-Run" -Force -Confirm:$false -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $StatusRegKey -Name "Outlook" -Value 1 -Force -Confirm:$false -ErrorAction SilentlyContinue
                WriteLog -Value "Outlook account successfully reset"

                If ($OutlookRunning -eq $true -and (Get-Process -Name OUTLOOK | Where-Object -Property SessionId -eq $UserSession).Count -eq 0) {
                    Start-Process -FilePath $OutlookExe
                }
            } Catch {
                $ErrorMessage = $_.Exception.Message
                WriteLog -Value "Failed to reset Outlook account"
                WriteLog -Value $ErrorMessage
            }
        } Else {
            WriteLog -Value "Outlook account already reset"
        }

        # Reset OneDrive
        If ((Get-ItemPropertyValue -Path $StatusRegKey -Name "OneDrive") -eq 0) {
            $OneDriveRegKey = "HKCU:\Software\Microsoft\OneDrive\Accounts"

            $OneDriveSubKeys = (Get-Item $OneDriveRegKey).GetSubKeyNames() -match "^Business"

            $OneDriveAccountCount = ($OneDriveSubKeys).Count
            $OneDriveSuccessCount = 0

            ForEach ($OneDriveSubKey In $OneDriveSubKeys) {
                $OneDriveAccountRegKey = Join-Path -Path $OneDriveRegKey -ChildPath $OneDriveSubKey
        
                $OneDriveDisplayName = (Get-ItemProperty -Path $OneDriveAccountRegKey -Name DisplayName).DisplayName
                $OneDriveName = "OneDrive - $OneDriveDisplayName"
        
                $DesktopPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace"
                $DesktopSubKeys = (Get-Item $DesktopPath).GetSubKeyNames()
        
                ForEach ($DesktopSubKey In $DesktopSubKeys) {
                    $SubKeyFullPath = Join-Path -Path $DesktopPath -ChildPath $DesktopSubKey
        
                    If ((Get-ItemProperty -Path $SubKeyFullPath)."(Default)" -eq $OneDriveName) {
                        While ((Get-Process -Name OneDrive | Where-Object -Property SessionId -eq $UserSession).Count -gt 0) {
                            $OneDriveRunning = $true
                            $OneDriveExe = (Get-Process -Name OneDrive | Where-Object -Property SessionId -eq $UserSession).Path | Select-Object -First 1
                            Get-Process -Name OneDrive | Where-Object -Property SessionId -eq $UserSession | Stop-Process -Force
                            Start-Sleep -Milliseconds 500
                        }
                        
                        Try {
                            If (Test-Path -Path $SubKeyFullPath) {
                                $RemoveSuccess = 0
                                Do {
                                    Try {
                                        Remove-Item -Path $SubKeyFullPath -Recurse -Force -Confirm:$false -ErrorAction Stop
                                        $RemoveSuccess = 1
                                    } Catch {
                                        $ErrorMessage = $_.Exception.Message
                                        WriteLog -Value $ErrorMessage
                                        $RemoveSuccess = 0
                                    }
                                } Until ($RemoveSuccess -eq 1 -or $TryCount -eq 20)
                            }
                            

                            If (Test-Path -Path $OneDriveAccountRegKey) {
                                $RemoveSuccess = 0
                                Do {
                                    Try {
                                        Remove-Item -Path $OneDriveAccountRegKey -Recurse -Force -Confirm:$false -ErrorAction Stop
                                        $RemoveSuccess = 1
                                    } Catch {
                                        $ErrorMessage = $_.Exception.Message
                                        WriteLog -Value $ErrorMessage
                                        $RemoveSuccess = 0
                                    }
                                } Until ($RemoveSuccess -eq 1)
                            }
                            $OneDriveSuccessCount++
                        } Catch {
                            $ErrorMessage = $_.Exception.Message
                            WriteLog -Value $ErrorMessage
                        }
                    }
                }
            }

            If ($OneDriveSuccessCount -eq $OneDriveAccountCount) {
                Set-ItemProperty -Path $StatusRegKey -Name "OneDrive" -Value 1 -Force -Confirm:$false -ErrorAction SilentlyContinue
                WriteLog -Value "OneDrive account successfully reset"

                If ($OneDriveRunning -eq $true -and (Get-Process -Name OneDrive | Where-Object -Property SessionId -eq $UserSession).Count -eq 0) {
                    Start-Process -FilePath $OneDriveExe
                }
            } Else {
                WriteLog -Value "Failed to reset OneDrive account"
            }
        } Else {
            WriteLog -Value "OneDrive account already reset"
        }

        # Reset Skype For Business
        If ((Get-ItemPropertyValue -Path $StatusRegKey -Name "Skype") -eq 0) {
            $SkypeAccounts = (Get-Item "$env:LOCALAPPDATA\Microsoft\Office\16.0\Lync").GetDirectories() -match "sip_"

            $SkypeAccountCount = ($SkypeAccounts).Count
            $SkypeSuccessCount = 0

            ForEach ($SkypeAccount In $SkypeAccounts) {

                $SkypeAccountName = ($SkypeAccount.Name).Replace("sip_","")

                $SkypeAccountPath = $SkypeAccount.FullName
                $SkypeAccountRegKey = Join-Path -Path $OfficeRegKey -ChildPath "Lync\$SkypeAccountName"
                
                While ((Get-Process -Name lync | Where-Object -Property SessionId -eq $UserSession).Count -gt 0) {
                    $SkypeRunning = $true
                    $SkypeExe = (Get-Process -Name lync | Where-Object -Property SessionId -eq $UserSession).Path | Select-Object -First 1
                    Get-Process -Name lync | Where-Object -Property SessionId -eq $UserSession | Stop-Process -Force
                    Start-Sleep -Milliseconds 500
                }

                Try {
                    If (Test-Path -Path $SkypeAccountPath) {
                        $RemoveSuccess = 0
                        Do {
                            Try {
                                Remove-Item -Path $SkypeAccountPath -Recurse -Force -Confirm:$false -ErrorAction Stop
                                $RemoveSuccess = 1
                            } Catch {
                                $ErrorMessage = $_.Exception.Message
                                WriteLog -Value $ErrorMessage
                                $RemoveSuccess = 0
                            }
                        } Until ($RemoveSuccess -eq 1)
                    }
                    If (Test-Path -Path $SkypeAccountRegKey) {
                        $RemoveSuccess = 0
                        Do {
                            Try {
                                Remove-Item -Path $SkypeAccountRegKey -Recurse -Force -Confirm:$false -ErrorAction Stop
                                $RemoveSuccess = 1
                            } Catch {
                                $ErrorMessage = $_.Exception.Message
                                WriteLog -Value $ErrorMessage
                                $RemoveSuccess = 0
                            }
                        } Until ($RemoveSuccess -eq 1)
                    }
                    $SkypeSuccessCount++
                } Catch {
                    $ErrorMessage = $_.Exception.Message
                    WriteLog -Value $ErrorMessage
                }
            }

            Try {
                $SkypeProfilesDatPath = "$env:APPDATA\Microsoft\Office\16.0\Lync\AccountProfiles.dat"
                If (Test-Path -Path $SkypeProfilesDatPath) {
                    $RemoveSuccess = 0
                    Do {
                        Try {
                            Remove-Item -Path $SkypeProfilesDatPath -Recurse -Force -Confirm:$false -ErrorAction Stop
                            $RemoveSuccess = 1
                        } Catch {
                            $ErrorMessage = $_.Exception.Message
                            WriteLog -Value $ErrorMessage
                            $RemoveSuccess = 0
                        }
                    } Until ($RemoveSuccess -eq 1)
                }
            } Catch {
                $ErrorMessage = $_.Exception.Message
                WriteLog -Value $ErrorMessage
            }

            Remove-ItemProperty -Path "$OfficeRegKey\Lync" -Name "FirstRun" -Force -Confirm:$false -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "$OfficeRegKey\Lync" -Name "ServerSipUri" -Value "" -Force -Confirm:$false -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "$OfficeRegKey\Lync" -Name "ServerUsername" -Value "" -Force -Confirm:$false -ErrorAction SilentlyContinue

            If ($SkypeSuccessCount -eq $SkypeAccountCount) {
                Set-ItemProperty -Path $StatusRegKey -Name "Skype" -Value 1 -Force -ErrorAction SilentlyContinue
                WriteLog -Value "Skype For Business account successfully reset"

                If ($SkypeRunning -eq $true -and (Get-Process -Name lync | Where-Object -Property SessionId -eq $UserSession).Count -eq 0) {
                    Start-Process -FilePath $SkypeExe
                }
            } Else {
                WriteLog -Value "Failed to reset Skype For Business account"
            }
        } Else {
            WriteLog -Value "Skype For Business account already reset"
        }

        # Reset Teams
        If ((Get-ItemPropertyValue -Path $StatusRegKey -Name "Teams") -eq 0) {
            $TeamsRegKey = "HKCU:\\Software\Microsoft\Office\Teams"
            $TeamsPath = "$env:APPDATA\Microsoft\Teams"

            While ((Get-Process -Name Teams | Where-Object -Property SessionId -eq $UserSession).Count -gt 0) {
                $TeamsRunning = $true
                $TeamsExe = (Get-Process -Name Teams | Where-Object -Property SessionId -eq $UserSession).Path | Select-Object -First 1
                Get-Process -Name Teams | Where-Object -Property SessionId -eq $UserSession | Stop-Process -Force
                Start-Sleep -Milliseconds 500
            }

            Try {
                If (Test-Path -Path $TeamsRegKey) {
                    $RemoveSuccess = 0
                    Do {
                        Try {
                            Remove-Item -Path "$TeamsRegKey" -Recurse -Force -Confirm:$false -ErrorAction Stop
                            $RemoveSuccess = 1
                        } Catch {
                            $ErrorMessage = $_.Exception.Message
                            WriteLog -Value $ErrorMessage
                            $RemoveSuccess = 0
                        }
                    } Until ($RemoveSuccess -eq 1)
                }
                
                $TeamsConfigFile = "$TeamsPath\desktop-config.json"

                If (Test-Path -Path $TeamsConfigFile) {
                    $TeamsJson = Get-Content $TeamsConfigFile | ConvertFrom-Json

                    $TeamsJson.upnWindowUserUpn = ""
                    $TeamsJson.userOid = ""
                    $TeamsJson.userTid = ""
                    $TeamsJson.homeTenantId = ""
                    $TeamsJson.webAccountId = ""
                    $TeamsJson.upnScreenShowCount = "1"
                    $TeamsJson.isLoggedOut = "true"
    
                    $TeamsJson | ConvertTo-Json | Set-Content $TeamsConfigFile -Force
                }

                Set-ItemProperty -Path $StatusRegKey -Name "Teams" -Value 1 -Force -Confirm:$false -ErrorAction SilentlyContinue
                WriteLog -Value "Teams account successfully reset"

                If ($TeamsRunning -eq $true -and (Get-Process -Name Teams | Where-Object -Property SessionId -eq $UserSession).Count -eq 0) {
                    Start-Process -FilePath $TeamsExe
                }
            } Catch {
                $ErrorMessage = $_.Exception.Message
                WriteLog -Value $ErrorMessage
            }
        } Else {
            WriteLog -Value "Teams account already reset"
        }

        # Check status for all reset functions
        $OneDriveReset = Get-ItemPropertyValue -Path $StatusRegKey -Name "OneDrive"
        $OutlookReset = Get-ItemPropertyValue -Path $StatusRegKey -Name "Outlook"
        $SkypeReset = Get-ItemPropertyValue -Path $StatusRegKey -Name "Skype"
        $TeamsReset = Get-ItemPropertyValue -Path $StatusRegKey -Name "Teams"

        If ($OneDriveReset -eq 1 -and $OutlookReset -eq 1 -and $SkypeReset -eq 1 -and $TeamsReset -eq 1) {
            Set-ItemProperty -Path $StatusRegKey -Name "Status" -Value 1 -Force -Confirm:$false -ErrorAction Stop
            WriteLog -Value "All Office products successfully reset"
        }
    } Else {
        WriteLog -Value "All Office products already reset"
    }
}

Set-Content -Path "$env:SystemRoot\OfficeResetTask.ps1" -Force -Value $ScriptBlock

If (Get-ScheduledTask -TaskName "Microsoft Office Reset" -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName "Microsoft Office Reset" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "Microsoft Office Reset" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft Office Reset" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    $TaskGUID = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" | Get-ItemProperty -Name URI | Where-Object -Property "URI" -eq "\Microsoft Office Reset").PSChildName
    If ($TaskGUID) {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$($TaskGUID)" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\$($TaskGUID)" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

If (!(Get-ScheduledTask -TaskName "Microsoft Office Reset" -ErrorAction SilentlyContinue)) {
    $StateChangeTrigger = Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskSessionStateChangeTrigger
    $Action = New-ScheduledTaskAction -Execute "powershell" -Argument "-noninteractive -executionpolicy bypass -windowstyle hidden -file ""$env:SystemRoot\OfficeResetTask.ps1"""
    $Trigger = @(
        $(New-ScheduledTaskTrigger -AtLogOn),
        $(New-CimInstance -CimClass $(StateChangeTrigger) -Property @{StateChange = 1} -ClientOnly),
        $(New-CimInstance -CimClass $(StateChangeTrigger) -Property @{StateChange = 8} -ClientOnly)
    )
    $Trigger.StartBoundary = $ActivateTime
    $Trigger.EndBoundary = $ExpireTime
    $Set = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter "00:00:01"
    $Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545"
    $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Set -Principal $Principal
    Register-ScheduledTask -TaskName "Microsoft Office Reset" -InputObject $Task -Force -ErrorAction Stop
}
