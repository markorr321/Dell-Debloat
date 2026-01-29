<#
.SYNOPSIS
    Removes Dell SupportAssist applications.

.DESCRIPTION
    Remediation script for Microsoft Intune.
    Uses the safe registry method to find and uninstall Dell SupportAssist.
    Exits with code 0 on success, code 1 on failure.

.NOTES
    Version:        1.0
    Date:           2026-01-21
#>

#region -------- Script Identification --------
# Output script name to agent executor log for tracking
$ScriptName = "Remediate-DellSupportAssist.ps1"
#endregion

#region -------- Logging Setup --------
# Create log folder if it doesn't exist
$LogFolder = "C:\Windows\Temp\Remediate-DellSupportAssist"
if (-not (Test-Path -Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}
# Create transcript log file with timestamp for local device logging
# Transcript captures all output for troubleshooting on the device
$LogPath = "$LogFolder\Remediate-DellSupportAssist_$(Get-Date -Format 'yyyyMMdd_hhmmsstt').log"
$StartTime = Get-Date
Start-Transcript -Path $LogPath -Force | Out-Null
Write-Output "Start Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt') $((Get-TimeZone).StandardName)"
#endregion

#region -------- Initialize Variables --------
# Track exit code and failure count for reporting
$exitCode = 0
$failedCount = 0
#endregion

#region -------- Main Execution Block --------
# Wrapped in try/catch/finally to ensure transcript is always written
# Even if a terminating error occurs, the finally block runs
try {
    Write-Output "Script: $ScriptName"
    Write-Output "=== Dell SupportAssist Remediation ==="

    #region -------- Registry Query --------
    # Query both 64-bit and 32-bit uninstall registry keys (machine-wide)
    # This method is fast and has no side effects (unlike Win32_Product)
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    # Filter for Dell SupportAssist applications by DisplayName
    $apps = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.DisplayName -like "*SupportAssist*" -or 
            $_.DisplayName -like "*Dell Support*" 
        }
    #endregion

    #region -------- Process Applications --------
    if (-not $apps) {
        # No applications found - nothing to remediate
        Write-Output "No Dell SupportAssist applications found."
        $exitCode = 0
    }
    else {
        # List all applications that will be removed
        Write-Output "Found $($apps.Count) application(s) to remove:"
        $apps | ForEach-Object { Write-Output "  - $($_.DisplayName)" }

        #region -------- Uninstall Loop --------
        # Iterate through each application and attempt uninstall
        foreach ($app in $apps) {
            Write-Output "Uninstalling $($app.DisplayName) ..."
            
            try {
                if ($app.QuietUninstallString) {
                    # Preferred: Use QuietUninstallString if available
                    # This is the vendor-provided silent uninstall command
                    Write-Output "  Using QuietUninstallString"
                    cmd.exe /c $app.QuietUninstallString 2>&1 | Out-Null
                    Write-Output "  -> Success"
                }
                elseif ($app.UninstallString) {
                    # Fallback: Use standard UninstallString with silent switches
                    Write-Output "  Using UninstallString"
                    
                    if ($app.UninstallString -match "msiexec" -and $app.UninstallString -match "\{[A-F0-9\-]+\}") {
                        # MSI package - extract GUID and uninstall silently
                        # Exit code 0 = success, 3010 = success but reboot required
                        $guid = [regex]::Match($app.UninstallString, "\{[A-F0-9\-]+\}").Value
                        Write-Output "  MSI GUID: $guid"
                        $process = Start-Process "msiexec.exe" -ArgumentList "/X$guid", "/quiet", "/norestart" -Wait -PassThru
                        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                            Write-Output "  -> Success (Exit code: $($process.ExitCode))"
                        }
                        else {
                            Write-Output "  -> Failed (Exit code: $($process.ExitCode))"
                            $failedCount++
                        }
                    }
                    else {
                        # EXE installer - try common silent switches
                        cmd.exe /c "$($app.UninstallString) /silent /quiet /S" 2>&1 | Out-Null
                        Write-Output "  -> Success"
                    }
                }
                else {
                    # No uninstall method available
                    Write-Output "  -> No uninstall string found"
                    $failedCount++
                }
            }
            catch {
                # Catch any errors during individual app uninstall
                Write-Output "  -> Failed: $($_.Exception.Message)"
                $failedCount++
            }
        }
        #endregion

        # Set exit code based on failure count
        if ($failedCount -gt 0) {
            $exitCode = 1
        }
    }
    #endregion

    Write-Output "=== Remediation Complete ==="
}
catch {
    #region -------- Fatal Error Handler --------
    # Catch any terminating errors not handled elsewhere
    # Log the error message and line number for troubleshooting
    Write-Output "=== FATAL ERROR ==="
    Write-Output "Error: $($_.Exception.Message)"
    Write-Output "Line: $($_.InvocationInfo.ScriptLineNumber)"
    $exitCode = 1
    #endregion
}
finally {
    #region -------- Cleanup --------
    # Always runs - ensures transcript is written even after terminating errors
    $EndTime = Get-Date
    $ElapsedTime = $EndTime - $StartTime
    Write-Output "End Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt') $((Get-TimeZone).StandardName)"
    Write-Output "Total Time: $($ElapsedTime.Minutes) minutes $($ElapsedTime.Seconds) seconds"
    Write-Output "Log: $LogPath"
    Stop-Transcript | Out-Null
    #endregion
}
#endregion

exit $exitCode
