<#
.SYNOPSIS
    Detects Dell SupportAssist applications.

.DESCRIPTION
    Detection script for Microsoft Intune remediation.
    Exits with code 1 if Dell SupportAssist is found (remediation needed).
    Exits with code 0 if not found (compliant).

.NOTES
    Version:        1.0
    Date:           2026-01-21
#>

#region -------- Script Identification --------
# Output script name to agent executor log for tracking
$ScriptName = "Detect-DellSupportAssist.ps1"
#endregion

#region -------- Logging Setup --------
# Create log folder if it doesn't exist
$LogFolder = "C:\Windows\Temp\Remediate-DellSupportAssist"
if (-not (Test-Path -Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}
# Create transcript log file with timestamp for local device logging
# Transcript captures all output for troubleshooting on the device
$LogPath = "$LogFolder\Detect-DellSupportAssist_$(Get-Date -Format 'yyyyMMdd_hhmmsstt').log"
Start-Transcript -Path $LogPath -Force | Out-Null
Write-Output "Start Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt') $((Get-TimeZone).StandardName)"
#endregion

#region -------- Initialize Variables --------
$exitCode = 0
#endregion

#region -------- Main Execution Block --------
# Wrapped in try/catch/finally to ensure transcript is always written
try {
    Write-Output "Script: $ScriptName"

    #region -------- Registry Query --------
    # Query both 64-bit and 32-bit uninstall registry keys (machine-wide)
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

    #region -------- Detection Result --------
    # Determine compliance status and output results
    if ($apps) {
        # Dell SupportAssist found - remediation needed
        Write-Output "=== Applications Found ==="
        $apps | ForEach-Object { Write-Output "  - $($_.DisplayName)" }
        Write-Output "Exit code: 1 (Remediation needed)"
        $exitCode = 1
    }
    else {
        # No Dell SupportAssist found - device is compliant
        Write-Output "=== Applications Found ==="
        Write-Output "  None"
        Write-Output "Exit code: 0 (Compliant)"
        $exitCode = 0
    }
    #endregion
}
catch {
    #region -------- Fatal Error Handler --------
    Write-Output "=== FATAL ERROR ==="
    Write-Output "Error: $($_.Exception.Message)"
    Write-Output "Line: $($_.InvocationInfo.ScriptLineNumber)"
    $exitCode = 1
    #endregion
}
finally {
    #region -------- Cleanup --------
    Write-Output "End Time: $(Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt') $((Get-TimeZone).StandardName)"
    Write-Output "Log: $LogPath"
    Stop-Transcript | Out-Null
    #endregion
}
#endregion

exit $exitCode
#endregion
