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
Write-Output "Script: $ScriptName"
#endregion

#region -------- Registry Query --------
# Query both 64-bit and 32-bit uninstall registry keys (machine-wide)
$registryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

#region -------- Per-User Registry Paths --------
# Mount HKU (HKEY_USERS) drive if not already available
# This allows access to per-user registry hives
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

# Add per-user uninstall paths for all loaded user profiles
# NOTE: Only works for currently logged-in users whose hives are loaded
# Users who haven't logged in recently won't have their NTUSER.DAT mounted
try {
    $userSids = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match 'S-1-5-21-' }  # Filter for actual user SIDs (not system accounts)
    
    foreach ($sid in $userSids) {
        $userPath = "HKU:\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $registryPaths += $userPath
    }
}
catch {
    # Silently continue if per-user paths cannot be enumerated
}
#endregion

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
    exit 1
}
else {
    # No Dell SupportAssist found - device is compliant
    Write-Output "=== Applications Found ==="
    Write-Output "  None"
    Write-Output "Exit code: 0 (Compliant)"
    exit 0
}
#endregion
