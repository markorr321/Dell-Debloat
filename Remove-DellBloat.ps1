<#
.SYNOPSIS
    Safely removes Dell bloatware including SupportAssist without causing BSOD.

.DESCRIPTION
    This script uses Dell's native uninstallers (QuietUninstallString) to safely remove
    Dell applications. This approach lets Dell's own uninstaller handle kernel driver
    unloading and service shutdown in the correct order, preventing CRITICAL_PROCESS_DIED BSOD.

    Based on the proven RemoveBloat.ps1 methodology by Andrew Taylor.

.NOTES
    Version:        1.0
    Author:         Based on RemoveBloat.ps1 by Andrew Taylor (andrewstaylor.com)
    Creation Date:  2026-01-21
    Purpose:        Safe Dell bloatware removal for Intune/SYSTEM execution

    IMPORTANT: This script does NOT forcibly stop Dell services or kill processes
    before uninstall. Doing so can cause BSOD due to orphaned kernel-mode drivers.
#>

#Requires -RunAsAdministrator

#region -------- Configuration --------

$ErrorActionPreference = 'SilentlyContinue'

# Logging setup
$LogDir = 'C:\ProgramData\Debloat'
if (!(Test-Path -Path $LogDir)) { 
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null 
}
$LogPath = Join-Path $LogDir "DellBloatRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path $LogPath -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$timestamp] [$Level] $Message"
}

#endregion

#region -------- Dell Win32 App Removal (Safe Method) --------

Write-Log "=== Dell Bloatware Removal Starting ==="
Write-Log "Using native Dell uninstallers to prevent BSOD..."

# Get all Dell uninstall entries at once for efficiency
$registryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$allDellApps = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -like "*Dell*" -and $_.DisplayName -notlike "*Dell*Audio*" -and $_.DisplayName -notlike "*Dell*Firmware*" }

Write-Log "Found $($allDellApps.Count) Dell applications to evaluate."

#--- Dell Optimizer Core ---
Write-Log "Processing Dell Optimizer Core..."
$dellOptimizer = $allDellApps | Where-Object { $_.DisplayName -like "Dell*Optimizer*Core" }
ForEach ($app in $dellOptimizer) {
    If ($app.UninstallString) {
        Write-Log "Uninstalling: $($app.DisplayName)"
        try {
            cmd.exe /c $app.UninstallString -silent 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell SupportAssist Remediation (CRITICAL - use QuietUninstallString) ---
Write-Log "Processing Dell SupportAssist Remediation..."
$dellSARemediation = $allDellApps | Where-Object { $_.DisplayName -match "Dell SupportAssist Remediation" }
ForEach ($sa in $dellSARemediation) {
    If ($sa.QuietUninstallString) {
        Write-Log "Uninstalling: $($sa.DisplayName)"
        try {
            cmd.exe /c $sa.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell SupportAssist OS Recovery Plugin ---
Write-Log "Processing Dell SupportAssist OS Recovery Plugin..."
$dellSARecovery = $allDellApps | Where-Object { $_.DisplayName -match "Dell SupportAssist OS Recovery Plugin" }
ForEach ($sa in $dellSARecovery) {
    If ($sa.QuietUninstallString) {
        Write-Log "Uninstalling: $($sa.DisplayName)"
        try {
            cmd.exe /c $sa.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell SupportAssist (main app and variants) ---
Write-Log "Processing Dell SupportAssist..."
$dellSA = $allDellApps | Where-Object { 
    $_.DisplayName -match "^Dell SupportAssist$" -or 
    $_.DisplayName -match "Dell SupportAssist for" -or
    $_.DisplayName -match "SupportAssist Recovery Assistant" -or
    $_.DisplayName -match "Dell SupportAssistAgent" -or
    $_.DisplayName -match "Dell Update - SupportAssist"
}
ForEach ($sa in $dellSA) {
    Write-Log "Uninstalling: $($sa.DisplayName)"
    If ($sa.QuietUninstallString) {
        try {
            cmd.exe /c $sa.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully (quiet)."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
    ElseIf ($sa.UninstallString) {
        try {
            cmd.exe /c "$($sa.UninstallString) /silent /quiet" 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully (standard)."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell Command | Update ---
Write-Log "Processing Dell Command Update..."
$dellCU = $allDellApps | Where-Object { $_.DisplayName -like "Dell Command*Update*" }
ForEach ($cu in $dellCU) {
    Write-Log "Uninstalling: $($cu.DisplayName)"
    If ($cu.QuietUninstallString) {
        try {
            cmd.exe /c $cu.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
    ElseIf ($cu.UninstallString) {
        try {
            if ($cu.UninstallString -match "msiexec") {
                $uninstallCmd = $cu.UninstallString -replace "/I", "/X"
                cmd.exe /c "$uninstallCmd /quiet /norestart" 2>&1 | Out-Null
            } else {
                cmd.exe /c "$($cu.UninstallString) /silent /quiet" 2>&1 | Out-Null
            }
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell Digital Delivery ---
Write-Log "Processing Dell Digital Delivery..."
$dellDD = $allDellApps | Where-Object { $_.DisplayName -like "Dell Digital Delivery*" }
ForEach ($dd in $dellDD) {
    Write-Log "Uninstalling: $($dd.DisplayName)"
    If ($dd.QuietUninstallString) {
        try {
            cmd.exe /c $dd.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell Optimizer (non-core) ---
Write-Log "Processing Dell Optimizer..."
$dellOpt = $allDellApps | Where-Object { 
    ($_.DisplayName -like "Dell Optimizer*" -or $_.DisplayName -like "DellOptimizerUI") -and 
    $_.DisplayName -notlike "*Core*" 
}
ForEach ($opt in $dellOpt) {
    Write-Log "Uninstalling: $($opt.DisplayName)"
    If ($opt.QuietUninstallString) {
        try {
            cmd.exe /c $opt.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
    ElseIf ($opt.UninstallString) {
        try {
            cmd.exe /c "$($opt.UninstallString) -silent" 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell Power Manager ---
Write-Log "Processing Dell Power Manager..."
$dellPM = $allDellApps | Where-Object { $_.DisplayName -like "Dell Power Manager*" -or $_.DisplayName -like "Dell Command*Power*" }
ForEach ($pm in $dellPM) {
    Write-Log "Uninstalling: $($pm.DisplayName)"
    If ($pm.QuietUninstallString) {
        try {
            cmd.exe /c $pm.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell Display Manager ---
Write-Log "Processing Dell Display Manager..."
$dellDM = $allDellApps | Where-Object { $_.DisplayName -like "Dell*Display*Manager*" }
ForEach ($dm in $dellDM) {
    Write-Log "Uninstalling: $($dm.DisplayName)"
    If ($dm.UninstallString) {
        try {
            cmd.exe /c "$($dm.UninstallString) /S" 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#--- Dell Peripheral Manager ---
Write-Log "Processing Dell Peripheral Manager..."
$peripheralPath = "C:\Program Files\Dell\Dell Peripheral Manager\Uninstall.exe"
if (Test-Path $peripheralPath) {
    Write-Log "Uninstalling: Dell Peripheral Manager"
    try {
        Start-Process -FilePath $peripheralPath -ArgumentList "/S" -Wait -NoNewWindow
        Write-Log "  -> Uninstall initiated successfully."
    }
    catch {
        Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
    }
}

#--- Dell Pair ---
Write-Log "Processing Dell Pair..."
$pairPath = "C:\Program Files\Dell\Dell Pair\Uninstall.exe"
if (Test-Path $pairPath) {
    Write-Log "Uninstalling: Dell Pair"
    try {
        Start-Process -FilePath $pairPath -ArgumentList "/S" -Wait -NoNewWindow
        Write-Log "  -> Uninstall initiated successfully."
    }
    catch {
        Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
    }
}

#--- Dell Trusted Device ---
Write-Log "Processing Dell Trusted Device..."
$dellTD = $allDellApps | Where-Object { $_.DisplayName -like "Dell Trusted Device*" }
ForEach ($td in $dellTD) {
    Write-Log "Uninstalling: $($td.DisplayName)"
    If ($td.QuietUninstallString) {
        try {
            cmd.exe /c $td.QuietUninstallString 2>&1 | Out-Null
            Write-Log "  -> Uninstall initiated successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

# Wait for uninstallers to complete
Write-Log "Waiting 30 seconds for native uninstallers to complete..."
Start-Sleep -Seconds 30

#endregion

#region -------- Dell Appx/MSIX Removal --------

Write-Log "Processing Dell Appx packages..."

$dellAppxPackages = @(
    "DellInc.PartnerPromo"
    "DellInc.DellOptimizer"
    "DellInc.DellCommandUpdate"
    "DellInc.DellPowerManager"
    "DellInc.DellDigitalDelivery"
    "DellInc.DellSupportAssistforPCs"
)

foreach ($appx in $dellAppxPackages) {
    # Remove provisioned package
    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $appx }
    if ($provisioned) {
        Write-Log "Removing provisioned package: $appx"
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction SilentlyContinue | Out-Null
            Write-Log "  -> Removed successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }

    # Remove installed package for all users
    $installed = Get-AppxPackage -AllUsers -Name $appx
    if ($installed) {
        Write-Log "Removing Appx package: $appx"
        try {
            Remove-AppxPackage -Package $installed.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            Write-Log "  -> Removed successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#endregion

#region -------- Dell Scheduled Tasks Cleanup (Post-Uninstall) --------

Write-Log "Cleaning up Dell scheduled tasks..."

$dellTaskFolders = @(
    '\Dell\',
    '\Dell\SupportAssistAgent\',
    '\Dell\CommandUpdate\',
    '\Dell\DellCustomerConnect\'
)

foreach ($taskFolder in $dellTaskFolders) {
    try {
        $tasks = Get-ScheduledTask -TaskPath $taskFolder -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            Write-Log "Removing scheduled task: $($task.TaskPath)$($task.TaskName)"
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "  -> Removed successfully."
            }
            catch {
                Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
            }
        }
    }
    catch {
        # Task folder may not exist, that's OK
    }
}

#endregion

#region -------- Optional Folder Cleanup --------

Write-Log "Cleaning up residual Dell folders..."

$foldersToClean = @(
    'C:\Program Files\Dell\SupportAssistAgent',
    'C:\Program Files\Dell\CommandUpdate',
    'C:\Program Files\Dell\Dell Optimizer',
    'C:\Program Files (x86)\Dell\CommandUpdate',
    'C:\ProgramData\Dell\SARemediation'
)

foreach ($folder in $foldersToClean) {
    if (Test-Path $folder) {
        Write-Log "Removing folder: $folder"
        try {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "  -> Removed successfully."
        }
        catch {
            Write-Log "  -> Failed: $($_.Exception.Message)" "WARN"
        }
    }
}

#endregion

#region -------- Intune Inventory Reset (Optional) --------

Write-Log "Resetting Intune inventory flag..."

$registryPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\InventorySetting"
$valueName = "FirstTimeSwitch"

try {
    if (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $registryPath -Name $valueName -Force -ErrorAction SilentlyContinue
        Write-Log "Intune IME inventory value removed successfully."
    }
}
catch {
    Write-Log "Intune inventory reset: $($_.Exception.Message)" "WARN"
}

#endregion

#region -------- Final Summary --------

Write-Log "=== Dell Bloatware Removal Complete ==="
Write-Log "Log saved to: $LogPath"

# Check what's remaining
$remainingDell = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -like "*Dell*" } |
    Select-Object DisplayName, DisplayVersion

if ($remainingDell) {
    Write-Log "Remaining Dell applications (may be whitelisted or require reboot):"
    foreach ($app in $remainingDell) {
        Write-Log "  - $($app.DisplayName) ($($app.DisplayVersion))"
    }
} else {
    Write-Log "No Dell applications remaining in registry."
}

Stop-Transcript | Out-Null

#endregion
