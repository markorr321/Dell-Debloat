<#
.SYNOPSIS
    Safely removes Dell SupportAssist applications.

.DESCRIPTION
    Targets only Dell SupportAssist apps using the safe registry method
    instead of Win32_Product (which is slow and triggers MSI repairs).

.NOTES
    Version:        1.0
    Date:           2026-01-21
#>

#Requires -RunAsAdministrator

# Logging
$LogPath = "C:\Windows\Temp\Remove-DellSupportAssist_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogPath -Force | Out-Null

Write-Host "=== Dell SupportAssist Removal ===" -ForegroundColor Cyan
Write-Host "Using safe registry method (not Win32_Product)" -ForegroundColor Gray
Write-Host ""

# Query registry (fast, no side effects)
$registryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$apps = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.DisplayName -like "*SupportAssist*" -or 
        $_.DisplayName -like "*Dell Support*" 
    }

if (-not $apps) {
    Write-Host "No Dell SupportAssist applications found." -ForegroundColor Green
    Stop-Transcript | Out-Null
    exit 0
}

Write-Host "Found $($apps.Count) application(s) to remove:" -ForegroundColor Yellow
$apps | ForEach-Object { Write-Host "  - $($_.DisplayName)" -ForegroundColor White }
Write-Host ""

# Uninstall each app using native uninstaller
foreach ($app in $apps) {
    Write-Host "Uninstalling $($app.DisplayName) ..." -ForegroundColor Yellow
    
    try {
        if ($app.QuietUninstallString) {
            # Preferred: Use quiet uninstall string
            Write-Host "  Using QuietUninstallString" -ForegroundColor Gray
            cmd.exe /c $app.QuietUninstallString 2>&1 | Out-Null
            Write-Host "  -> Success" -ForegroundColor Green
        }
        elseif ($app.UninstallString) {
            # Fallback: Use standard uninstall string with silent switches
            Write-Host "  Using UninstallString with /silent" -ForegroundColor Gray
            
            if ($app.UninstallString -match "msiexec") {
                # MSI package
                $uninstallCmd = $app.UninstallString -replace "/I", "/X"
                cmd.exe /c "$uninstallCmd /quiet /norestart" 2>&1 | Out-Null
            }
            else {
                # EXE installer
                cmd.exe /c "$($app.UninstallString) /silent /quiet /S" 2>&1 | Out-Null
            }
            Write-Host "  -> Success" -ForegroundColor Green
        }
        else {
            Write-Host "  -> No uninstall string found" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  -> Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Removal Complete ===" -ForegroundColor Cyan
Write-Host "Log: $LogPath" -ForegroundColor Gray

Stop-Transcript | Out-Null
