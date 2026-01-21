<#
    Application: Dell App Cleanup (Target-Only, Approved-Verbs)
    Packaged by: nbrady@firstam.com
    Updated: 2025-11-27
    Purpose: Remove only the explicitly listed Dell apps (e.g., "Dell Command | Update"), without touching other Dell software.
    Context: Designed for Intune/SYSTEM execution; idempotent.

    Key Safeguards:
    - NO generic "*Dell*" matching anywhere
    - Only items matching $AppTargets are processed
    - Appx/MSIX removal restricted to target names/identities (no publisher wildcard)
    - Folder deletion limited to sanitized-name equality with targets
    - Final registry cleanup scoped to targets only

    NOTE: Requires administrative privileges.
#>

#region -------- Configuration --------

# Define ONLY the apps you want removed. Everything else is untouched.
$AppTargets = @(
    # Core examples (adjust to your needs)
    'Dell Command | Update', 
    'Dell Command Update', 
    'Dell-Command-Update', 
    'DellCommandUpdate',
    'Dell Command | Update for Windows Universal',
    'Dell Optimizer', 
    'Dell-Optimizer',
    'Dell Optimizer Core',
    'Dell SupportAssist', 
    'Dell Support Assist', 
    'SupportAssist',
    'Dell SupportAssist Remediation', 
    'SupportAssist Remediation',
    "Dell Support Assist for Business PC's",
    'Dell Digital Delivery',
    'Dell Digital Delivery Services',
    'Dell Update', 
    'Dell Update for Windows 10',
    'Dell Trusted Device',

    # Store (Appx/MSIX) identities (family/package names)
    'DellInc.DellCommandUpdate',
    'DellInc.DellOptimizer',
    'DellInc.DellSupportAssistforPCs',
    'DellInc.DellDigitalDelivery'
)

# Optional Dell task paths we’ll check, but we will remove tasks ONLY if the task name/path matches targets.
$ScheduledTaskFolders = @(
    '\Dell',
    '\Dell\SupportAssistAgent',
    '\Dell\CommandUpdate',
    '\Dell\DellCustomerConnect'
)

# Root folders to scan (we remove ONLY subfolders whose sanitized name equals a sanitized target)
$FolderRoots = @(
    'C:\Program Files\Dell',
    'C:\Program Files (x86)\Dell',
    'C:\ProgramData\Dell'
)

# Intune IME inventory reset flag (keeps your original behavior)
$ResetIntuneInventorySetting = $true

#endregion

#region -------- Logging / Helpers --------

$LogDir = 'C:\Windows\Temp'
if (!(Test-Path -LiteralPath $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogPath = Join-Path $LogDir "DellAppCleanup_$Timestamp.log"

try {
    Start-Transcript -Path $LogPath -Force | Out-Null
}
catch {
    # If transcript can't start (already running, etc.), continue without failing
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'u'), $Level.ToUpper(), $Message
    Write-Output $line
}

function ConvertTo-RegexEscapedString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    return [Regex]::Escape($Text)
}

function ConvertTo-SafeFileName {
    [CmdletBinding()]
    param([string]$Name)
    if (-not $Name) { return $Name }
    # Remove characters illegal in file/folder names, normalize whitespace
    return ($Name -replace '[<>:"/\\|?*]', '') -replace "\s+", ' '
}

function Test-GuidString {
    [CmdletBinding()]
    param([string]$Text)
    return $Text -match '^\{?[0-9A-Fa-f]{8}(-?[0-9A-Fa-f]{4}){3}-?[0-9A-Fa-f]{12}\}?$'
}

function Get-TargetUnionRegex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Targets)
    $parts = $Targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertTo-RegexEscapedString -Text $_ }
    if ($parts.Count -eq 0) { return $null }
    # Non-anchored union: matches substring anywhere (safe because we escape)
    return '(?:' + ($parts -join '|') + ')'
}

# Build global regex & sanitized target set for exact folder matches
$script:TargetUnionRegex = Get-TargetUnionRegex -Targets $AppTargets
$script:SanitizedTargets = $AppTargets | ForEach-Object { ConvertTo-SafeFileName -Name $_ } | Where-Object { $_ -and $_.Trim() -ne '' } | Sort-Object -Unique

# Helper to run a process with a timeout, so we don't hang forever on a bad uninstaller
function Invoke-ProcessWithTimeout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Arguments,
        [int]$TimeoutSeconds = 600 # 10 minutes default
    )

    $result = [PSCustomObject]@{
        Started   = $false
        ExitCode  = $null
        TimedOut  = $false
        Exception = $null
    }

    try {
        Write-Log "Starting process with timeout $TimeoutSeconds sec: `"$FilePath`" $Arguments"

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi

        $null = $proc.Start()
        $result.Started = $true

        # WaitForExit returns $true if process exits, $false on timeout
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $result.TimedOut = $true
            Write-Log "Process timed out after $TimeoutSeconds seconds. Killing: `"$FilePath`"" "WARN"
            try {
                $proc.Kill()
            }
            catch {
                Write-Log "Failed to kill timed-out process: $($_.Exception.Message)" "WARN"
            }
        }

        # We still try to read ExitCode (may be 0 if it exited just in time)
        try {
            $result.ExitCode = $proc.ExitCode
        }
        catch {
            $result.ExitCode = $null
        }
    }
    catch {
        $result.Exception = $_.Exception
        Write-Log "Error starting process `"$FilePath`": $($result.Exception.Message)" "WARN"
    }

    return $result
}

# Safe wrapper for Get-ScheduledTask with timeout using a background job
function Get-ScheduledTasksSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TaskPath,
        [int]$TimeoutSeconds = 20
    )

    try {
        Write-Log "Querying scheduled tasks for path '$TaskPath' with timeout $TimeoutSeconds sec..."
        $job = Start-Job -ScriptBlock {
            param($tp)
            Import-Module ScheduledTasks -ErrorAction SilentlyContinue
            Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue
        } -ArgumentList $TaskPath

        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds

        if (-not $completed) {
            Write-Log "Get-ScheduledTask timed out for path '$TaskPath'. Skipping this folder." "WARN"
            Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            return @()
        }

        $tasks = Receive-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        return $tasks
    }
    catch {
        Write-Log "Get-ScheduledTasksSafe error for path '$TaskPath': $($_.Exception.Message)" "WARN"
        return @()
    }
}

#endregion

#region -------- Pre-Uninstall Quiescing (Target-Scoped) --------

function Stop-TargetProcesses {
    [CmdletBinding()]
    param()
    if (-not $script:TargetUnionRegex) { return }
    Write-Log "Stopping target-matching processes under Dell paths (if any)..."
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Path -and ($_.Path -like "C:\Program Files*\Dell\*") -and ($_.Path -imatch $script:TargetUnionRegex)
        } | ForEach-Object {
            Write-Log "Stopping process: $($_.ProcessName) ($($_.Id)) from $($_.Path)"
            try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    catch {
        Write-Log "Process enumeration error: $($_.Exception.Message)" "WARN"
    }
}

function Stop-TargetServices {
    [CmdletBinding()]
    param()
    if (-not $script:TargetUnionRegex) { return }
    Write-Log "Stopping services whose Name/DisplayName match targets (best-effort)..."
    try {
        $services = Get-Service | Where-Object { $_.Name -imatch $script:TargetUnionRegex -or $_.DisplayName -imatch $script:TargetUnionRegex }
        foreach ($svc in $services) {
            if ($svc.Status -in @('Running', 'StartPending')) {
                Write-Log "Stopping service: $($svc.Name) ($($svc.DisplayName))"
                try { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
    catch {
        Write-Log "Service enumeration error: $($_.Exception.Message)" "WARN"
    }
}

function Remove-TargetScheduledTasks {
    [CmdletBinding()]
    param()
    if (-not $script:TargetUnionRegex) { return }

    Write-Log "Removing scheduled tasks ONLY if TaskPath/TaskName matches targets (with timeout)..."

    foreach ($folder in $ScheduledTaskFolders) {
        try {
            $tasks = Get-ScheduledTasksSafe -TaskPath $folder -TimeoutSeconds 20
            if (-not $tasks -or $tasks.Count -eq 0) { continue }

            $tasks |
            Where-Object {
                $_.TaskName -imatch $script:TargetUnionRegex -or
                $_.TaskPath -imatch $script:TargetUnionRegex
            } |
            ForEach-Object {
                Write-Log "Deleting scheduled task: $($_.TaskPath)$($_.TaskName)"
                try {
                    Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "Failed to delete scheduled task $($_.TaskPath)$($_.TaskName): $($_.Exception.Message)" "WARN"
                }
            }
        }
        catch {
            Write-Log "Scheduled task handling error for folder '$folder': $($_.Exception.Message)" "WARN"
        }
    }
}

#endregion

#region -------- Uninstall Engines (Target-Only) --------

function Get-UninstallEntries {
    [CmdletBinding()]
    param()
    $roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    # Optional: per-user (HKU) uninstall keys – best effort, may be empty under SYSTEM
    try {
        $userSids = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-' }
        foreach ($sid in $userSids) {
            $roots += @(
                "HKU:\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            )
        }
    }
    catch {}

    $entries = foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue
        }
    }
    return $entries
}

function Invoke-UninstallFromKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Key,     # RegistryKey
        [switch]$ForceQuiet
    )
    try {
        $displayName = $Key.GetValue('DisplayName', $null)
        $uninstallStr = $Key.GetValue('UninstallString', $null)
        $quietStr = $Key.GetValue('QuietUninstallString', $null)
        $psChildName = $Key.PSChildName

        if (-not $displayName -and -not $uninstallStr) { return $false }

        Write-Log "Attempting uninstall: DisplayName='$displayName' Key='$psChildName'"

        # Prefer QuietUninstallString if present
        $candidate = if ($quietStr) { $quietStr } elseif ($uninstallStr) { $uninstallStr } else { $null }
        if (-not $candidate -and (Test-GuidString $psChildName)) {
            $candidate = "msiexec.exe /x $psChildName"
        }
        if (-not $candidate) {
            Write-Log "No uninstall string or GUID found for '$displayName'" "WARN"
            return $false
        }

        # Break into exe and arguments safely (handles quoted paths)
        $ExePath = $null
        $ExecArgs = $null
        if ($candidate.StartsWith('"')) {
            $firstQuoteEnd = $candidate.IndexOf('"', 1)
            if ($firstQuoteEnd -gt 1) {
                $ExePath = $candidate.Substring(1, $firstQuoteEnd - 1)
                $ExecArgs = $candidate.Substring($firstQuoteEnd + 1).Trim()
            }
        }
        if (-not $ExePath) {
            $parts = $candidate.Split(' ', 2)
            $ExePath = $parts[0]
            $ExecArgs = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        }

        # Normalize msiexec handling and enforce quiet
        $isMsiExec = ($ExePath -imatch 'msiexec(\.exe)?$')
        if ($isMsiExec) {
            if ($ExecArgs -notmatch '/[XxIi]\s*\{?[0-9A-Fa-f-]{36,38}\}?') {
                $ExecArgs = $ExecArgs -replace '/[Ii]\b', '/X'
            }
            if ($ForceQuiet -or ($ExecArgs -notmatch '/q')) {
                $ExecArgs = "$ExecArgs /qn /norestart"
            }
        }
        else {
            $hasQuiet = $ExecArgs -match '(/quiet|/qn|/s(?!\w)|\s-S\b|\s/S\b)'
            if ($ForceQuiet -or -not $hasQuiet) {
                $ExecArgs = ($ExecArgs + ' /quiet /norestart').Trim()
            }
        }

        Write-Log "Uninstall command: `"$ExePath`" $ExecArgs"

        # Use timeout-based execution so we don't hang the entire remediation
        $procResult = Invoke-ProcessWithTimeout -FilePath $ExePath -Arguments $ExecArgs -TimeoutSeconds 600

        if (-not $procResult.Started) {
            Write-Log "Failed to start uninstall process for '$displayName'." "WARN"
            return $false
        }

        if ($procResult.TimedOut) {
            Write-Log "Uninstall for '$displayName' timed out. Marking as failed but continuing script." "WARN"
            return $false
        }

        if ($procResult.ExitCode -eq 0) {
            Write-Log "Uninstall succeeded for '$displayName' (exit code 0)."
            return $true
        }
        else {
            $exit = if ($procResult.ExitCode -ne $null) { $procResult.ExitCode } else { 'N/A' }
            Write-Log "Primary uninstall reported exit code $exit for '$displayName'." "WARN"

            # Fallback only for non-MSI EXEs if primary attempt failed
            if (-not $isMsiExec -and $ExePath) {
                $FallbackArgsList = @('/S', '/s', '/verysilent /norestart', '/silent /norestart')
                foreach ($FallbackArgs in $FallbackArgsList) {
                    Write-Log "Trying fallback switches for '$displayName': $FallbackArgs"
                    $fbResult = Invoke-ProcessWithTimeout -FilePath $ExePath -Arguments $FallbackArgs -TimeoutSeconds 600
                    if ($fbResult.Started -and -not $fbResult.TimedOut -and $fbResult.ExitCode -eq 0) {
                        Write-Log "Fallback uninstall succeeded for '$displayName'."
                        return $true
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Uninstall error for key '$($Key.PSChildName)': $($_.Exception.Message)" "ERROR"
    }
    return $false
}

#endregion

#region -------- Appx/MSIX Removal (Target-Only) --------

function Remove-TargetAppx {
    [CmdletBinding()]
    param([string]$TargetRegex)
    if (-not $TargetRegex) { return @() }
    $removed = @()

    # Remove ONLY packages whose Name/Family/DisplayName match the target regex
    try {
        $pkgs = Get-AppxPackage -AllUsers | Where-Object { 
            $_.Name -imatch $TargetRegex -or $_.PackageFamilyName -imatch $TargetRegex -or $_.DisplayName -imatch $TargetRegex
        }
        foreach ($pkg in $pkgs) {
            Write-Log "Removing Appx for all users: $($pkg.Name) ($($pkg.PackageFullName))"
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                $removed += $pkg.PackageFullName
            }
            catch {
                Write-Log "Failed to remove Appx $($pkg.PackageFullName): $($_.Exception.Message)" "WARN"
            }
        }
    }
    catch {
        Write-Log "Appx enumeration error: $($_.Exception.Message)" "WARN"
    }

    # De-provision ONLY provisioned packages that match the target regex
    try {
        $prov = Get-AppxProvisionedPackage -Online | Where-Object { 
            $_.DisplayName -imatch $TargetRegex -or $_.PackageName -imatch $TargetRegex 
        }
        foreach ($p in $prov) {
            Write-Log "Removing provisioned package: $($p.DisplayName) ($($p.PackageName))"
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Log "Failed to remove provisioned $($p.PackageName): $($_.Exception.Message)" "WARN"
            }
        }
    }
    catch {
        Write-Log "Provisioned Appx enumeration error: $($_.Exception.Message)" "WARN"
    }

    return $removed
}

#endregion

#region -------- Folder Cleanup (Target-Only) --------

function Remove-TargetFolders {
    [CmdletBinding()]
    param(
        [string[]]$Roots,
        [string[]]$SanitizedTargets
    )
    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dirName = $_.Name
            $sanDir = ConvertTo-SafeFileName -Name $dirName
            if ($SanitizedTargets -contains $sanDir) {
                try {
                    Write-Log "Removing folder: $($_.FullName)"
                    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "Failed to remove folder $($_.FullName): $($_.Exception.Message)" "WARN"
                }
            }
        }
    }
}

#endregion

#region -------- Main Execution --------

Write-Log "=== Dell App Cleanup (Target-Only) starting ==="
Write-Log "Log: $LogPath"

# Pre-uninstall quiescing (strictly target-matched)
Stop-TargetProcesses
Stop-TargetServices
Remove-TargetScheduledTasks

# Uninstall keys matching ONLY the targets
$entries = Get-UninstallEntries
$matchedKeys = @()
if ($script:TargetUnionRegex) {
    foreach ($key in $entries) {
        try {
            $dn = $key.GetValue('DisplayName', $null)
            if (-not $dn) { continue }
            if ($dn -imatch $script:TargetUnionRegex) { $matchedKeys += $key }
        }
        catch { }
    }
}
$matchedKeys = $matchedKeys | Sort-Object PSChildName -Unique

$uninstalled = @()
foreach ($k in $matchedKeys) {
    $ok = Invoke-UninstallFromKey -Key $k -ForceQuiet
    if ($ok) { $uninstalled += $k.GetValue('DisplayName', $k.PSChildName) }
}

# Appx/MSIX cleanup (target-only)
$appxRemoved = Remove-TargetAppx -TargetRegex $script:TargetUnionRegex

# Folder cleanup (target-only)
Remove-TargetFolders -Roots $FolderRoots -SanitizedTargets $script:SanitizedTargets

# Final registry scrubs ONLY for matched targets (no "*Dell*" broad matches)
try {
    $finalKeys = Get-UninstallEntries | Where-Object {
        $dn = $_.GetValue('DisplayName', $null)
        $dn -and ($dn -imatch $script:TargetUnionRegex)
    }
    foreach ($fk in $finalKeys) {
        Write-Log "Residual uninstall key found, removing: $($fk.PSChildName) [$($fk.GetValue('DisplayName','(no name)'))]"
        try { Remove-Item -LiteralPath $fk.PSPath -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
}
catch {
    Write-Log "Final registry cleanup encountered errors: $($_.Exception.Message)" "WARN"
}

# Optional: Reset Intune IME inventory flag so next scan runs fresh
if ($ResetIntuneInventorySetting) {
    $registryPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\InventorySetting"
    $valueName = "FirstTimeSwitch"
    try {
        $val = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
        if ($val) {
            Remove-ItemProperty -Path $registryPath -Name $valueName -Force -ErrorAction SilentlyContinue
            Write-Log "Intune IME inventory value '$valueName' removed successfully."
        }
        else {
            Write-Log "Intune IME inventory value '$valueName' not present (OK)."
        }
    }
    catch {
        Write-Log "IME inventory flag cleanup warning: $($_.Exception.Message)" "WARN"
    }
}

# Final report: show remaining uninstall entries matching your targets (not all Dell)
Write-Log "=== Remaining uninstall entries that match your targets ==="
try {
    $remaining = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" ,
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.GetValue('DisplayName', $null) -imatch $script:TargetUnionRegex } |
    ForEach-Object {
        [PSCustomObject]@{
            DisplayName    = $_.GetValue('DisplayName', '')
            DisplayVersion = $_.GetValue('DisplayVersion', '')
            Publisher      = $_.GetValue('Publisher', '')
            Key            = $_.PSChildName
        }
    }
    if ($remaining) {
        $remaining | Sort-Object DisplayName | Format-Table -AutoSize | Out-String | Write-Output
    }
    else {
        Write-Log "None."
    }
}
catch {
    Write-Log "Failed to enumerate remaining uninstall entries: $($_.Exception.Message)" "WARN"
}

Write-Log "Uninstalled (best-effort): $($uninstalled -join '; ' )"
if ($appxRemoved -and $appxRemoved.Count -gt 0) {
    Write-Log "Removed Appx (best-effort): $($appxRemoved -join '; ')"
}

Write-Log "=== Dell App Cleanup (Target-Only) complete ==="
try {
    Stop-Transcript | Out-Null
}
catch {
    # If transcript wasn't started or already stopped, ignore
}

#endregion