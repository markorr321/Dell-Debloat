# Dell SupportAssist Removal - Best Practices

## Summary

The original Dell removal script (`Enforce-Remove-Dell-Apps.ps1`) was causing **CRITICAL_PROCESS_DIED (0xEF)** blue screen errors on Windows devices during Intune remediation deployment. The root cause was identified as the script's approach of forcibly stopping Dell services and killing Dell processes *before* initiating the uninstall process. Dell SupportAssist includes kernel-mode drivers (such as `dcdbas.sys` and `DSAPI.sys`) that communicate with user-mode services. When the script terminated these services and processes prematurely, the kernel-mode drivers were left in an orphaned state—still loaded in kernel memory but unable to communicate with their user-mode components. Windows detected this as a critical system process failure, resulting in a stop error.

The solution is to remove the process and service termination steps entirely and instead rely on Dell's native `QuietUninstallString` found in the registry. Dell's own uninstaller knows the correct shutdown sequence to safely stop services, unload kernel drivers, and remove files without destabilizing the system. The corrected scripts (`Remove-DellSupportAssist.ps1` and `Remove-DellBloat.ps1`) use this registry-based approach, querying `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` for Dell applications and executing their built-in quiet uninstall commands.

Additionally, the `Win32_Product` WMI class should be avoided for application enumeration and uninstallation. When queried, `Win32_Product` performs a consistency check on every MSI-installed application on the system, which can take several minutes and generates hundreds of Event ID 1035 entries in the Application log. Microsoft explicitly advises against using this class, stating it is "not query optimized." Beyond the performance impact, calling the `.Uninstall()` method bypasses the application's native uninstaller and invokes a generic MSI removal, which may not properly handle kernel drivers, services, or cleanup tasks that the vendor's uninstaller would normally perform. The registry-based approach is faster, has no side effects, and uses the application's intended removal process.

---

## Why Use the Registry Path

When you install an application on Windows, the installer writes an entry to the registry under:

- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`
- `HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*` (for 32-bit apps)

Each entry contains metadata including `QuietUninstallString` or `UninstallString`—the exact command the vendor designed to remove their software.

### The Registry Method Is Best Because:

#### 1. It calls the vendor's own uninstaller
- Dell wrote their uninstaller to properly stop services, unload kernel drivers, remove files, and clean up
- The vendor knows their product's dependencies and shutdown sequence

#### 2. It's fast
- Directly reads registry keys (milliseconds)
- No scanning or enumeration of all installed software

#### 3. It has no side effects
- Just reads data—doesn't trigger anything else
- No MSI consistency checks, no repairs, no log spam

#### 4. It works for all installer types
- MSI packages, EXE installers, vendor-specific installers
- `Win32_Product` only sees MSI-installed apps

---

## Comparison

| Method | Speed | Side Effects | Uses Native Uninstaller |
|--------|-------|--------------|------------------------|
| Registry + QuietUninstallString | ⚡ Fast | ✅ None | ✅ Yes |
| Win32_Product | 🐌 Minutes | ❌ MSI reconfiguration on ALL apps | ❌ Generic MSI removal |
| Kill processes then uninstall | ⚡ Fast | ❌ **BSOD risk** | ❌ Orphans drivers |

---

## Bottom Line

The registry gives you the exact uninstall command the vendor intended you to use—run that and nothing else.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `Remove-DellSupportAssist.ps1` | Removes only Dell SupportAssist applications |
| `Remove-DellBloat.ps1` | Removes all Dell bloatware applications |

## References

- [Microsoft: Win32_Product is not query optimized](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-product)
- Stop Code 0xEF: CRITICAL_PROCESS_DIED
