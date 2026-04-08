# Anthropic Claude Co-Work MONACO MOD
# claude-cowork-deploy.ps1
# Rev 52.3
#
# .SYNOPSIS
#     Deploys Claude Desktop (MSIX) enterprise-wide via Intune / SCCM / PDQ.
#     Designed for split-account environments where end users are NOT local admins.
#
# .DESCRIPTION
#     - Checks C:\GI\Claude\Claude.msix against the latest release via SHA-256 hash.
#       If the local cached copy matches the latest, it is used directly (no download).
#       If the hashes differ (newer release available), the latest is downloaded,
#       the cache is updated, and installation proceeds.
#       If the download fails but a cache exists, the cache is used as a fallback.
#     - Removes any legacy Squirrel-based Claude install that would block MSIX
#     - Removes ALL per-user MSIX registrations (any version) before re-provisioning
#       to prevent stale ghost packages from overriding the newly provisioned version
#     - Removes any provisioned packages that differ from the version being installed
#     - Enables the Virtual Machine Platform feature required for Cowork
#     - Provisions the MSIX machine-wide (Add-AppxProvisionedPackage) so ALL
#       users on the device get Claude - no per-user UAC prompt needed
#     - Pins Claude to the taskbar for all existing and future users (Windows 11)
#     - Logs all activity to C:\GI\ClaudeDeploy.log
#
# .NOTES
#     Run context  : SYSTEM (Intune default) or an elevated admin account
#     Architecture : Script auto-detects x64 vs ARM64
#     Tested on    : Windows 11
#     Log location : C:\GI\ClaudeDeploy.log
#     MSIX cache   : C:\GI\Claude\Claude.msix  (kept up-to-date automatically)
#
#     NOTE: [CmdletBinding()] and param() blocks are intentionally omitted.
#     PDQ Deploy wraps scripts in its own Try{} block, which causes a parser
#     error if param() is present. All tuneable settings are in the
#     "Configuration" section below.
#
#     DEPLOY VIA PDQ:
#       Set package timeout to 1800 seconds (30 min) as a safety net.
#       PDQ runs as SYSTEM - ensure outbound HTTPS to claude.ai is permitted,
#       or pre-populate C:\GI\Claude\Claude.msix to skip the download.
#
#     DEPLOY VIA INTUNE:
#       Intune > Devices > Scripts > Add > Windows 10 and later
#         - Script file       : This file
#         - Run as account    : System
#         - Enforce sig check : No
#         - Run in 64-bit PS  : Yes

# --- Tuneable settings (replaces param block for PDQ compatibility) ----------
$MsixUrl      = ""          # Override download URL; leave empty for auto-detect
$SkipVmpEnable = $false     # Set $true to skip VirtualMachinePlatform check
$RebootPolicy  = "Suppress" # "Suppress" | "Force" | "None"

# --- Configuration -----------------------------------------------------------
$LogPath     = "C:\GI\ClaudeDeploy.log"
$TempDir     = "$env:TEMP\ClaudeDeploy"
$LocalCache  = "C:\GI\Claude\Claude.msix"
$MsixX64     = "https://claude.ai/api/desktop/win32/x64/msix/latest/redirect"
$MsixArm64   = "https://claude.ai/api/desktop/win32/arm64/msix/latest/redirect"
$PackageName        = "Claude"
$SquirrelExe        = "$env:LOCALAPPDATA\Programs\Claude\Update.exe"
$TaskbarXmlPath     = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
$TaskbarXmlDir      = Split-Path $TaskbarXmlPath
# AppUserModelID for the provisioned MSIX - used to pin for existing users
$ClaudeAUMID        = "AnthropicPBC.Claude_pzs8sxrjxfjjc!claude"

# --- Logging -----------------------------------------------------------------
function Write-Log {
    param([string]$Msg, [ValidateSet("INFO","WARN","ERROR")]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    Write-Host $line
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

# --- Appx helpers ------------------------------------------------------------
function Get-AllClaudeProvisioned {
    Write-Log "Querying provisioned packages..."
    $pkgs = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Claude*" -or $_.PackageName -like "*Claude*" }
    Write-Log "Found $(@($pkgs).Count) provisioned Claude package(s)."
    return $pkgs
}

function Get-AllClaudeAppx {
    Write-Log "Querying per-user AppxPackages (all users)..."
    $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*Claude*" -or $_.Name -like "*Anthropic*" }
    Write-Log "Found $(@($pkgs).Count) per-user Claude package(s)."
    return $pkgs
}

function Remove-AllClaudeAppx {
    $pkgs = Get-AllClaudeAppx
    if (-not $pkgs) {
        Write-Log "No per-user Claude packages to remove."
        return
    }
    foreach ($pkg in $pkgs) {
        Write-Log "Removing per-user package: $($pkg.PackageFullName)"
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log "Removed: $($pkg.PackageFullName)"
        } catch {
            Write-Log "Failed to remove $($pkg.PackageFullName): $_" "WARN"
        }
    }
}

function Remove-AllClaudeProvisioned {
    $pkgs = Get-AllClaudeProvisioned
    if (-not $pkgs) {
        Write-Log "No provisioned Claude packages to remove."
        return
    }
    foreach ($pkg in $pkgs) {
        Write-Log "Removing provisioned package: $($pkg.PackageName)"
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop
            Write-Log "Removed provisioned: $($pkg.PackageName)"
        } catch {
            Write-Log "Failed to remove provisioned $($pkg.PackageName): $_" "WARN"
        }
    }
}

function Get-FileSHA256 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

# --- PDQ compatibility -------------------------------------------------------
# PDQ Connect monitors stderr in real time and treats ANY error-stream output
# as a task failure, even when the exit code is 0.  Redirect the entire error
# stream to $null so non-terminating warnings/errors from Appx cmdlets never
# reach stderr.  Our own error handling uses explicit try/catch + Write-Log.
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$Error.Clear()

# --- Bootstrap ---------------------------------------------------------------
$null = New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force
$null = New-Item -ItemType Directory -Path $TempDir -Force
Write-Log "=== Claude Desktop Deployment Script Started (Rev 52.3) ==="
Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# --- 1. Detect architecture --------------------------------------------------
$arch = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
if ($arch -eq 12) {
    $DownloadUrl = if ($MsixUrl) { $MsixUrl } else { $MsixArm64 }
    Write-Log "Architecture: ARM64"
} else {
    $DownloadUrl = if ($MsixUrl) { $MsixUrl } else { $MsixX64 }
    Write-Log "Architecture: x64"
}

# --- 2. Enable Virtual Machine Platform (required for Cowork) ----------------
if (-not $SkipVmpEnable) {
    Write-Log "Checking Virtual Machine Platform feature..."
    $vmp = Get-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -ErrorAction SilentlyContinue
    if ($vmp -and $vmp.State -eq "Enabled") {
        Write-Log "VirtualMachinePlatform already enabled - skipping."
    } else {
        Write-Log "Enabling VirtualMachinePlatform..."
        try {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -All -NoRestart -ErrorAction Stop
            if ($result.RestartNeeded) {
                Write-Log "A restart is required to complete VirtualMachinePlatform enablement." "WARN"
                if ($RebootPolicy -eq "Force") {
                    Write-Log "RebootPolicy=Force - scheduling reboot and exiting."
                    shutdown /r /t 60 /c "Claude Desktop: VirtualMachinePlatform enabled, rebooting."
                    exit 0
                }
            } else {
                Write-Log "VirtualMachinePlatform enabled successfully."
            }
        } catch {
            Write-Log "Failed to enable VirtualMachinePlatform: $_" "WARN"
            Write-Log "Cowork may not function until this feature is enabled and the device is rebooted." "WARN"
        }
    }
} else {
    Write-Log "SkipVmpEnable=$true - skipping VirtualMachinePlatform step."
}

# --- 3. Remove legacy Squirrel-based Claude install --------------------------
Write-Log "Checking for legacy Squirrel-based Claude installation..."
$profileRoot   = "C:\Users"
$squirrelFound = $false
Get-ChildItem $profileRoot -Directory | ForEach-Object {
    $updateExe = Join-Path $_.FullName "AppData\Local\Programs\Claude\Update.exe"
    if (Test-Path $updateExe) {
        Write-Log "Found Squirrel install for user: $($_.Name) - uninstalling..."
        $squirrelFound = $true
        try {
            $proc = Start-Process -FilePath $updateExe -ArgumentList "--uninstall -s" -Wait -PassThru -ErrorAction Stop
            Write-Log "Squirrel uninstall exit code: $($proc.ExitCode)"
        } catch {
            Write-Log "Squirrel uninstall failed for $($_.Name): $_" "WARN"
        }
    }
}
if (-not $squirrelFound) { Write-Log "No Squirrel installation found." }

# --- 4. Resolve MSIX - use local cache or download latest --------------------
$msixPath = Join-Path $TempDir "Claude.msix"
$cacheDir = Split-Path $LocalCache
$useCache = $false
$null = New-Item -ItemType Directory -Path $cacheDir -Force

$cacheExists = Test-Path $LocalCache
Write-Log "Checking local MSIX cache: $LocalCache (exists: $cacheExists)"

Write-Log "Attempting to download latest MSIX from: $DownloadUrl"
$downloadOk = $false
try {
    Write-Log "Downloading via WebClient..."
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($DownloadUrl, $msixPath)
    $dlSize = (Get-Item $msixPath).Length
    Write-Log "Download complete. File size: $([math]::Round($dlSize/1MB,2)) MB"
    $downloadOk = $true
} catch {
    Write-Log "WebClient download failed: $_" "WARN"
    try {
        Write-Log "Trying Invoke-WebRequest as fallback..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $msixPath -UseBasicParsing -ErrorAction Stop
        $dlSize = (Get-Item $msixPath).Length
        Write-Log "Invoke-WebRequest download complete. File size: $([math]::Round($dlSize/1MB,2)) MB"
        $downloadOk = $true
    } catch {
        Write-Log "All download methods failed: $_" "WARN"
    }
}

# Determine whether a new version is available based on hash comparison
$newVersionAvailable = $false

if ($downloadOk) {
    if ($cacheExists) {
        $hashNew   = Get-FileSHA256 $msixPath
        $hashCache = Get-FileSHA256 $LocalCache
        Write-Log "Hash (downloaded) : $hashNew"
        Write-Log "Hash (cache)      : $hashCache"
        if ($hashNew -eq $hashCache) {
            Write-Log "Hashes match - cached file is current."
            $useCache = $true
        } else {
            Write-Log "Hashes differ - newer release detected. Updating cache."
            Copy-Item -Path $msixPath -Destination $LocalCache -Force
            Write-Log "Cache updated: $LocalCache"
            $newVersionAvailable = $true
        }
    } else {
        Write-Log "No cache found - seeding cache for future deployments."
        Copy-Item -Path $msixPath -Destination $LocalCache -Force
        Write-Log "Cache seeded: $LocalCache"
        $newVersionAvailable = $true
    }
} else {
    if ($cacheExists) {
        Write-Log "Using cached MSIX as fallback: $LocalCache" "WARN"
        Copy-Item -Path $LocalCache -Destination $msixPath -Force
        $useCache = $true
    } else {
        Write-Log "FATAL: Download failed and no local cache available at $LocalCache. Cannot proceed." "ERROR"
        exit 1
    }
}

$installSize = (Get-Item $msixPath).Length
Write-Log "MSIX ready ($([math]::Round($installSize/1MB,2)) MB) - source: $(if ($useCache -and -not $newVersionAvailable) { 'local cache (unchanged)' } else { 'fresh download' })"

# --- 5. Decide whether install/re-provision is needed -----------------------
#
# Always remove ALL per-user registrations and re-provision when:
#   (a) A newer version was downloaded (hash changed), OR
#   (b) Any per-user registration exists that doesn't match the provisioned version
#       (catches leftovers from prior partial installs or manual installs), OR
#   (c) No provisioned package is present at all.
#
# If hashes matched (same version already cached) AND provisioned package exists
# AND zero stale per-user registrations are present, skip re-provisioning.
# ---------------------------------------------------------------------------

Write-Log "Evaluating existing Claude installation state..."
$provisionedPkgs = Get-AllClaudeProvisioned
$perUserPkgs     = Get-AllClaudeAppx

$provisionedVersion = $null
if ($provisionedPkgs) {
    # Extract version from the first provisioned package name (format: Name_Version_Arch__PublisherId)
    $provisionedVersion = ($provisionedPkgs[0].PackageName -split '_')[1]
    Write-Log "Currently provisioned version: $provisionedVersion"
}

# Identify per-user packages whose version differs from what is provisioned
$stalePkgs = @()
if ($provisionedVersion) {
    $stalePkgs = @($perUserPkgs | Where-Object { ($_.PackageFullName -split '_')[1] -ne $provisionedVersion })
} else {
    $stalePkgs = @($perUserPkgs)
}

$needsInstall = $false
$reason       = ""

if ($newVersionAvailable) {
    $needsInstall = $true
    $reason = "newer MSIX version downloaded"
} elseif (-not $provisionedPkgs) {
    $needsInstall = $true
    $reason = "no provisioned Claude package found"
} elseif ($stalePkgs.Count -gt 0) {
    $needsInstall = $true
    $staleVersions = ($stalePkgs | ForEach-Object { ($_.PackageFullName -split '_')[1] }) -join ", "
    $reason = "stale per-user registration(s) detected at version(s): $staleVersions"
} else {
    Write-Log "Claude $provisionedVersion is already provisioned with no stale registrations - skipping re-install."
}

if (-not $needsInstall) {
    # Write success marker and exit cleanly
    Write-Log "Nothing to do."
    New-Item -ItemType File -Path "C:\GI\Claude\deploy.success" -Force | Out-Null
    Write-Log "Success marker written: C:\GI\Claude\deploy.success"
    Write-Log "=== Claude Desktop Deployment Script Completed ==="
    exit 0
}

Write-Log "Install required - reason: $reason"

# --- 6. Full cleanup: remove ALL per-user and provisioned Claude packages ----
Write-Log "--- Beginning full Claude package cleanup ---"

Write-Log "Step 6a: Removing ALL per-user Claude packages (all versions, all users)..."
Remove-AllClaudeAppx

Write-Log "Step 6b: Removing ALL provisioned Claude packages..."
Remove-AllClaudeProvisioned

# Brief pause to let the package store settle after removals
Write-Log "Waiting 5 seconds for package store to settle after cleanup..."
Start-Sleep -Seconds 5

# Confirm cleanup
$checkProv = Get-AllClaudeProvisioned
$checkAppx = Get-AllClaudeAppx
if ($checkProv -or $checkAppx) {
    Write-Log "WARNING: Some Claude packages could not be removed. Proceeding anyway - provisioning may overwrite them." "WARN"
    if ($checkProv) { foreach ($p in $checkProv) { Write-Log "  Remaining provisioned: $($p.PackageName)" "WARN" } }
    if ($checkAppx) { foreach ($p in $checkAppx) { Write-Log "  Remaining per-user:    $($p.PackageFullName)" "WARN" } }
} else {
    Write-Log "Cleanup confirmed - no residual Claude packages found."
}

# --- 7. Provision MSIX machine-wide -----------------------------------------
Write-Log "Provisioning MSIX for all users (Add-AppxProvisionedPackage)..."
try {
    $result = Add-AppxProvisionedPackage `
        -Online `
        -PackagePath $msixPath `
        -SkipLicense `
        -Regions "all" `
        -ErrorAction Stop

    Write-Log "Provisioning successful."
    if ($result.RestartNeeded) {
        Write-Log "A restart may be needed to complete provisioning." "WARN"
    }
} catch {
    Write-Log "FATAL: Add-AppxProvisionedPackage failed: $_" "ERROR"
    Write-Log "Common causes: AppLocker blocking MSIX, S-Mode, or insufficient permissions." "ERROR"
    exit 1
}

# --- 8. Verify installation --------------------------------------------------
Write-Log "Waiting 5 seconds for package store to propagate..."
Start-Sleep -Seconds 5

Write-Log "Verifying provisioned package..."
$verify = Get-AllClaudeProvisioned
if ($verify) {
    Write-Log "SUCCESS: Claude Desktop provisioned - Package: $($verify[0].PackageName)"
} else {
    Write-Log "WARNING: Could not confirm provisioned package. Manual verification recommended." "WARN"
    Write-Log "Tip: Run 'Get-AppxProvisionedPackage -Online | Where DisplayName -like *Claude*' to inspect." "WARN"
}

Write-Log "Verifying per-user AppxPackage registration (all users)..."
$allUsers = Get-AllClaudeAppx
if ($allUsers) {
    # Flag any version mismatch as a warning - should only be one version after clean install
    $newProvVersion = if ($verify) { ($verify[0].PackageName -split '_')[1] } else { $null }
    foreach ($pkg in $allUsers) {
        $pkgVer  = ($pkg.PackageFullName -split '_')[1]
        $userStr = ($pkg.PackageUserInformation | ForEach-Object { $_.UserSecurityId }) -join ", "
        if ($newProvVersion -and $pkgVer -ne $newProvVersion) {
            Write-Log "WARN: Unexpected version in per-user registration - Package: $($pkg.PackageFullName) | Users: $userStr" "WARN"
        } else {
            Write-Log "Per-user registration OK - Package: $($pkg.PackageFullName) | Users: $userStr"
        }
    }
} else {
    Write-Log "No per-user AppxPackage registrations found yet. Normal if no user has logged in since provisioning." "WARN"
}

# --- 9. Cleanup --------------------------------------------------------------
Write-Log "Cleaning up temp files..."
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# --- 10. Optional forced reboot -----------------------------------------------
if ($RebootPolicy -eq "Force") {
    Write-Log "RebootPolicy=Force - scheduling reboot in 60 seconds."
    shutdown /r /t 60 /c "Claude Desktop installation complete. Rebooting to finalize."
}

# --- 11. Write success marker for PDQ Connect detection ----------------------
Write-Log "Writing PDQ Connect success marker..."
New-Item -ItemType File -Path "C:\GI\Claude\deploy.success" -Force | Out-Null
Write-Log "Success marker written: C:\GI\Claude\deploy.success"

# --- 12. Taskbar pinning -----------------------------------------------------
#
# Two-pronged approach for Windows 11:
#
#   (a) Default User profile - LayoutModification.xml
#       Pins Claude for any user who has NOT yet logged in (new accounts,
#       freshly imaged machines). Survives reboots and new-user provisioning.
#
#   (b) Existing logged-in users - Shell32 COM pin via RunAs
#       Iterates all user profiles with an existing taskbar layout and pins
#       Claude using the Shell.Application COM object invoked in the user's
#       own session context via a scheduled task trick. This is the only
#       reliable way to mutate a live user taskbar from SYSTEM context on
#       Windows 11 without a Group Policy push.
#
# NOTE: Microsoft intentionally restricts taskbar mutation from outside the
# user session. The scheduled task approach below is the supported workaround
# for MDM/SCCM/PDQ deployments. Users CAN unpin Claude afterwards - this
# script will not re-pin on subsequent runs if it detects the xml is already
# present for that profile.
# ---------------------------------------------------------------------------

Write-Log "--- Taskbar pinning (Windows 11) ---"

# (a) Seed Default User profile for future logins
Write-Log "Step 12a: Writing LayoutModification.xml to Default User profile..."
$null = New-Item -ItemType Directory -Path $TaskbarXmlDir -Force

$xmlContent = @'
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Append">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:UWA AppUserModelID="AnthropicPBC.Claude_pzs8sxrjxfjjc!claude" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
'@

try {
    Set-Content -Path $TaskbarXmlPath -Value $xmlContent -Encoding UTF8 -Force
    Write-Log "LayoutModification.xml written: $TaskbarXmlPath"
} catch {
    Write-Log "Failed to write LayoutModification.xml: $_" "WARN"
}

# (b) Pin for existing user profiles via per-user scheduled task
Write-Log "Step 12b: Pinning Claude for existing user profiles..."

# Build a small PS script that performs the pin using Shell.Application
# This runs in the user's own session so it can touch their taskbar
$pinScriptBlock = @"
try {
    `$shell = New-Object -ComObject Shell.Application
    `$appPath = (Get-AppxPackage -Name '*Claude*' -ErrorAction SilentlyContinue |
        Select-Object -First 1 |
        ForEach-Object { `$_.InstallLocation })
    if (-not `$appPath) { exit 1 }
    `$exe = Join-Path `$appPath 'claude.exe'
    if (-not (Test-Path `$exe)) { exit 1 }
    `$folder = `$shell.Namespace((Split-Path `$exe))
    `$item   = `$folder.ParseName((Split-Path `$exe -Leaf))
    `$verbs  = `$item.Verbs()
    `$pin    = `$verbs | Where-Object { `$_.Name -match 'Pin to taskbar' }
    if (`$pin) { `$pin.DoIt() }
} catch { exit 1 }
exit 0
"@

$pinScriptPath = "$TempDir\PinClaude.ps1"
$null = New-Item -ItemType Directory -Path $TempDir -Force
Set-Content -Path $pinScriptPath -Value $pinScriptBlock -Encoding UTF8

$profileRoot = "C:\Users"
Get-ChildItem $profileRoot -Directory | ForEach-Object {
    $userFolder  = $_.FullName
    $userName    = $_.Name
    $ntuser      = Join-Path $userFolder "NTUSER.DAT"
    $taskbarDir  = Join-Path $userFolder "AppData\Local\Microsoft\Windows\Shell"
    $userXmlPath = Join-Path $taskbarDir "LayoutModification.xml"

    # Skip system pseudo-profiles
    if ($userName -in @("Default","Default User","Public","All Users")) { return }
    if (-not (Test-Path $ntuser)) { return }

    # If the user already has a LayoutModification.xml we wrote, skip
    # (avoids overwriting a user who has since customised their taskbar)
    if (Test-Path $userXmlPath) {
        Write-Log "Skipping $userName - LayoutModification.xml already present."
        return
    }

    Write-Log "Pinning Claude for existing user: $userName"

    # Write the layout XML into this user's shell dir as well
    $null = New-Item -ItemType Directory -Path $taskbarDir -Force
    try {
        Set-Content -Path $userXmlPath -Value $xmlContent -Encoding UTF8 -Force
        Write-Log "  LayoutModification.xml written for $userName"
    } catch {
        Write-Log "  Failed to write xml for ${userName}: $_" "WARN"
    }

    # Attempt live-session pin via a run-once scheduled task in the user's context
    # Resolve SID for the user account (domain or local)
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($userName)).Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Log "  Could not resolve SID for $userName - skipping live pin." "WARN"
        return
    }

    $taskName = "ClaudeTaskbarPin_$userName"
    $psArgs   = "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$pinScriptPath`""

    # Register a task that runs once as the user, then self-deletes
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><TimeTrigger><StartBoundary>$(
      (Get-Date).AddSeconds(30).ToString("yyyy-MM-ddTHH:mm:ss")
  )</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$sid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <DeleteExpiredTaskAfter>PT1H</DeleteExpiredTaskAfter>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$psArgs</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    try {
        Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force -ErrorAction Stop | Out-Null
        Write-Log "  Scheduled live-pin task registered for $userName (fires in ~30s, self-deletes after 1h)."
    } catch {
        Write-Log "  Failed to register scheduled task for ${userName}: $_" "WARN"
    }
}

Write-Log "Taskbar pinning steps complete."

# --- 13. Final exit -------------------------------------------------------------
# Clear $Error so PDQ Connect's wrapper check ($Error.WriteErrorStream) does not
# misinterpret non-terminating SilentlyContinue errors as a script failure.
$Error.Clear()
Write-Log "=== Claude Desktop Deployment Script Completed ==="
exit 0