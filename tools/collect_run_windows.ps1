# ==============================================================================
# A6: Windows Evidence Collection Orchestrator
# Project: Real-Time Fileless Malware Detection
# Usage:
#   Interactive: .\tools\collect_run_windows.ps1
#   Automated:   .\tools\collect_run_windows.ps1 -Category powershell_fileless -OutputDir "C:\FMD-Transfer"
#   Transfer:    .\tools\collect_run_windows.ps1 -Category powershell_fileless -Transfer
# ==============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Category,

    [Parameter(Mandatory=$false)]
    [string]$OutputDir,

    [Parameter(Mandatory=$false)]
    [string]$DumpItPath,

    [Parameter(Mandatory=$false)]
    [switch]$SkipMemory,

    [Parameter(Mandatory=$false)]
    [string]$Notes = "",

    [Parameter(Mandatory=$false)]
    [switch]$NoElevation,

    [Parameter(Mandatory=$false)]
    [switch]$Transfer,

    [Parameter(Mandatory=$false)]
    [string]$KaliHost = "192.168.100.10",

    [Parameter(Mandatory=$false)]
    [string]$KaliUser = "fmd",

    [Parameter(Mandatory=$false)]
    [string]$KaliDest = "~/fmd-results/custom/",

    [Parameter(Mandatory=$false)]
    [string]$PythonCmd
)

$ErrorActionPreference = "Stop"

function Write-StateHeader {
    param([string]$State, [string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor $Color
    Write-Host " [STATE: $State] - $Message" -ForegroundColor $Color
    Write-Host ("=" * 72) -ForegroundColor $Color
    Write-Host ""
}

# ------------------------------------------------------------------------------
# STEP 0: ADMINISTRATOR PRIVILEGE VERIFICATION & SAFE SELF-ELEVATION
# ------------------------------------------------------------------------------
$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[-] Administrator privileges are required for Sysmon EVTX export and memory acquisition." -ForegroundColor Red
    if (-not $NoElevation) {
        Write-Host "[*] Attempting safe relaunch with Administrator privileges..." -ForegroundColor Yellow
        try {
            $ScriptPath = $MyInvocation.MyCommand.Definition
            $ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
            foreach ($param in $PSBoundParameters.GetEnumerator()) {
                if ($param.Value -is [switch]) {
                    if ($param.Value.IsPresent) { $ArgumentList += " -$($param.Key)" }
                } else {
                    $ArgumentList += " -$($param.Key) `"$($param.Value)`""
                }
            }
            $elevatedProc = Start-Process powershell.exe -ArgumentList $ArgumentList -Verb RunAs -PassThru
            exit 0
        } catch {
            Write-Host "[-] Elevation request was declined or failed: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[-] Elevation declined (-NoElevation specified). Halting." -ForegroundColor Red
        exit 1
    }
}

# Resolve Repository Root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
if (-not (Test-Path (Join-Path $RepoRoot "data\raw\custom\categories.json"))) {
    if (Test-Path ".\categories.json") {
        $CategoriesPath = ".\categories.json"
    } elseif (Test-Path (Join-Path $ScriptDir "..\data\raw\custom\categories.json")) {
        $CategoriesPath = (Join-Path $ScriptDir "..\data\raw\custom\categories.json")
    } else {
        $CategoriesPath = $null
    }
} else {
    $CategoriesPath = Join-Path $RepoRoot "data\raw\custom\categories.json"
}

# ------------------------------------------------------------------------------
# STEP 1: READY STATE & RUN ALLOCATION WITH LEDGER
# ------------------------------------------------------------------------------
Write-StateHeader "READY" "Initializing Windows Evidence Collector" ([ConsoleColor]::Green)

# Detect/Normalize Python Launcher (preferring py -3 over python to bypass Windows Store alias)
if (-not $PythonCmd) {
    try {
        & py -3 -c "import sys; sys.exit(0)" 2>$null
        if ($LASTEXITCODE -eq 0) { $PythonCmd = "py -3" }
    } catch {}
}
if (-not $PythonCmd) {
    try {
        & py -c "import sys; sys.exit(0)" 2>$null
        if ($LASTEXITCODE -eq 0) { $PythonCmd = "py" }
    } catch {}
}
if (-not $PythonCmd) {
    try {
        $pyExe = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($pyExe -and $pyExe.Source -notlike "*WindowsApps*") {
            & python -c "import sys; sys.exit(0)" 2>$null
            if ($LASTEXITCODE -eq 0) { $PythonCmd = "python" }
        }
    } catch {}
}
if ($PythonCmd) {
    Write-Host "[+] Python Launcher   : $PythonCmd" -ForegroundColor Green
} else {
    Write-Host "[*] Python Launcher   : Pure PowerShell mode" -ForegroundColor Gray
}

# Load Categories
if (-not $CategoriesPath -or -not (Test-Path $CategoriesPath)) {
    Write-Host "[-] Could not find categories.json at $CategoriesPath." -ForegroundColor Red
    Write-Host "[-] Using embedded category definitions." -ForegroundColor Yellow
    $Categories = @(
        @{ name = "benign"; track = "BENIGN"; run_range = @(1100, 1299); binary_label = 0; family = "benign" }
        @{ name = "powershell_fileless"; track = "TRACK_A"; run_range = @(2, 99); binary_label = 1; family = "powershell_fileless" }
        @{ name = "process_hollowing"; track = "TRACK_A"; run_range = @(100, 199); binary_label = 1; family = "process_hollowing" }
        @{ name = "memory_only_rat"; track = "TRACK_A"; run_range = @(200, 299); binary_label = 1; family = "memory_only_rat" }
        @{ name = "registry_resident_malware"; track = "TRACK_A"; run_range = @(300, 399); binary_label = 1; family = "registry_resident_malware" }
        @{ name = "cobalt_strike_beacon"; track = "TRACK_A"; run_range = @(400, 499); binary_label = 1; family = "cobalt_strike_beacon" }
        @{ name = "metasploit_memory_payloads"; track = "TRACK_A"; run_range = @(500, 599); binary_label = 1; family = "metasploit_memory_payloads" }
        @{ name = "wmi_malware"; track = "TRACK_B"; run_range = @(600, 699); binary_label = 1; family = "wmi_malware" }
        @{ name = "reflective_dll_injection"; track = "TRACK_B"; run_range = @(700, 799); binary_label = 1; family = "reflective_dll_injection" }
        @{ name = "lolbins_abuse"; track = "TRACK_B"; run_range = @(800, 899); binary_label = 1; family = "lolbins_abuse" }
        @{ name = "fileless_ransomware"; track = "TRACK_B"; run_range = @(900, 999); binary_label = 1; family = "fileless_ransomware" }
        @{ name = "empire_framework"; track = "TRACK_B"; run_range = @(1000, 1099); binary_label = 1; family = "empire_framework" }
    )
} else {
    $CategoriesJson = Get-Content -Raw -Path $CategoriesPath | ConvertFrom-Json
    $Categories = $CategoriesJson.categories
}

# Select Category if not passed
if (-not $Category) {
    Write-Host "Select Experiment Category:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Categories.Count; $i++) {
        $cat = $Categories[$i]
        $rStr = "RUN-{0:D3}..RUN-{1:D3}" -f $cat.run_range[0], $cat.run_range[1]
        Write-Host ("  [{0,2}] {1,-28} (Track: {2,-7}, Range: {3})" -f ($i + 1), $cat.name, $cat.track, $rStr)
    }
    Write-Host ""
    $Selection = Read-Host "Enter category number (1-12)"
    $Idx = [int]$Selection - 1
    if ($Idx -lt 0 -or $Idx -ge $Categories.Count) {
        Write-StateHeader "FAILED" "Invalid category selection: $Selection" ([ConsoleColor]::Red)
        exit 1
    }
    $SelectedCat = $Categories[$Idx]
} else {
    $SelectedCat = $Categories | Where-Object { $_.name -ieq $Category }
    if (-not $SelectedCat) {
        Write-StateHeader "FAILED" "Unknown category '$Category'" ([ConsoleColor]::Red)
        exit 1
    }
}

# Resolve Base Output Directory
if (-not $OutputDir) {
    if (Test-Path "C:\FMD-Transfer") {
        $OutputDir = "C:\FMD-Transfer"
    } elseif ($RepoRoot -and (Test-Path (Join-Path $RepoRoot "data\raw\custom"))) {
        $OutputDir = Join-Path $RepoRoot ("data\raw\custom\" + $SelectedCat.name)
    } else {
        $OutputDir = ".\custom_runs"
    }
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

# Persistent Run Allocation Ledger
$LedgerPath = $null
if ($RepoRoot -and (Test-Path (Join-Path $RepoRoot "data\raw\custom"))) {
    $LedgerPath = Join-Path $RepoRoot "data\raw\custom\allocated_runs.json"
} elseif (Test-Path (Join-Path $OutputDir "allocated_runs.json")) {
    $LedgerPath = Join-Path $OutputDir "allocated_runs.json"
} else {
    $LedgerPath = Join-Path $OutputDir "allocated_runs.json"
}

$ExistingIds = @(1) # Always reserve RUN-001

# Read existing ledger if present
$LedgerData = $null
if (Test-Path $LedgerPath) {
    try {
        $LedgerData = Get-Content -Raw -Path $LedgerPath | ConvertFrom-Json
        if ($LedgerData.runs) {
            foreach ($prop in $LedgerData.runs.PSObject.Properties) {
                $entry = $prop.Value
                if ($entry.run_number) {
                    $ExistingIds += [int]$entry.run_number
                }
            }
        }
    } catch {
        Write-Host "[-] Warning: Could not read ledger at ${LedgerPath}: $_" -ForegroundColor Yellow
    }
}

# Scan file system for existing RUN directories
$ExistingRunDirs = Get-ChildItem -Directory -Path $OutputDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^RUN-(\d+)$' }
foreach ($d in $ExistingRunDirs) {
    if ($d.Name -match '^RUN-(\d+)$') {
        $ExistingIds += [int]$Matches[1]
    }
}

if ($RepoRoot -and (Test-Path (Join-Path $RepoRoot "data\raw\custom"))) {
    $RepoCustomDirs = Get-ChildItem -Recurse -Directory -Path (Join-Path $RepoRoot "data\raw\custom") -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^RUN-(\d+)$' }
    foreach ($d in $RepoCustomDirs) {
        if ($d.Name -match '^RUN-(\d+)$') {
            $ExistingIds += [int]$Matches[1]
        }
    }
}

# Deduplicate
$ExistingIds = $ExistingIds | Select-Object -Unique

# Allocate next unused ID within category range
$RunRange = $SelectedCat.run_range
$AllocatedNum = $null
$AllocatedRunId = $null

for ($num = [int]$RunRange[0]; $num -le [int]$RunRange[1]; $num++) {
    if ($ExistingIds -notcontains $num) {
        $AllocatedNum = $num
        $AllocatedRunId = ("RUN-{0:D3}" -f $num)
        break
    }
}

if (-not $AllocatedRunId) {
    Write-StateHeader "FAILED" "Exhausted allocated range for category $($SelectedCat.name)" ([ConsoleColor]::Red)
    exit 1
}

$RunDir = Join-Path $OutputDir $AllocatedRunId
if (Test-Path $RunDir) {
    Write-StateHeader "FAILED" "Collision protection: Run directory already exists at $RunDir" ([ConsoleColor]::Red)
    exit 1
}

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

# Update ledger atomically with ALLOCATED status
try {
    if (-not $LedgerData) {
        $LedgerData = [PSCustomObject]@{
            version = "1.0.0"
            updated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            runs = [PSCustomObject]@{
                "RUN-001" = [PSCustomObject]@{
                    run_id = "RUN-001"
                    run_number = 1
                    category = "benign"
                    allocation_timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    status = "RESERVED_BASELINE"
                    evidence_location = "data/raw/custom/RUN-001"
                }
            }
        }
    }
    $newEntry = [PSCustomObject]@{
        run_id = $AllocatedRunId
        run_number = $AllocatedNum
        category = $SelectedCat.name
        allocation_timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        status = "ALLOCATED"
        evidence_location = $RunDir
    }
    $LedgerData.runs | Add-Member -NotePropertyName $AllocatedRunId -NotePropertyValue $newEntry -Force
    $LedgerData.updated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $LedgerData | ConvertTo-Json -Depth 5 | Set-Content -Path $LedgerPath -Encoding UTF8
    Write-Host "[+] Persistent ledger updated: $LedgerPath" -ForegroundColor Green
} catch {
    Write-Host "[-] Warning: Failed to update ledger: $_" -ForegroundColor Yellow
}

Write-Host "[+] Category    : $($SelectedCat.name)" -ForegroundColor Green
Write-Host "[+] Track       : $($SelectedCat.track)" -ForegroundColor Green
Write-Host "[+] RUN ID      : $AllocatedRunId" -ForegroundColor Green
Write-Host "[+] Target Dir  : $RunDir" -ForegroundColor Green

# ------------------------------------------------------------------------------
# STEP 2: COLLECTING STATE
# ------------------------------------------------------------------------------
Write-StateHeader "COLLECTING" "Experiment execution phase" ([ConsoleColor]::Yellow)

$CollectionStartTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "[*] Collection window opened at: $CollectionStartTime" -ForegroundColor Yellow
Write-Host "[*] SAFETY NOTICE: The orchestrator does NOT execute malware or payloads." -ForegroundColor Cyan
Write-Host "[*] Please start your authorized, controlled activity inside this isolated VM now." -ForegroundColor Cyan
Write-Host ""
Write-Host "Press [ENTER] when the activity is running and ready for CAPTURE..." -ForegroundColor Green
[void][System.Console]::ReadLine()

# ------------------------------------------------------------------------------
# STEP 3: CAPTURE STATE
# ------------------------------------------------------------------------------
Write-StateHeader "CAPTURE" "Capturing live telemetry and memory state" ([ConsoleColor]::Magenta)

# 1. Export Sysmon Event Log
$SysmonEvtxPath = Join-Path $RunDir "sysmon.evtx"
$SysmonAvailable = $false
try {
    Write-Host "[*] Exporting Sysmon event logs..." -ForegroundColor Cyan
    $SysmonLog = "Microsoft-Windows-Sysmon/Operational"
    $Wevtutil = "$env:SystemRoot\System32\wevtutil.exe"
    if (Test-Path $Wevtutil) {
        & $Wevtutil epl $SysmonLog $SysmonEvtxPath /ow:true 2>$null
        if ((Test-Path $SysmonEvtxPath) -and (Get-Item $SysmonEvtxPath).Length -gt 0) {
            $SysmonAvailable = $true
            Write-Host "    [+] Sysmon logs exported successfully: $SysmonEvtxPath" -ForegroundColor Green
        } else {
            Write-Host "    [-] Sysmon channel empty or not active." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "    [-] Failed to export Sysmon: $_" -ForegroundColor Yellow
}

# 2. Export PowerShell Event Log
$PSEvtxPath = Join-Path $RunDir "powershell.evtx"
try {
    Write-Host "[*] Exporting PowerShell operational logs..." -ForegroundColor Cyan
    $PSLog = "Microsoft-Windows-PowerShell/Operational"
    if (Test-Path $Wevtutil) {
        & $Wevtutil epl $PSLog $PSEvtxPath /ow:true 2>$null
        if ((Test-Path $PSEvtxPath) -and (Get-Item $PSEvtxPath).Length -gt 0) {
            Write-Host "    [+] PowerShell logs exported: $PSEvtxPath" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "    [-] PowerShell export warning: $_" -ForegroundColor Yellow
}

# 3. Capture Live Processes and Network Snapshot
try {
    Write-Host "[*] Capturing live process list snapshot..." -ForegroundColor Cyan
    $ProcCsvPath = Join-Path $RunDir "process_snapshot.csv"
    Get-Process | Select-Object Id, ProcessName, Path, StartTime, CPU, WorkingSet64 | Export-Csv -Path $ProcCsvPath -NoTypeInformation
    Write-Host "    [+] Process snapshot saved: $ProcCsvPath" -ForegroundColor Green
} catch {
    Write-Host "    [-] Process snapshot warning: $_" -ForegroundColor Yellow
}

try {
    Write-Host "[*] Capturing live network connections snapshot..." -ForegroundColor Cyan
    $NetCsvPath = Join-Path $RunDir "network_connections.csv"
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Export-Csv -Path $NetCsvPath -NoTypeInformation
    Write-Host "    [+] Network connections snapshot saved: $NetCsvPath" -ForegroundColor Green
} catch {
    Write-Host "    [-] Network connections snapshot warning: $_" -ForegroundColor Yellow
}

# 4. Volatile Memory Dump Acquisition
$MemoryDumpPresent = $false
$MemoryStatus = "SKIPPED"

if (-not $SkipMemory) {
    Write-Host "[*] Checking for DumpIt installation..." -ForegroundColor Cyan
    $CandidateDumpIt = @(
        @(
            $DumpItPath,
            "$env:USERPROFILE\Desktop\DumpIt\x64\DumpIt.exe",
            "$env:USERPROFILE\Desktop\DumpIt\DumpIt.exe",
            "C:\FMD-Collector\tools\DumpIt.exe",
            "C:\Tools\DumpIt\DumpIt.exe",
            "C:\FMD-Transfer\DumpIt.exe",
            ".\DumpIt.exe",
            (Get-Command DumpIt.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
        ) | Where-Object { 
            $_ -and (Test-Path -Path $_ -PathType Leaf) -and ((Split-Path $_ -Leaf) -ieq "DumpIt.exe") 
        }
    )

    $ResolvedDumpIt = $null
    if ($CandidateDumpIt.Count -gt 0) {
        $ResolvedDumpIt = $CandidateDumpIt[0]
    } else {
        # Recursive fallback search for DumpIt.exe under $env:USERPROFILE\Desktop\DumpIt
        $DesktopDumpItDir = "$env:USERPROFILE\Desktop\DumpIt"
        if ($DesktopDumpItDir -and (Test-Path -Path $DesktopDumpItDir -PathType Container)) {
            $FoundDumpIt = Get-ChildItem -Path $DesktopDumpItDir -Filter "DumpIt.exe" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq "DumpIt.exe" } | Select-Object -First 1
            if ($FoundDumpIt) {
                $ResolvedDumpIt = $FoundDumpIt.FullName
            }
        }
    }

    if ($ResolvedDumpIt) {
        $MemDumpPath = Join-Path $RunDir "memory.raw"
        Write-Host "    [+] Found DumpIt: $ResolvedDumpIt" -ForegroundColor Green
        Write-Host "    [*] Initiating volatile memory capture to $MemDumpPath..." -ForegroundColor Yellow
        try {
            $proc = Start-Process -FilePath $ResolvedDumpIt -ArgumentList "/O `"$MemDumpPath`" /Q" -Wait -PassThru -NoNewWindow
            if ((Test-Path $MemDumpPath) -and (Get-Item $MemDumpPath).Length -gt 0) {
                $MemoryDumpPresent = $true
                $MemoryStatus = "SUCCESS"
                Write-Host "    [+] MEMORY CAPTURE SUCCESS: $MemDumpPath" -ForegroundColor Green
            } elseif (Test-Path (Join-Path $RunDir "memory.dmp")) {
                $MemoryDumpPresent = $true
                $MemoryStatus = "SUCCESS"
                Write-Host "    [+] MEMORY CAPTURE SUCCESS: memory.dmp" -ForegroundColor Green
            } else {
                # Some DumpIt versions write to current working directory
                $DmpFiles = Get-ChildItem -Filter "*.raw" -Path (Split-Path -Parent $ResolvedDumpIt) -ErrorAction SilentlyContinue
                if ($DmpFiles.Count -gt 0 -and $DmpFiles[0].Length -gt 0) {
                    Move-Item -Path $DmpFiles[0].FullName -Destination $MemDumpPath -Force
                    $MemoryDumpPresent = $true
                    $MemoryStatus = "SUCCESS"
                    Write-Host "    [+] MEMORY CAPTURE SUCCESS: $MemDumpPath" -ForegroundColor Green
                } else {
                    $MemoryStatus = "FAILED"
                    Write-Host "    [-] MEMORY CAPTURE FAILED: Dump file not produced." -ForegroundColor Red
                }
            }
        } catch {
            $MemoryStatus = "FAILED"
            Write-Host "    [-] MEMORY CAPTURE FAILED: $_" -ForegroundColor Red
        }
    } else {
        $MemoryStatus = "FAILED"
        Write-Host "    [-] MEMORY CAPTURE FAILED: DumpIt executable not found." -ForegroundColor Red
    }

    # Strict check: If memory capture was required but failed, halt the run
    if ($MemoryStatus -eq "FAILED") {
        Write-StateHeader "FAILED" "Memory acquisition failed unexpectedly. Halting run." ([ConsoleColor]::Red)
        if ($LedgerData -and $LedgerPath) {
            $LedgerData.runs.$AllocatedRunId.status = "FAILED"
            $LedgerData | ConvertTo-Json -Depth 5 | Set-Content -Path $LedgerPath -Encoding UTF8
        }
        exit 1
    }
} else {
    $MemoryStatus = "SKIPPED"
    Write-Host "[*] MEMORY CAPTURE SKIPPED: User specified -SkipMemory flag." -ForegroundColor Yellow
}

# ------------------------------------------------------------------------------
# STEP 4: FINALIZING STATE & CANONICAL EVIDENCE SHA-256
# ------------------------------------------------------------------------------
Write-StateHeader "FINALIZING" "Computing canonical evidence hash and writing metadata" ([ConsoleColor]::Cyan)

# Canonical Directory Hashing Algorithm (delegates to canonical Python calculate_directory_evidence_sha256)
function Get-CanonicalDirectoryEvidenceSha256 {
    param(
        [string]$TargetDirectory,
        [string]$PythonLauncher = $PythonCmd
    )

    if (-not (Test-Path $TargetDirectory)) {
        throw "Target evidence directory does not exist: $TargetDirectory"
    }

    # Locate collection_orchestrator.py
    $OrchestratorScript = Join-Path $ScriptDir "collection_orchestrator.py"
    if (-not (Test-Path $OrchestratorScript) -and $RepoRoot) {
        $OrchestratorScript = Join-Path $RepoRoot "tools\collection_orchestrator.py"
    }
    if (-not (Test-Path $OrchestratorScript)) {
        if (Test-Path ".\tools\collection_orchestrator.py") {
            $OrchestratorScript = ".\tools\collection_orchestrator.py"
        } elseif (Test-Path ".\collection_orchestrator.py") {
            $OrchestratorScript = ".\collection_orchestrator.py"
        }
    }

    # Verify Python launcher is available
    if (-not $PythonLauncher) {
        throw "Python interpreter is not configured. Python 3.11+ is required for canonical evidence hashing."
    }
    if (-not (Test-Path $OrchestratorScript)) {
        throw "Could not find collection_orchestrator.py to compute canonical hash."
    }

    # Parse $PythonLauncher into executable and base arguments
    if ($PythonLauncher -match '^"([^"]+)"\s*(.*)$') {
        $pyExe = $Matches[1]
        $pyExtra = $Matches[2].Trim()
    } elseif ($PythonLauncher -match '^(\S+)\s*(.*)$') {
        $pyExe = $Matches[1]
        $pyExtra = $Matches[2].Trim()
    } else {
        $pyExe = $PythonLauncher
        $pyExtra = ""
    }

    $pyArgs = @()
    if ($pyExtra) {
        $pyArgs += ($pyExtra -split '\s+')
    }
    $resolvedDir = (Resolve-Path $TargetDirectory).Path
    $pyArgs += @($OrchestratorScript, "hash-evidence", $resolvedDir)

    Write-Host "[*] Invoking canonical Python hashing via: $PythonLauncher ..." -ForegroundColor Cyan
    $pyRawOutput = & $pyExe @pyArgs 2>&1
    $pyExitCode = $LASTEXITCODE

    $trimmedLines = @($pyRawOutput | Where-Object { $_ -and $_.ToString().Trim() -ne "" } | ForEach-Object { $_.ToString().Trim() })
    $lastLine = if ($trimmedLines.Count -gt 0) { $trimmedLines[-1] } else { "" }

    if ($pyExitCode -ne 0 -or $lastLine -notmatch '^[a-f0-9]{64}$') {
        $errDetails = ($trimmedLines -join "`n")
        throw "Canonical Python hashing failed (exit code $pyExitCode). Output:`n$errDetails"
    }

    return $lastLine.ToLowerInvariant()
}

try {
    $EvidenceSha256 = Get-CanonicalDirectoryEvidenceSha256 -TargetDirectory $RunDir -PythonLauncher $PythonCmd
    Write-Host "[+] Consolidated Canonical Evidence SHA-256: $EvidenceSha256" -ForegroundColor Green
} catch {
    Write-StateHeader "FAILED" "Canonical evidence hashing failed. Halting run." ([ConsoleColor]::Red)
    Write-Host "[-] $_" -ForegroundColor Red
    Write-Host "[*] Preserving all collected evidence in: $RunDir" -ForegroundColor Yellow
    if ($LedgerData -and $LedgerPath) {
        try {
            $LedgerData.runs.$AllocatedRunId.status = "FAILED"
            $LedgerData.updated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            $LedgerData | ConvertTo-Json -Depth 5 | Set-Content -Path $LedgerPath -Encoding UTF8
        } catch {}
    }
    exit 1
}

# Detect OS string
$OSInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = if ($OSInfo) { $OSInfo.Caption } else { "Windows 10" }
$OSClean = ($OSCaption.ToLower() -replace '\s+', '_') -replace '[^\w_]', ''

# Build metadata matching CustomCollectionMetadata schema
$Metadata = [PSCustomObject]@{
    sample_id            = "EXEC_$AllocatedRunId"
    label                = [int]$SelectedCat.binary_label
    family               = $SelectedCat.family
    track                = $SelectedCat.track
    os                   = $OSClean
    execution_timestamp  = $CollectionStartTime
    source_type          = "custom_sandbox"
    source_reference     = "manual_controlled_execution"
    evidence_sha256      = $EvidenceSha256
    memory_dump          = $MemoryDumpPresent
    sysmon_available     = $SysmonAvailable
    notes                = if ($Notes) { $Notes } else { "Controlled execution for $($SelectedCat.family)" }
}

$MetadataJsonPath = Join-Path $RunDir "metadata.json"
$Metadata | ConvertTo-Json -Depth 4 | Set-Content -Path $MetadataJsonPath -Encoding UTF8

Write-Host "[+] metadata.json written to: $MetadataJsonPath" -ForegroundColor Green

# Update ledger status to FINALIZED
if ($LedgerData -and $LedgerPath) {
    try {
        $LedgerData.runs.$AllocatedRunId.status = "FINALIZED"
        $LedgerData.updated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $LedgerData | ConvertTo-Json -Depth 5 | Set-Content -Path $LedgerPath -Encoding UTF8
    } catch {}
}

# ------------------------------------------------------------------------------
# STEP 5: OPTIONAL AUTOMATED TRANSFER (-Transfer)
# ------------------------------------------------------------------------------
$TransferSuccess = $null
if ($Transfer) {
    Write-StateHeader "TRANSFER" "Transferring evidence to Kali ($KaliHost)" ([ConsoleColor]::Yellow)
    $ScpCmd = Get-Command scp.exe -ErrorAction SilentlyContinue
    if (-not $ScpCmd) {
        $ScpCmd = Get-Command scp -ErrorAction SilentlyContinue
    }

    if ($ScpCmd) {
        Write-Host "[*] Executing SCP transfer: $RunDir -> ${KaliUser}@${KaliHost}:${KaliDest}" -ForegroundColor Cyan
        try {
            $destTarget = "${KaliUser}@${KaliHost}:${KaliDest}"
            & $ScpCmd.Source -r -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$RunDir" "$destTarget"
            if ($LASTEXITCODE -eq 0) {
                $TransferSuccess = $true
                Write-Host "[+] TRANSFER SUCCESS: Evidence delivered to ${KaliHost}:${KaliDest}" -ForegroundColor Green
                if ($LedgerData -and $LedgerPath) {
                    try {
                        $LedgerData.runs.$AllocatedRunId.status = "TRANSFERRED"
                        $LedgerData | ConvertTo-Json -Depth 5 | Set-Content -Path $LedgerPath -Encoding UTF8
                    } catch {}
                }
            } else {
                $TransferSuccess = $false
                Write-Host "[-] TRANSFER FAILED: SCP returned exit code $LASTEXITCODE" -ForegroundColor Red
            }
        } catch {
            $TransferSuccess = $false
            Write-Host "[-] TRANSFER FAILED: $_" -ForegroundColor Red
        }
    } else {
        $TransferSuccess = $false
        Write-Host "[-] TRANSFER FAILED: scp command not found on Windows host." -ForegroundColor Red
    }
}

# ------------------------------------------------------------------------------
# STEP 6: COMPLETE STATE
# ------------------------------------------------------------------------------
Write-StateHeader "COMPLETE" "Collection finished successfully" ([ConsoleColor]::Green)
Write-Host "[+] Run ID               : $AllocatedRunId" -ForegroundColor Green
Write-Host "[+] Run Directory        : $RunDir" -ForegroundColor Green
Write-Host "[+] Category             : $($SelectedCat.name)" -ForegroundColor Green
Write-Host "[+] Family               : $($SelectedCat.family)" -ForegroundColor Green
Write-Host "[+] Binary Label         : $($SelectedCat.binary_label)" -ForegroundColor Green
Write-Host "[+] Consolidated SHA256  : $EvidenceSha256" -ForegroundColor Green
Write-Host "[+] Memory Status        : $MemoryStatus" -ForegroundColor Green
if ($Transfer) {
    Write-Host "[+] Transfer Status      : $(if ($TransferSuccess) { 'SUCCESS' } else { 'FAILED' })" -ForegroundColor $(if ($TransferSuccess) { 'Green' } else { 'Red' })
}
Write-Host ""
Write-Host "NEXT STEP ON KALI (192.168.100.10):" -ForegroundColor Yellow
Write-Host "  ./tools/process_run_kali.sh $AllocatedRunId" -ForegroundColor Cyan
Write-Host ""
