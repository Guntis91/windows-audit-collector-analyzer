<#
Audit-Collector-Analyzer.ps1
============================

What this tool does
- Collects its own audit evidence (Event Logs + system snapshot)
- Saves everything into a timestamped session folder
- Analyzes the collected evidence for suspicious patterns
- Exports results (Summary.txt + Findings.csv)

Why this tool exists
- It does NOT depend on your Admin Toolkit logs
- It is a standalone audit + analysis tool
- Perfect for portfolio: shows collection, logging, detection, reporting

How to run
1) Open PowerShell as Administrator
2) Run:
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Audit-Collector-Analyzer.ps1

Safety
- Read-only for system state (does not change settings)
- Only creates files in the output folder
#>

# ------------------------------
# Global settings (easy to edit)
# ------------------------------

# This is where all audit sessions will be saved.
# Each run creates a new folder inside this root folder.
$Global:AuditRoot = "C:\AdminToolkit\AuditSessions"

# How many hours of Event Logs to collect by default (can be changed in menu).
$Global:DefaultHoursBack = 24

# ------------------------------
# Helper: Write a neat heading
# ------------------------------
function Write-Heading {
    param([string]$Text)

    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host $Text
    Write-Host ("=" * 70)
}

# ----------------------------------------------------------
# Helper: Ensure a folder exists (creates it if missing)
# ----------------------------------------------------------
function Ensure-Folder {
    param([string]$Path)

    # Test-Path checks if a file or folder exists at the path.
    if (-not (Test-Path $Path)) {
        # New-Item creates the folder. Out-Null hides the object output.
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

# ----------------------------------------------------------
# Helper: Read a menu choice safely (prevents invalid input)
# ----------------------------------------------------------
function Read-MenuChoice {
    param(
        [string]$Prompt,
        [int[]]$Allowed
    )

    while ($true) {
        $val = Read-Host $Prompt

        # This checks if the user typed a whole number.
        if ($val -match '^\d+$') {
            $num = [int]$val

            # This checks if the number is one of the allowed choices.
            if ($Allowed -contains $num) {
                return $num
            }
        }

        Write-Host "Invalid choice. Please select one of: $($Allowed -join ', ')" -ForegroundColor Yellow
    }
}

# ----------------------------------------------------------
# Helper: Create a new session folder (timestamp based)
# ----------------------------------------------------------
function New-AuditSessionFolder {

    # Create root folder if it does not exist.
    Ensure-Folder -Path $Global:AuditRoot

    # Create a timestamp string used in the folder name.
    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

    # Join-Path safely combines folder paths.
    $sessionPath = Join-Path $Global:AuditRoot $stamp

    # Create the session folder.
    Ensure-Folder -Path $sessionPath

    return $sessionPath
}

# ----------------------------------------------------------
# Helper: List sessions and let the user pick one
# ----------------------------------------------------------
function Select-AuditSession {

    Write-Heading "Select an Audit Session"

    if (-not (Test-Path $Global:AuditRoot)) {
        Write-Host "No audit sessions folder found at: $Global:AuditRoot" -ForegroundColor Yellow
        Write-Host "Run a collection first (Collect Evidence)." -ForegroundColor Yellow
        return $null
    }

    $sessions = Get-ChildItem -Path $Global:AuditRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending

    if (-not $sessions -or $sessions.Count -eq 0) {
        Write-Host "No audit sessions found." -ForegroundColor Yellow
        Write-Host "Run a collection first (Collect Evidence)." -ForegroundColor Yellow
        return $null
    }

    # Print a numbered list of session folders.
    for ($i = 0; $i -lt $sessions.Count; $i++) {
        Write-Host ("{0}. {1}" -f ($i + 1), $sessions[$i].Name)
    }
    Write-Host "0. Back"

    while ($true) {
        $choice = Read-Host "Choose session number"
        if ($choice -match '^\d+$') {
            $n = [int]$choice
            if ($n -eq 0) { return $null }
            if ($n -ge 1 -and $n -le $sessions.Count) {
                return $sessions[$n - 1].FullName
            }
        }
        Write-Host "Invalid session number. Try again." -ForegroundColor Yellow
    }
}

# ----------------------------------------------------------
# Collector: Export Event Logs (Security, System, Application)
# ----------------------------------------------------------
function Collect-EventLogs {
    param(
        [string]$SessionPath,
        [int]$HoursBack
    )

    Write-Heading "Collecting Event Logs"

    # Calculate start time for event log filter.
    $startTime = (Get-Date).AddHours(-1 * $HoursBack)

    # Create an output folder inside this session for event logs.
    $outFolder = Join-Path $SessionPath "EventLogs"
    Ensure-Folder -Path $outFolder

    # We collect three main logs (these exist on most servers).
    $logsToCollect = @("Security", "System", "Application")

    foreach ($logName in $logsToCollect) {
        try {
            Write-Host "Collecting $logName events since $startTime ..."

            # Get-WinEvent is the modern way to query Windows Event Logs.
            # FilterHashtable is faster than filtering after the fact.
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $startTime
            } -ErrorAction Stop

            # Export to CSV so it can be analyzed easily.
            # We select key fields that matter for investigations.
            $csvPath = Join-Path $outFolder ($logName + ".csv")
            $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            Write-Host "Saved: $csvPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Could not collect $logName log. Reason: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ----------------------------------------------------------
# Collector: Export a system snapshot (state at collection time)
# ----------------------------------------------------------
function Collect-SystemSnapshot {
    param([string]$SessionPath)

    Write-Heading "Collecting System Snapshot"

    $outFolder = Join-Path $SessionPath "Snapshot"
    Ensure-Folder -Path $outFolder

    try {
        # Save basic system info.
        (Get-ComputerInfo | Out-String) | Set-Content -Path (Join-Path $outFolder "ComputerInfo.txt") -Encoding UTF8

        # Save IP config.
        (ipconfig /all | Out-String) | Set-Content -Path (Join-Path $outFolder "IpConfig.txt") -Encoding UTF8

        # Save active TCP connections.
        (Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Sort-Object LocalPort | Format-Table -AutoSize | Out-String) |
            Set-Content -Path (Join-Path $outFolder "TcpConnections.txt") -Encoding UTF8

        # Save listening ports.
        (Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort | Format-Table -AutoSize | Out-String) |
            Set-Content -Path (Join-Path $outFolder "ListeningPorts.txt") -Encoding UTF8

        # Save service list.
        (Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName |
            Sort-Object Name | Export-Csv -Path (Join-Path $outFolder "Services.csv") -NoTypeInformation -Encoding UTF8)

        # Save firewall rule summary.
        (Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action, Profile |
            Export-Csv -Path (Join-Path $outFolder "FirewallRules.csv") -NoTypeInformation -Encoding UTF8)

        Write-Host "Snapshot collected successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Snapshot collection error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ----------------------------------------------------------
# Analyzer: Simple pattern-based detections from Event Logs
# ----------------------------------------------------------
function Analyze-Session {
    param([string]$SessionPath)

    Write-Heading "Analyzing Session (Suspicious Patterns)"

    if (-not (Test-Path $SessionPath)) {
        Write-Host "Session folder not found." -ForegroundColor Yellow
        return
    }

    $eventFolder = Join-Path $SessionPath "EventLogs"
    if (-not (Test-Path $eventFolder)) {
        Write-Host "No EventLogs folder found in this session. Collect evidence first." -ForegroundColor Yellow
        return
    }

    # Output folder for analysis results.
    $analysisFolder = Join-Path $SessionPath "Analysis"
    Ensure-Folder -Path $analysisFolder

    # Files used in analysis.
    $securityCsv = Join-Path $eventFolder "Security.csv"
    $systemCsv   = Join-Path $eventFolder "System.csv"

    # This list will hold all findings (easy to export later).
    $findings = New-Object System.Collections.Generic.List[object]

    # ------------------------
    # Detection 1: Failed logon
    # ------------------------
    # Common Security Event IDs:
    # 4625 = failed logon
    # 4624 = successful logon
    if (Test-Path $securityCsv) {
        $sec = Import-Csv $securityCsv

        # Grab failed logon events by ID (4625).
        $failed = $sec | Where-Object { $_.Id -eq "4625" }

        # Group by message (rough) or just count total as a starting point.
        if ($failed.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Finding  = "Failed logons detected (Event ID 4625)"
                Count    = $failed.Count
                Detail   = "Review Security.csv for repeated failures. Consider password spraying/brute force."
                Source   = "Security.csv"
            })
        }

        # Optional: detect new user creation (4720) or group membership changes (4728/4732).
        $newUser = $sec | Where-Object { $_.Id -eq "4720" }
        if ($newUser.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Finding  = "New user accounts created (Event ID 4720)"
                Count    = $newUser.Count
                Detail   = "Verify if user creation was approved. Check who created accounts."
                Source   = "Security.csv"
            })
        }

        $adminGroup = $sec | Where-Object { $_.Id -in @("4728","4732","4756") }
        if ($adminGroup.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Finding  = "Group membership changes detected (4728/4732/4756)"
                Count    = $adminGroup.Count
                Detail   = "Possible privilege changes. Validate changes and check affected groups."
                Source   = "Security.csv"
            })
        }
    } else {
        $findings.Add([pscustomobject]@{
            Severity="Low"
            Finding="Security.csv missing"
            Count=0
            Detail="Security events were not collected. Run collection as Administrator."
            Source="EventLogs"
        })
    }

    # --------------------------
    # Detection 2: Service events
    # --------------------------
    # System Event IDs vary by service manager/provider, so we do a simple keyword approach.
    if (Test-Path $systemCsv) {
        $sys = Import-Csv $systemCsv

        $serviceKeywords = $sys | Where-Object {
            ($_.Message -match 'service') -and
            ($_.Message -match 'stopped|terminated|disabled|failed|crash')
        }

        if ($serviceKeywords.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Finding  = "Service stop/failure keywords detected in System log"
                Count    = $serviceKeywords.Count
                Detail   = "Review System.csv for service failures or unexpected stops."
                Source   = "System.csv"
            })
        }
    }

    # --------------------------
    # Export results
    # --------------------------
    $findingsCsv = Join-Path $analysisFolder "Findings.csv"
    $summaryTxt  = Join-Path $analysisFolder "Summary.txt"

    # Export CSV (easy to open in Excel).
    $findings | Export-Csv -Path $findingsCsv -NoTypeInformation -Encoding UTF8

    # Build a simple text summary.
    $summary = New-Object System.Collections.Generic.List[string]
    $summary.Add("Audit Session Analysis Summary")
    $summary.Add("==============================")
    $summary.Add("")
    $summary.Add("Session: $SessionPath")
    $summary.Add("Generated: " + (Get-Date))
    $summary.Add("")
    $summary.Add("Findings count: " + $findings.Count)
    $summary.Add("")

    foreach ($f in $findings) {
        $summary.Add("Severity: " + $f.Severity)
        $summary.Add("Finding: " + $f.Finding)
        $summary.Add("Count: " + $f.Count)
        $summary.Add("Source: " + $f.Source)
        $summary.Add("Detail: " + $f.Detail)
        $summary.Add("")
    }

    $summary | Set-Content -Path $summaryTxt -Encoding UTF8

    Write-Host "Saved: $findingsCsv" -ForegroundColor Green
    Write-Host "Saved: $summaryTxt" -ForegroundColor Green

    # Show basic results on screen too.
    Write-Heading "Findings (Quick View)"
    if ($findings.Count -eq 0) {
        Write-Host "No findings detected." -ForegroundColor Green
    } else {
        $findings | Format-Table -AutoSize
    }
}

# ----------------------------------------------------------
# Main menu loop (simple and clear)
# ----------------------------------------------------------
function Start-MainMenu {

    Ensure-Folder -Path $Global:AuditRoot

    $hoursBack = $Global:DefaultHoursBack
    $lastSession = $null

    while ($true) {

        Write-Heading "Audit Collector + Analyzer (Standalone)"
        Write-Host "Audit root: $Global:AuditRoot"
        Write-Host "Hours back for event log collection: $hoursBack"
        Write-Host ("Last collected session: " + ($lastSession ? $lastSession : "None"))
        Write-Host ""

        Write-Host "1  Collect Evidence (Event Logs + System Snapshot)"
        Write-Host "2  Analyze a Session (pick from list)"
        Write-Host "3  Change Hours Back (Event Logs)"
        Write-Host "4  Open Audit Root Folder (Explorer)"
        Write-Host "0  Exit"
        Write-Host ""

        $choice = Read-MenuChoice -Prompt "Choose" -Allowed @(0,1,2,3,4)

        switch ($choice) {

            1 {
                # Create a new session folder for this collection run.
                $session = New-AuditSessionFolder
                $lastSession = $session

                # Collect evidence into that session folder.
                Collect-EventLogs -SessionPath $session -HoursBack $hoursBack
                Collect-SystemSnapshot -SessionPath $session

                Write-Host ""
                Write-Host "Collection complete. Session saved to:" -ForegroundColor Green
                Write-Host $session -ForegroundColor Green
                Read-Host "Press ENTER to continue" | Out-Null
            }

            2 {
                $session = Select-AuditSession
                if ($session) {
                    Analyze-Session -SessionPath $session
                }
                Read-Host "Press ENTER to continue" | Out-Null
            }

            3 {
                Write-Heading "Change Hours Back"
                Write-Host "Current: $hoursBack"
                $val = Read-Host "Enter hours back (example: 6, 24, 72)"
                if ($val -match '^\d+$') {
                    $hoursBack = [int]$val
                    Write-Host "Updated hours back to $hoursBack." -ForegroundColor Green
                } else {
                    Write-Host "Invalid number. Hours back not changed." -ForegroundColor Yellow
                }
                Read-Host "Press ENTER to continue" | Out-Null
            }

            4 {
                # Open audit folder in Windows Explorer.
                Start-Process explorer.exe $Global:AuditRoot
            }

            0 {
                Write-Host "Goodbye."
                return
            }
        }
    }
}

# Start the tool
Start-MainMenu
