<#
Audit-Collector-Analyzer.ps1
============================

Purpose
- Standalone Audit Collector + Analyzer for Windows (PowerShell 5.1 compatible)
- Collects event logs and a system snapshot into timestamped sessions
- Analyzes the collected evidence for suspicious activity patterns
- Exports CSV + readable text reports with exact locations (file + time + event ID)

Key design goals
- Works on Windows Server 2022 default PowerShell (5.1)
- No ternary operators, no PowerShell 7-only syntax
- Read-only collection: does not modify system settings
- Easy to expand: detection rules are simple and clearly commented

How to run
1) Open PowerShell as Administrator (recommended for Security log access)
2) Run:
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Audit-Collector-Analyzer.ps1

Where output goes
C:\AdminToolkit\AuditSessions\<timestamp>\
  EventLogs\  (Security.csv, System.csv, Application.csv)
  Snapshot\   (ComputerInfo.txt, IpConfig.txt, ListeningPorts.txt, Services.csv, FirewallRules.csv, etc.)
  Analysis\   (Findings.csv, Summary.txt, Findings-Detailed.txt)

#>

# ------------------------------
# Global settings (easy to edit)
# ------------------------------

# Root folder where all sessions are stored (each run creates a timestamp folder).
$Global:AuditRoot = "C:\AdminToolkit\AuditSessions"

# Default hours back for event log collection.
$Global:DefaultHoursBack = 24

# Thresholds (you can tune these later)
$Global:FailedLogonThreshold = 3            # you asked for 3 so you can test easily
$Global:LockoutThreshold = 1                # any lockout is worth reviewing
$Global:NewUserThreshold = 1                # any new user creation is worth reviewing
$Global:AdminGroupChangeThreshold = 1       # any admin group changes are worth reviewing
$Global:ScheduledTaskCreateThreshold = 1    # any new scheduled task can be suspicious
$Global:ServiceInstallThreshold = 1         # any new service install can be suspicious

# ------------------------------
# Helper: Write headings neatly
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
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

# ----------------------------------------------------------
# Helper: Read menu choice safely (only allowed numbers)
# ----------------------------------------------------------
function Read-MenuChoice {
    param(
        [string]$Prompt,
        [int[]]$Allowed
    )

    while ($true) {
        $val = Read-Host $Prompt
        if ($val -match '^\d+$') {
            $num = [int]$val
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
    Ensure-Folder -Path $Global:AuditRoot
    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $sessionPath = Join-Path $Global:AuditRoot $stamp
    Ensure-Folder -Path $sessionPath
    return $sessionPath
}

# ----------------------------------------------------------
# Helper: List sessions and let the user pick one
# ----------------------------------------------------------
function Select-AuditSession {

    Write-Heading "Select an Audit Session"

    if (-not (Test-Path $Global:AuditRoot)) {
        Write-Host "No audit root found at: $Global:AuditRoot" -ForegroundColor Yellow
        Write-Host "Run collection first (option 1)." -ForegroundColor Yellow
        return $null
    }

    $sessions = Get-ChildItem -Path $Global:AuditRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending

    if (-not $sessions -or $sessions.Count -eq 0) {
        Write-Host "No sessions found. Run collection first." -ForegroundColor Yellow
        return $null
    }

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

    # This sets the start time for the event log query.
    $startTime = (Get-Date).AddHours(-1 * $HoursBack)

    # Create output folder for the event logs.
    $outFolder = Join-Path $SessionPath "EventLogs"
    Ensure-Folder -Path $outFolder

    # Logs to collect (standard on most Windows systems).
    $logsToCollect = @("Security", "System", "Application")

    foreach ($logName in $logsToCollect) {
        try {
            Write-Host "Collecting $logName events since $startTime ..."

            # Get-WinEvent reads from Windows Event Viewer.
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $startTime
            } -ErrorAction Stop

            # Export selected fields to CSV to make analysis easy.
            $csvPath = Join-Path $outFolder ($logName + ".csv")
            $events |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
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
        # ComputerInfo is a broad system summary (OS, build, hardware, etc).
        (Get-ComputerInfo | Out-String) | Set-Content -Path (Join-Path $outFolder "ComputerInfo.txt") -Encoding UTF8

        # ipconfig is a standard network snapshot.
        (ipconfig /all | Out-String) | Set-Content -Path (Join-Path $outFolder "IpConfig.txt") -Encoding UTF8

        # Active TCP connections (useful for investigations).
        (Get-NetTCPConnection |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Sort-Object LocalPort |
            Format-Table -AutoSize | Out-String) |
            Set-Content -Path (Join-Path $outFolder "TcpConnections.txt") -Encoding UTF8

        # Listening ports (useful for detecting unexpected services).
        (Get-NetTCPConnection -State Listen |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort |
            Format-Table -AutoSize | Out-String) |
            Set-Content -Path (Join-Path $outFolder "ListeningPorts.txt") -Encoding UTF8

        # Full service list (Name, state, start mode, account).
        (Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, StartName |
            Sort-Object Name |
            Export-Csv -Path (Join-Path $outFolder "Services.csv") -NoTypeInformation -Encoding UTF8)

        # Firewall rule summary.
        (Get-NetFirewallRule |
            Select-Object DisplayName, Enabled, Direction, Action, Profile |
            Export-Csv -Path (Join-Path $outFolder "FirewallRules.csv") -NoTypeInformation -Encoding UTF8)

        Write-Host "Snapshot collected successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Snapshot collection error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ----------------------------------------------------------
# Analyzer helper: make a “location string” for exact evidence
# ----------------------------------------------------------
function New-EventLocation {
    param(
        [string]$FilePath,
        [object]$EventRow
    )

    # We create a human readable location with:
    # - CSV file name
    # - TimeCreated
    # - Event ID
    # This makes it easy to find the evidence later.
    $fileName = Split-Path $FilePath -Leaf
    return "$fileName | Time=$($EventRow.TimeCreated) | EventID=$($EventRow.Id)"
}

# ----------------------------------------------------------
# Analyzer helper: add a finding object in a consistent format
# ----------------------------------------------------------
function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [int]$Count,
        [string]$FilePath,
        [string]$Details,
        [string[]]$ExampleLocations,
        [string]$Recommendation
    )

    $Findings.Add([pscustomobject]@{
        Severity        = $Severity
        Category        = $Category
        Title           = $Title
        Count           = $Count
        File            = $FilePath
        Details         = $Details
        ExampleEvidence = ($ExampleLocations -join " ; ")
        Recommendation  = $Recommendation
    })
}

# ----------------------------------------------------------
# Analyzer: Run detections against collected CSV files
# ----------------------------------------------------------
function Analyze-Session {
    param([string]$SessionPath)

    Write-Heading "Analyzing Session (Intermediate Audit + Detection)"

    if (-not (Test-Path $SessionPath)) {
        Write-Host "Session folder not found." -ForegroundColor Yellow
        return
    }

    $eventFolder = Join-Path $SessionPath "EventLogs"
    if (-not (Test-Path $eventFolder)) {
        Write-Host "No EventLogs folder found. Collect evidence first (option 1)." -ForegroundColor Yellow
        return
    }

    # Create Analysis output folder.
    $analysisFolder = Join-Path $SessionPath "Analysis"
    Ensure-Folder -Path $analysisFolder

    # Paths to the exported event CSV files.
    $securityCsv = Join-Path $eventFolder "Security.csv"
    $systemCsv   = Join-Path $eventFolder "System.csv"
    $appCsv      = Join-Path $eventFolder "Application.csv"

    # Findings list that will be exported later.
    $findings = New-Object System.Collections.Generic.List[object]

    # We will also write a detailed text report listing evidence lines.
    $detailedLines = New-Object System.Collections.Generic.List[string]
    $detailedLines.Add("Detailed Findings Report")
    $detailedLines.Add("========================")
    $detailedLines.Add("Session: $SessionPath")
    $detailedLines.Add("Generated: " + (Get-Date))
    $detailedLines.Add("")

    # ---------------------------
    # 1) SECURITY LOG DETECTIONS
    # ---------------------------
    Write-Host ""
    Write-Host "Checking Security.csv ..." -ForegroundColor Cyan

    if (Test-Path $securityCsv) {
        $sec = Import-Csv $securityCsv

        # 4625 = Failed logon
        $failed = $sec | Where-Object { $_.Id -eq "4625" }
        if ($failed.Count -ge $Global:FailedLogonThreshold) {
            $examples = $failed | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Authentication" `
                -Title "Failed logons (Event ID 4625) reached threshold" `
                -Count $failed.Count `
                -FilePath $securityCsv `
                -Details "Detected $($failed.Count) failed logons. Threshold is $($Global:FailedLogonThreshold). Possible password spraying or brute force." `
                -ExampleLocations $locs `
                -Recommendation "Review Security.csv messages for usernames and source details. Check for repeated failures on one account. Consider account lockout policy and MFA."

            $detailedLines.Add("High | Authentication | Failed logons >= threshold (4625)")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        } else {
            Write-Host "Security.csv: OK (failed logons below threshold $($Global:FailedLogonThreshold))" -ForegroundColor Green
        }

        # 4624 = Successful logon
        # We do not always flag these, but we can highlight RDP logons (Logon Type 10) because they are important.
        $rdpLogons = $sec | Where-Object { $_.Id -eq "4624" -and $_.Message -match "Logon Type:\s+10" }
        if ($rdpLogons.Count -gt 0) {
            $examples = $rdpLogons | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "Medium" `
                -Category "Remote Access" `
                -Title "RDP logons detected (4624 Logon Type 10)" `
                -Count $rdpLogons.Count `
                -FilePath $securityCsv `
                -Details "RDP logons are sensitive and worth reviewing, especially on servers." `
                -ExampleLocations $locs `
                -Recommendation "Confirm RDP is expected. Verify source IPs in the event message. Restrict RDP to management IPs where possible."

            $detailedLines.Add("Medium | Remote Access | RDP logons (4624 Type 10)")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        } else {
            Write-Host "Security.csv: OK (no RDP logons detected)" -ForegroundColor Green
        }

        # 4740 = Account lockout
        $lockouts = $sec | Where-Object { $_.Id -eq "4740" }
        if ($lockouts.Count -ge $Global:LockoutThreshold) {
            $examples = $lockouts | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Authentication" `
                -Title "Account lockouts detected (4740)" `
                -Count $lockouts.Count `
                -FilePath $securityCsv `
                -Details "Account lockouts can indicate brute force attempts or misconfigured services using old credentials." `
                -ExampleLocations $locs `
                -Recommendation "Identify locked accounts from event message. Check for repeated failures from the same source. Review service accounts and scheduled tasks."

            $detailedLines.Add("High | Authentication | Account lockouts (4740)")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        } else {
            Write-Host "Security.csv: OK (no account lockouts detected)" -ForegroundColor Green
        }

        # 4720 = New user created
        $newUsers = $sec | Where-Object { $_.Id -eq "4720" }
        if ($newUsers.Count -ge $Global:NewUserThreshold) {
            $examples = $newUsers | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "Medium" `
                -Category "Identity" `
                -Title "New user accounts created (4720)" `
                -Count $newUsers.Count `
                -FilePath $securityCsv `
                -Details "New user creation should always be reviewed on servers." `
                -ExampleLocations $locs `
                -Recommendation "Confirm accounts were created via change request. Check who created them and whether they were added to privileged groups."

            $detailedLines.Add("Medium | Identity | New user accounts (4720)")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        } else {
            Write-Host "Security.csv: OK (no new user accounts created detected)" -ForegroundColor Green
        }

        # Group membership changes (common IDs)
        # 4728: member added to a security-enabled global group
        # 4732: member added to a security-enabled local group
        # 4756: member added to a security-enabled universal group
        $groupAdds = $sec | Where-Object { $_.Id -in @("4728","4732","4756") }
        if ($groupAdds.Count -ge $Global:AdminGroupChangeThreshold) {
            $examples = $groupAdds | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Privilege" `
                -Title "Group membership changes detected (4728/4732/4756)" `
                -Count $groupAdds.Count `
                -FilePath $securityCsv `
                -Details "Group changes can be privilege escalation. Review which group and who was added." `
                -ExampleLocations $locs `
                -Recommendation "Confirm the change is approved. Pay attention to Admin groups. Review membership changes around the same time."

            $detailedLines.Add("High | Privilege | Group membership changes (4728/4732/4756)")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        } else {
            Write-Host "Security.csv: OK (no group membership adds detected)" -ForegroundColor Green
        }

        # 4698 = Scheduled task created (if auditing enabled)
        $taskCreate = $sec | Where-Object { $_.Id -eq "4698" }
        if ($taskCreate.Count -ge $Global:ScheduledTaskCreateThreshold) {
            $examples = $taskCreate | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Persistence" `
                -Title "Scheduled tasks created (4698)" `
                -Count $taskCreate.Count `
                -FilePath $securityCsv `
                -Details "Scheduled tasks are a common persistence technique." `
                -ExampleLocations $locs `
                -Recommendation "Verify task name and creator in the event message. Review for suspicious paths or PowerShell execution."

            $detailedLines.Add("High | Persistence | Scheduled task created (4698)")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        } else {
            Write-Host "Security.csv: OK (no scheduled task creations detected)" -ForegroundColor Green
        }

        # 7045 is actually System log usually, but sometimes appears in Security depending on setup.
        $serviceCreateSec = $sec | Where-Object { $_.Id -eq "7045" }
        if ($serviceCreateSec.Count -ge $Global:ServiceInstallThreshold) {
            $examples = $serviceCreateSec | Select-Object -First 5
            $locs = @()
            foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $securityCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Persistence" `
                -Title "New service installed (7045) seen in Security log" `
                -Count $serviceCreateSec.Count `
                -FilePath $securityCsv `
                -Details "New service install can be legitimate software or attacker persistence." `
                -ExampleLocations $locs `
                -Recommendation "Check service name and binary path in message. Confirm install is expected."

            $detailedLines.Add("High | Persistence | Service installed (7045) in Security")
            foreach ($e in $examples) {
                $detailedLines.Add((New-EventLocation -FilePath $securityCsv -EventRow $e))
                $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " ))
            }
            $detailedLines.Add("")
        }
    }
    else {
        Add-Finding -Findings $findings `
            -Severity "Low" `
            -Category "Collection" `
            -Title "Security.csv missing" `
            -Count 0 `
            -FilePath $securityCsv `
            -Details "Security log export missing. This often happens if PowerShell was not run as Administrator or access is restricted." `
            -ExampleLocations @() `
            -Recommendation "Run tool as Administrator and re-collect."

        Write-Host "Security.csv: Missing" -ForegroundColor Yellow
    }

    # -------------------------
    # 2) SYSTEM LOG DETECTIONS
    # -------------------------
    Write-Host ""
    Write-Host "Checking System.csv ..." -ForegroundColor Cyan

    if (Test-Path $systemCsv) {
        $sys = Import-Csv $systemCsv

        # IMPORTANT FIX FOR YOUR NOISE:
        # Event ID 7036 (Information) is usually normal: "service entered running/stopped state"
        # We do NOT treat those as suspicious anymore.
        # Instead we focus on:
        # - unexpected shutdowns
        # - service crashes/failures (errors/warnings)
        # - new service installed (7045)
        # - system time changes
        # - audit log cleared (sometimes appears elsewhere)
        # - driver or critical failures

        # 1074 = planned shutdown/restart initiated by a process/user
        $shutdownPlanned = $sys | Where-Object { $_.Id -eq "1074" }
        if ($shutdownPlanned.Count -gt 0) {
            $examples = $shutdownPlanned | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $systemCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "Medium" `
                -Category "System" `
                -Title "Shutdown/restart initiated (1074)" `
                -Count $shutdownPlanned.Count `
                -FilePath $systemCsv `
                -Details "A process or user initiated a shutdown/restart. This may be legitimate maintenance." `
                -ExampleLocations $locs `
                -Recommendation "Confirm maintenance window. Check the message for which process/user initiated restart."

            $detailedLines.Add("Medium | System | Planned shutdown/restart (1074)")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $systemCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        }

        # 1076 = reason for unexpected shutdown (you have this in your sample)
        $unexpectedReason = $sys | Where-Object { $_.Id -eq "1076" }
        if ($unexpectedReason.Count -gt 0) {
            $examples = $unexpectedReason | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $systemCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "System" `
                -Title "Unexpected shutdown reason recorded (1076)" `
                -Count $unexpectedReason.Count `
                -FilePath $systemCsv `
                -Details "System had an unexpected shutdown. This can indicate power loss, crash, or forced reset." `
                -ExampleLocations $locs `
                -Recommendation "Check for crash/bugcheck events around the same time. Confirm why shutdown happened and whether it is suspicious."

            $detailedLines.Add("High | System | Unexpected shutdown reason (1076)")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $systemCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        } else {
            Write-Host "System.csv: OK (no unexpected shutdown reasons detected)" -ForegroundColor Green
        }

        # 6008 = previous shutdown was unexpected
        $unexpected6008 = $sys | Where-Object { $_.Id -eq "6008" }
        if ($unexpected6008.Count -gt 0) {
            $examples = $unexpected6008 | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $systemCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "System" `
                -Title "Unexpected shutdown detected (6008)" `
                -Count $unexpected6008.Count `
                -FilePath $systemCsv `
                -Details "Windows reports the previous shutdown was unexpected." `
                -ExampleLocations $locs `
                -Recommendation "Check for related errors, crashes, or forced power-off. Correlate with 1076/bugcheck events."

            $detailedLines.Add("High | System | Unexpected shutdown (6008)")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $systemCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        }

        # 7045 = a service was installed in the system (very important)
        $serviceInstalled = $sys | Where-Object { $_.Id -eq "7045" }
        if ($serviceInstalled.Count -ge $Global:ServiceInstallThreshold) {
            $examples = $serviceInstalled | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $systemCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Persistence" `
                -Title "New service installed (7045)" `
                -Count $serviceInstalled.Count `
                -FilePath $systemCsv `
                -Details "New services can be legitimate installs, but are also common attacker persistence." `
                -ExampleLocations $locs `
                -Recommendation "Check service name and binary path in the message. Confirm install is expected."

            $detailedLines.Add("High | Persistence | Service installed (7045)")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $systemCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        } else {
            Write-Host "System.csv: OK (no new services installed detected)" -ForegroundColor Green
        }

        # Smarter service failure detection:
        # We only flag System events where Level is Warning/Error/Critical AND Message indicates service failure.
        $serviceFailures = $sys | Where-Object {
            ($_.LevelDisplayName -match "Warning|Error|Critical") -and
            ($_.Message -match "service") -and
            ($_.Message -match "failed|terminated|crash|stopped unexpectedly|was unable")
        }

        if ($serviceFailures.Count -gt 0) {
            $examples = $serviceFailures | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $systemCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "Medium" `
                -Category "Services" `
                -Title "Service failures (Warning/Error/Critical + failure keywords)" `
                -Count $serviceFailures.Count `
                -FilePath $systemCsv `
                -Details "Detected real service failures (not normal 7036 info state changes)." `
                -ExampleLocations $locs `
                -Recommendation "Identify affected services from the messages. Check if security tools were stopped or crashed."

            $detailedLines.Add("Medium | Services | Service failures (filtered)")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $systemCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        } else {
            Write-Host "System.csv: OK (no filtered service failures detected)" -ForegroundColor Green
        }

        # If you want to still *count* 7036 info events for context, we summarize them but do not flag as suspicious.
        $svcState7036 = $sys | Where-Object { $_.Id -eq "7036" -and $_.LevelDisplayName -eq "Information" }
        Write-Host ("System.csv: Service state changes (7036 Information): " + $svcState7036.Count + " (normal noise, not flagged)") -ForegroundColor DarkGray
    }
    else {
        Add-Finding -Findings $findings `
            -Severity "Low" `
            -Category "Collection" `
            -Title "System.csv missing" `
            -Count 0 `
            -FilePath $systemCsv `
            -Details "System log export missing. Collection may have failed." `
            -ExampleLocations @() `
            -Recommendation "Re-run collection."
    }

    # ------------------------------
    # 3) APPLICATION LOG DETECTIONS
    # ------------------------------
    Write-Host ""
    Write-Host "Checking Application.csv ..." -ForegroundColor Cyan

    if (Test-Path $appCsv) {
        $app = Import-Csv $appCsv

        # App crashes / .NET runtime issues (common investigation items)
        $appErrors = $app | Where-Object { $_.LevelDisplayName -match "Error|Critical" }
        if ($appErrors.Count -gt 0) {
            $examples = $appErrors | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $appCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "Low" `
                -Category "Applications" `
                -Title "Application errors present (Error/Critical)" `
                -Count $appErrors.Count `
                -FilePath $appCsv `
                -Details "Application errors are not always security issues, but can indicate instability or exploitation attempts." `
                -ExampleLocations $locs `
                -Recommendation "Review messages for repeated crashes of security tools, management tools, or unknown applications."

            $detailedLines.Add("Low | Applications | Application errors (Error/Critical)")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $appCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        } else {
            Write-Host "Application.csv: OK (no Error/Critical application events detected)" -ForegroundColor Green
        }

        # Windows Defender detections often appear in Application log depending on provider.
        $defenderHits = $app | Where-Object { $_.Message -match "Windows Defender|Microsoft Defender|Threat|malware|detected|quarantine" }
        if ($defenderHits.Count -gt 0) {
            $examples = $defenderHits | Select-Object -First 5
            $locs = @(); foreach ($e in $examples) { $locs += (New-EventLocation -FilePath $appCsv -EventRow $e) }

            Add-Finding -Findings $findings `
                -Severity "High" `
                -Category "Malware" `
                -Title "Defender/threat related messages detected" `
                -Count $defenderHits.Count `
                -FilePath $appCsv `
                -Details "Potential malware detection or security tool alerts." `
                -ExampleLocations $locs `
                -Recommendation "Review Defender history and message details. Confirm if threat was remediated. Investigate related processes/users."

            $detailedLines.Add("High | Malware | Defender/threat messages")
            foreach ($e in $examples) { $detailedLines.Add((New-EventLocation -FilePath $appCsv -EventRow $e)); $detailedLines.Add("Message: " + ($e.Message -replace "`r`n"," " )) }
            $detailedLines.Add("")
        } else {
            Write-Host "Application.csv: OK (no Defender/threat keywords detected)" -ForegroundColor Green
        }
    }
    else {
        Add-Finding -Findings $findings `
            -Severity "Low" `
            -Category "Collection" `
            -Title "Application.csv missing" `
            -Count 0 `
            -FilePath $appCsv `
            -Details "Application log export missing. Collection may have failed." `
            -ExampleLocations @() `
            -Recommendation "Re-run collection."
    }

    # --------------------------
    # Export analysis artifacts
    # --------------------------
    $findingsCsv = Join-Path $analysisFolder "Findings.csv"
    $summaryTxt  = Join-Path $analysisFolder "Summary.txt"
    $detailTxt   = Join-Path $analysisFolder "Findings-Detailed.txt"

    $findings | Export-Csv -Path $findingsCsv -NoTypeInformation -Encoding UTF8

    # Build a clean summary
    $summary = New-Object System.Collections.Generic.List[string]
    $summary.Add("Audit Session Analysis Summary")
    $summary.Add("==============================")
    $summary.Add("")
    $summary.Add("Session: $SessionPath")
    $summary.Add("Generated: " + (Get-Date))
    $summary.Add("")
    $summary.Add("Failed logon threshold: " + $Global:FailedLogonThreshold)
    $summary.Add("")

    if ($findings.Count -eq 0) {
        $summary.Add("No suspicious patterns were detected by the current rule set.")
        $summary.Add("This does not guarantee the system is clean. It means no rules triggered.")
    } else {
        $summary.Add("Total findings: " + $findings.Count)
        $summary.Add("")
        $bySev = $findings | Group-Object Severity
        foreach ($g in $bySev) {
            $summary.Add(("Severity {0}: {1}" -f $g.Name, $g.Count))
        }
        $summary.Add("")
        foreach ($f in $findings) {
            $summary.Add("Severity: " + $f.Severity)
            $summary.Add("Category: " + $f.Category)
            $summary.Add("Title: " + $f.Title)
            $summary.Add("Count: " + $f.Count)
            $summary.Add("File: " + $f.File)
            $summary.Add("Evidence: " + $f.ExampleEvidence)
            $summary.Add("Recommendation: " + $f.Recommendation)
            $summary.Add("")
        }
    }

    $summary | Set-Content -Path $summaryTxt -Encoding UTF8
    $detailedLines | Set-Content -Path $detailTxt -Encoding UTF8

    Write-Host ""
    Write-Host "Saved: $findingsCsv" -ForegroundColor Green
    Write-Host "Saved: $summaryTxt" -ForegroundColor Green
    Write-Host "Saved: $detailTxt" -ForegroundColor Green

    # Quick view on screen
    Write-Heading "Findings (Quick View)"
    if ($findings.Count -eq 0) {
        Write-Host "No findings detected by current rules." -ForegroundColor Green
    } else {
        $findings | Select-Object Severity, Category, Title, Count | Format-Table -AutoSize
        Write-Host ""
        Write-Host "Tip: Open Findings-Detailed.txt for exact messages and locations." -ForegroundColor Cyan
    }
}

# ----------------------------------------------------------
# Main menu loop
# ----------------------------------------------------------
function Start-MainMenu {

    Ensure-Folder -Path $Global:AuditRoot

    $hoursBack = $Global:DefaultHoursBack
    $lastSession = $null

    while ($true) {

        Write-Heading "Audit Collector + Analyzer (Standalone)"
        Write-Host "Audit root: $Global:AuditRoot"
        Write-Host "Hours back for event log collection: $hoursBack"
        Write-Host "Failed logon threshold (4625): $($Global:FailedLogonThreshold)"

        $lastText = "None"
        if (-not [string]::IsNullOrWhiteSpace($lastSession)) { $lastText = $lastSession }
        Write-Host ("Last collected session: " + $lastText)

        Write-Host ""
        Write-Host "1  Collect Evidence (Event Logs + Snapshot)"
        Write-Host "2  Analyze a Session (pick from list)"
        Write-Host "3  Change Hours Back"
        Write-Host "4  Change Failed Logon Threshold (default 3)"
        Write-Host "5  Open Audit Root Folder (Explorer)"
        Write-Host "0  Exit"
        Write-Host ""

        $choice = Read-MenuChoice -Prompt "Choose" -Allowed @(0,1,2,3,4,5)

        switch ($choice) {

            1 {
                $session = New-AuditSessionFolder
                $lastSession = $session

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
                Write-Heading "Change Failed Logon Threshold"
                Write-Host "Current: $($Global:FailedLogonThreshold)"
                $val = Read-Host "Enter new threshold (example: 3)"
                if ($val -match '^\d+$') {
                    $Global:FailedLogonThreshold = [int]$val
                    Write-Host "Updated failed logon threshold to $($Global:FailedLogonThreshold)." -ForegroundColor Green
                } else {
                    Write-Host "Invalid number. Threshold not changed." -ForegroundColor Yellow
                }
                Read-Host "Press ENTER to continue" | Out-Null
            }

            5 {
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
