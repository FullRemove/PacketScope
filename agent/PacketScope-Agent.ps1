<#
.SYNOPSIS
    PacketScope Windows Capture Agent (PowerShell 5.1+ / Wireshark 4.x / TShark / Npcap)
.DESCRIPTION
    Authorized network metadata capture agent for Windows 10 and Windows 11.
    Extracts strictly non-payload packet headers and dissector metadata (IP, port, transport,
    protocol, DNS query, TLS SNI, HTTP host, STUN/TURN message types) via a continuous TShark
    process with strict column alignment, local offline buffering, exponential backoff retry,
    periodic heartbeats, and clean shutdown.
#>

[CmdletBinding()]
param(
    [string]$ServerUrl = $env:PACKETSCOPE_SERVER_URL,
    [string]$SensorToken = $env:PACKETSCOPE_SENSOR_TOKEN,
    [string]$InterfaceId = "",
    [int]$BatchSize = 100,
    [int]$FlushIntervalSeconds = 2,
    [int]$HeartbeatIntervalSeconds = 15,
    [int]$MaxQueueRecords = 50000,
    [string]$StateDir = "$env:ProgramData\PacketScope",
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$AgentVersion = "1.4.0"

# Ensure state & queue directory exists
if (-not (Test-Path -Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}
$QueueFile = Join-Path $StateDir "queue.jsonl"
$ConfigFile = Join-Path $StateDir "agent-config.json"
$LogFile = Join-Path $StateDir "agent.log"

function Write-AgentLog {
    param([string]$Level, [string]$Message)
    # Redact any accidental token patterns before writing logs
    $SafeMsg = $Message -replace 'ps_live_[A-Za-z0-9_\-]+', 'ps_live_[REDACTED]'
    $Line = "{0} [{1}] {2}" -f (Get-Date).ToUniversalTime().ToString("o"), $Level.ToUpper(), $SafeMsg
    Write-Host $Line
    try {
        Add-Content -Path $LogFile -Value $Line -Encoding UTF8
    } catch { }
}

function Find-TSharkPath {
    $Candidates = @(
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe"
    )
    foreach ($Path in $Candidates) {
        if (Test-Path -Path $Path) { return $Path }
    }
    $Cmd = Get-Command "tshark.exe" -ErrorAction SilentlyContinue
    if ($Cmd) { return $Cmd.Source }
    return $null
}

function Test-NpcapInstalled {
    $Svc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    if (-not $Svc) {
        $Svc = Get-Service -Name "npf" -ErrorAction SilentlyContinue
    }
    if (-not $Svc) { return $false }
    return ($Svc.Status -eq "Running" -or $Svc.StartType -ne "Disabled")
}

function Get-SupportedTSharkFields {
    param([string]$TSharkExe)
    $Supported = @{}
    try {
        $Output = & $TSharkExe -G fields 2>$null
        foreach ($Line in $Output) {
            if ($Line -match '^F\t[^\t]+\t([^\t]+)\t') {
                $Supported[$Matches[1]] = $true
            }
        }
    } catch { }
    return $Supported
}

function Get-CaptureInterfaces {
    param([string]$TSharkExe)
    $List = @()
    $Raw = & $TSharkExe -D 2>$null
    foreach ($Line in $Raw) {
        if ($Line -match '^(\d+)\.\s+(.+)$') {
            $List += [PSCustomObject]@{
                Id   = $Matches[1]
                Name = $Matches[2].Trim()
            }
        }
    }
    return $List
}

function Parse-TSharkMetadataLine {
    param(
        [string]$Line,
        [string[]]$FieldOrder
    )
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    # Split strictly by tab preserving empty positions so missing fields NEVER shift columns
    $Cols = $Line.Split("`t")
    $Map = @{}
    for ($i = 0; $i -lt $FieldOrder.Count; $i++) {
        $Val = if ($i -lt $Cols.Count) { $Cols[$i].Trim() } else { "" }
        $Map[$FieldOrder[$i]] = $Val
    }

    $SrcIp = if ($Map["ip.src"]) { $Map["ip.src"] } elseif ($Map["ipv6.src"]) { $Map["ipv6.src"] } else { "" }
    $DstIp = if ($Map["ip.dst"]) { $Map["ip.dst"] } elseif ($Map["ipv6.dst"]) { $Map["ipv6.dst"] } else { "" }
    if (-not $SrcIp -or -not $DstIp) { return $null }

    # Strip any accidental CIDR suffix
    $SrcIp = ($SrcIp -split '/')[0]
    $DstIp = ($DstIp -split '/')[0]

    $EpochStr = $Map["frame.time_epoch"]
    $ObservedAt = (Get-Date).ToUniversalTime().ToString("o")
    if ($EpochStr -match '^\d+(\.\d+)?$') {
        try {
            $EpochSec = [double]$EpochStr
            $Origin = [DateTimeOffset]::new(1970, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $ObservedAt = $Origin.AddSeconds($EpochSec).UtcDateTime.ToString("o")
        } catch { }
    }

    $Transport = "OTHER"
    $SrcPort = $null
    $DstPort = $null
    if ($Map["tcp.srcport"] -or $Map["tcp.dstport"]) {
        $Transport = "TCP"
        if ($Map["tcp.srcport"] -match '^\d+$') { $SrcPort = [int]$Map["tcp.srcport"] }
        if ($Map["tcp.dstport"] -match '^\d+$') { $DstPort = [int]$Map["tcp.dstport"] }
    } elseif ($Map["udp.srcport"] -or $Map["udp.dstport"]) {
        $Transport = "UDP"
        if ($Map["udp.srcport"] -match '^\d+$') { $SrcPort = [int]$Map["udp.srcport"] }
        if ($Map["udp.dstport"] -match '^\d+$') { $DstPort = [int]$Map["udp.dstport"] }
    } elseif ($Map["icmp.type"] -or $Map["icmpv6.type"]) {
        $Transport = "ICMP"
    }

    $Len = 0
    if ($Map["frame.len"] -match '^\d+$') { $Len = [int]$Map["frame.len"] }

    $Payload = @{
        eventUid          = [Guid]::NewGuid().ToString("N")
        observedAt        = $ObservedAt
        srcIp             = $SrcIp
        dstIp             = $DstIp
        srcPort           = $SrcPort
        dstPort           = $DstPort
        transport         = $Transport
        dissectorProtocol = $Map["_ws.col.Protocol"]
        packetLength      = $Len
        dnsQuery          = if ($Map["dns.qry.name"]) { $Map["dns.qry.name"] } else { $null }
        tlsSni            = if ($Map["tls.handshake.extensions_server_name"]) { $Map["tls.handshake.extensions_server_name"] } else { $null }
        httpHost          = if ($Map["http.host"]) { $Map["http.host"] } else { $null }
        stunType          = if ($Map["stun.type"]) { $Map["stun.type"] } else { $null }
        stunClass         = if ($Map["stun.type.class"]) { $Map["stun.type.class"] } else { $null }
        stunMethod        = if ($Map["stun.type.method"]) { $Map["stun.type.method"] } else { $null }
        stunAttributes    = if ($Map["stun.attribute"]) { $Map["stun.attribute"] } else { $null }
    }
    return $Payload
}

# Load saved config if parameters were not passed
if ((-not $ServerUrl -or -not $SensorToken) -and (Test-Path -Path $ConfigFile)) {
    try {
        $Saved = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        if (-not $ServerUrl -and $Saved.serverUrl) { $ServerUrl = $Saved.serverUrl }
        if (-not $SensorToken -and $Saved.sensorToken) { $SensorToken = $Saved.sensorToken }
        if (-not $InterfaceId -and $Saved.interfaceId) { $InterfaceId = $Saved.interfaceId }
    } catch { }
}

if (-not $ServerUrl -or $ServerUrl -match 'YOUR-DEPLOYED-PACKETSCOPE-URL|your-packetscope-host|YOUR_PACKETSCOPE_URL') {
    if ($NonInteractive) { throw "Valid ServerUrl is required (replace placeholder URL)." }
    $ServerUrl = Read-Host "Enter your real PacketScope Server URL (e.g. https://your-cloud-run-url or http://localhost:3000)"
}
$ServerUrl = $ServerUrl.TrimEnd('/')

if (-not $SensorToken) {
    if ($NonInteractive) { throw "SensorToken is required." }
    $SecureToken = Read-Host "Enter Sensor Token (ps_live_...)" -AsSecureString
    $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
    $SensorToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($Bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
}

Write-AgentLog "INFO" "PacketScope Windows Capture Agent v$AgentVersion starting..."
Write-AgentLog "INFO" "Authorized monitoring only. Raw packet payloads are never collected."

$TSharkExe = Find-TSharkPath
if (-not $TSharkExe) {
    Write-AgentLog "ERROR" "TShark was not found. Install Wireshark 4.x with TShark and Npcap."
    exit 1
}
Write-AgentLog "INFO" "Discovered TShark at: $TSharkExe"

if (-not (Test-NpcapInstalled)) {
    Write-AgentLog "WARN" "Npcap driver service not detected as running; live capture may fail on interfaces lacking Npcap."
}

$Interfaces = Get-CaptureInterfaces -TSharkExe $TSharkExe
if ($Interfaces.Count -eq 0) {
    Write-AgentLog "ERROR" "No capture interfaces reported by TShark. Run as Administrator or verify Npcap permissions."
    exit 1
}

if (-not $InterfaceId) {
    if ($NonInteractive) {
        $InterfaceId = $Interfaces[0].Id
    } else {
        Write-Host "`nAvailable Authorized Network Interfaces:" -ForegroundColor Cyan
        foreach ($Ifc in $Interfaces) {
            Write-Host ("  [{0}] {1}" -f $Ifc.Id, $Ifc.Name)
        }
        $InterfaceId = Read-Host "`nSelect interface number to capture"
    }
}

$SelectedIfc = $Interfaces | Where-Object { $_.Id -eq $InterfaceId -or $_.Name -eq $InterfaceId } | Select-Object -First 1
if (-not $SelectedIfc) {
    Write-AgentLog "ERROR" "Selected interface '$InterfaceId' is not available."
    exit 1
}
Write-AgentLog "INFO" "Selected interface [$($SelectedIfc.Id)] $($SelectedIfc.Name)"

# Save non-interactive configuration (token stored with current user/admin ACLs)
try {
    @{
        serverUrl   = $ServerUrl
        sensorToken = $SensorToken
        interfaceId = $SelectedIfc.Id
    } | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
} catch { }

# Verify TShark dissector field names before starting continuous capture
$DesiredFields = @(
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "_ws.col.Protocol",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "http.host",
    "stun.type",
    "stun.type.class",
    "stun.type.method",
    "stun.attribute",
    "icmp.type",
    "icmpv6.type"
)

Write-AgentLog "INFO" "Verifying TShark dissector field compatibility..."
$SupportedMap = Get-SupportedTSharkFields -TSharkExe $TSharkExe
$ActiveFields = @()
foreach ($Field in $DesiredFields) {
    if ($Field -eq "_ws.col.Protocol" -or $SupportedMap.Count -eq 0 -or $SupportedMap.ContainsKey($Field)) {
        $ActiveFields += $Field
    } else {
        Write-AgentLog "WARN" "Field '$Field' not supported in installed TShark; omitting."
    }
}

# Build TShark arguments for continuous metadata-only capture
# Note: use TShark's /t token (never a raw tab byte) so Windows CreateProcess does not treat it as whitespace
$FieldArgs = @("-i", $SelectedIfc.Id, "-l", "-n", "-Q", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f", "-E", "header=n")
foreach ($F in $ActiveFields) {
    $FieldArgs += "-e"
    $FieldArgs += $F
}

# Diagnostic state counters
$Stats = @{
    captureRunning     = $false
    interfaceAvailable = $true
    packetsObserved    = [long]0
    recordsParsed      = [long]0
    recordsQueued      = [long]0
    recordsSubmitted   = [long]0
    recordsAccepted    = [long]0
    recordsRejected    = [long]0
    lastHeartbeat      = $null
    lastError          = $null
}

# Load any persisted offline queue records from disk
$Queue = New-Object System.Collections.Generic.List[object]
if (Test-Path -Path $QueueFile) {
    try {
        $ExistingLines = Get-Content -Path $QueueFile -Encoding UTF8
        foreach ($L in $ExistingLines) {
            if (-not [string]::IsNullOrWhiteSpace($L)) {
                $Queue.Add(($L | ConvertFrom-Json))
            }
        }
        $Stats.recordsQueued = $Queue.Count
        if ($Queue.Count -gt 0) {
            Write-AgentLog "INFO" "Loaded $($Queue.Count) queued records from offline buffer."
        }
    } catch {
        Write-AgentLog "WARN" "Could not parse existing offline queue file; starting fresh."
    }
}

function Save-QueueToDisk {
    param([System.Collections.Generic.List[object]]$Items)
    try {
        if ($Items.Count -eq 0) {
            if (Test-Path -Path $QueueFile) { Remove-Item -Path $QueueFile -Force }
            return
        }
        $Lines = $Items | ForEach-Object { $_ | ConvertTo-Json -Compress }
        Set-Content -Path $QueueFile -Value $Lines -Encoding UTF8
    } catch { }
}

function Invoke-Heartbeat {
    $Headers = @{
        "Authorization" = "Bearer $SensorToken"
        "Content-Type"  = "application/json"
    }
    $Body = @{
        hostname           = $env:COMPUTERNAME
        osVersion          = [Environment]::OSVersion.VersionString
        agentVersion       = $AgentVersion
        activeInterface    = $SelectedIfc.Name
        captureRunning     = $Stats.captureRunning
        interfaceAvailable = $Stats.interfaceAvailable
        packetsObserved    = $Stats.packetsObserved
        recordsParsed      = $Stats.recordsParsed
        recordsQueued      = $Queue.Count
        recordsSubmitted   = $Stats.recordsSubmitted
        recordsAccepted    = $Stats.recordsAccepted
        recordsRejected    = $Stats.recordsRejected
        lastError          = $Stats.lastError
        interfaces         = @($Interfaces | ForEach-Object { @{ name = $_.Name } })
    } | ConvertTo-Json -Depth 4

    try {
        $Resp = Invoke-RestMethod -Uri "$ServerUrl/api/agent/check-in" -Method Post -Headers $Headers -Body $Body -TimeoutSec 10
        if ($Resp -is [string] -and ($Resp -match '^\s*<(!DOCTYPE|html)' -or $Resp -match '__cookie_check\.html')) {
            throw "Server returned an HTML browser-cookie gate instead of JSON. Deploy PacketScope to a direct/Cloud Run URL or self-hosted server (ais-dev-* preview URLs block non-browser agents)."
        }
        $Stats.lastHeartbeat = (Get-Date).ToUniversalTime().ToString("o")
        $Stats.lastError = $null
    } catch {
        $Stats.lastError = "Heartbeat failed: $($_.Exception.Message)"
        Write-AgentLog "WARN" $Stats.lastError
    }
}

function Send-PendingBatch {
    if ($Queue.Count -eq 0) { return $true }

    $Count = [Math]::Min($BatchSize, $Queue.Count)
    [object[]]$Batch = $Queue.GetRange(0, $Count).ToArray()
    $Headers = @{
        "Authorization" = "Bearer $SensorToken"
        "Content-Type"  = "application/json"
    }
    $Body = @{
        agentVersion = $AgentVersion
        events       = @($Batch)
    } | ConvertTo-Json -Depth 6 -Compress

    try {
        $Stats.recordsSubmitted += $Count
        $Resp = Invoke-RestMethod -Uri "$ServerUrl/api/agent/ingest" -Method Post -Headers $Headers -Body $Body -TimeoutSec 15
        if ($Resp -is [string] -and ($Resp -match '^\s*<(!DOCTYPE|html)' -or $Resp -match '__cookie_check\.html')) {
            throw "Server returned an HTML browser-cookie gate instead of JSON. Use a deployed/direct PacketScope ServerUrl rather than an ais-dev-* preview URL."
        }
        $Accepted = if ($null -ne $Resp.accepted) { [int]$Resp.accepted } else { $Count }
        $Rejected = if ($null -ne $Resp.rejected) { [int]$Resp.rejected } else { 0 }

        $Stats.recordsAccepted += $Accepted
        $Stats.recordsRejected += $Rejected
        $Queue.RemoveRange(0, $Count)
        $Stats.recordsQueued = $Queue.Count
        Save-QueueToDisk -Items $Queue
        $Stats.lastError = $null
        return $true
    } catch {
        $Stats.lastError = "Ingestion failed: $($_.Exception.Message)"
        Write-AgentLog "WARN" "$($Stats.lastError) (queued=$($Queue.Count))"
        Save-QueueToDisk -Items $Queue
        return $false
    }
}

function Start-ContinuousTShark {
    $Psi = New-Object System.Diagnostics.ProcessStartInfo
    $Psi.FileName = $TSharkExe
    $Psi.Arguments = ($FieldArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $Psi.UseShellExecute = $false
    $Psi.RedirectStandardOutput = $true
    $Psi.RedirectStandardError = $true
    $Psi.CreateNoWindow = $true

    $Proc = New-Object System.Diagnostics.Process
    $Proc.StartInfo = $Psi
    $null = $Proc.Start()
    return $Proc
}

$TSharkProc = $null
$LineQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
$ErrQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
$LastFlush = Get-Date
$LastHeartbeat = (Get-Date).AddSeconds(-$HeartbeatIntervalSeconds)
$RetryBackoffSec = 2

try {
    while ($true) {
        # Ensure continuous TShark process is running
        if ($null -eq $TSharkProc -or $TSharkProc.HasExited) {
            if ($null -ne $TSharkProc) {
                $Stats.captureRunning = $false
                $Stats.lastError = "TShark exited unexpectedly (exit code $($TSharkProc.ExitCode))"
                Write-AgentLog "WARN" "$($Stats.lastError). Restarting safely in 3s..."
                Start-Sleep -Seconds 3
            }

            $TSharkProc = Start-ContinuousTShark
            $Stats.captureRunning = -not $TSharkProc.HasExited
            $null = Register-ObjectEvent -InputObject $TSharkProc -EventName OutputDataReceived -Action {
                if (-not [string]::IsNullOrEmpty($EventArgs.Data)) {
                    $Event.MessageData.Enqueue($EventArgs.Data)
                }
            } -MessageData $LineQueue
            $null = Register-ObjectEvent -InputObject $TSharkProc -EventName ErrorDataReceived -Action {
                if (-not [string]::IsNullOrEmpty($EventArgs.Data)) {
                    $Event.MessageData.Enqueue($EventArgs.Data)
                }
            } -MessageData $ErrQueue
            $TSharkProc.BeginOutputReadLine()
            $TSharkProc.BeginErrorReadLine()
            Write-AgentLog "INFO" "Continuous TShark capture started (PID $($TSharkProc.Id)) on interface $($SelectedIfc.Id)."
        }

        # Drain any TShark stderr messages so the OS pipe buffer never stalls
        $ErrLine = $null
        while ($ErrQueue.TryDequeue([ref]$ErrLine)) {
            if ($ErrLine -notmatch '^Capturing on') {
                $Stats.lastError = $ErrLine
                Write-AgentLog "WARN" "TShark: $ErrLine"
            } else {
                Write-AgentLog "INFO" "TShark: $ErrLine"
            }
        }

        # Drain parsed lines non-blockingly so heartbeats & retries run even at 0 packets
        $Line = $null
        $ProcessedThisTick = 0
        while ($ProcessedThisTick -lt 500 -and $LineQueue.TryDequeue([ref]$Line)) {
            $ProcessedThisTick++
            $Stats.packetsObserved++
            $Parsed = Parse-TSharkMetadataLine -Line $Line -FieldOrder $ActiveFields
            if ($null -ne $Parsed) {
                $Stats.recordsParsed++
                if ($Queue.Count -ge $MaxQueueRecords) {
                    $Queue.RemoveAt(0) # Bounded ring-buffer protection
                }
                $Queue.Add($Parsed)
                $Stats.recordsQueued = $Queue.Count
            }
        }

        $Now = Get-Date
        if (($Now - $LastHeartbeat).TotalSeconds -ge $HeartbeatIntervalSeconds) {
            Invoke-Heartbeat
            $LastHeartbeat = $Now
        }

        if ($Queue.Count -gt 0 -and (($Queue.Count -ge $BatchSize) -or (($Now - $LastFlush).TotalSeconds -ge $FlushIntervalSeconds))) {
            $Ok = Send-PendingBatch
            $LastFlush = $Now
            if ($Ok) {
                $RetryBackoffSec = 2
            } else {
                Start-Sleep -Seconds $RetryBackoffSec
                $RetryBackoffSec = [Math]::Min(60, $RetryBackoffSec * 2)
            }
        }

        Start-Sleep -Milliseconds 150
    }
} finally {
    Write-AgentLog "INFO" "Shutting down PacketScope agent cleanly..."
    Save-QueueToDisk -Items $Queue
    if ($null -ne $TSharkProc -and -not $TSharkProc.HasExited) {
        try {
            $TSharkProc.Kill()
            $TSharkProc.WaitForExit(3000) | Out-Null
        } catch { }
    }
    Write-AgentLog "INFO" "Shutdown complete. Final stats: observed=$($Stats.packetsObserved) accepted=$($Stats.recordsAccepted) queued=$($Queue.Count)"
}
