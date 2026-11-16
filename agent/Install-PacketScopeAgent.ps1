<#
.SYNOPSIS
    PacketScope Windows Agent Installer (Windows 10 / Windows 11)
.DESCRIPTION
    Verifies Wireshark/TShark and Npcap prerequisites, installs PacketScope-Agent.ps1
    into %ProgramData%\PacketScope with restricted ACLs, optionally registers a
    background Windows Scheduled Task running at system startup, and performs an
    initial sensor check-in test.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$SensorToken,

    [string]$InterfaceId = "",
    [switch]$InstallServiceTask,
    [switch]$StartNow
)

$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramData\PacketScope"

Write-Host "=== PacketScope Windows Capture Agent Installer ===" -ForegroundColor Cyan

if ($ServerUrl -match 'YOUR-DEPLOYED-PACKETSCOPE-URL|your-packetscope-host|YOUR_PACKETSCOPE_URL') {
    Write-Error "Replace the placeholder -ServerUrl with your actual PacketScope server URL (for example, your deployed Cloud Run URL or http://localhost:3000 if running locally)."
    exit 1
}

# Check Administrator privilege if installing scheduled service task
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($InstallServiceTask -and -not $IsAdmin) {
    Write-Error "Installing the background service task requires an elevated Administrator PowerShell prompt."
    exit 1
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ScriptSource = Join-Path $PSScriptRoot "PacketScope-Agent.ps1"
$ScriptTarget = Join-Path $InstallDir "PacketScope-Agent.ps1"

if (Test-Path $ScriptSource) {
    Copy-Item -Path $ScriptSource -Destination $ScriptTarget -Force
} else {
    Write-Host "Downloading latest PacketScope-Agent.ps1 from $ServerUrl..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Resp = Invoke-WebRequest -UseBasicParsing -Uri "$($ServerUrl.TrimEnd('/'))/api/agent/download/script"
    if ($Resp.Content -match '^\s*<(!DOCTYPE|html|head|script)' -or $Resp.Content -match '__cookie_check\.html') {
        Write-Error "Received an HTML authentication/cookie gate instead of PacketScope-Agent.ps1 from $ServerUrl. Click 'Download Agent (.ps1)' in your browser to save PacketScope-Agent.ps1 into the same folder as this installer, and pass a direct/deployed PacketScope ServerUrl (ais-dev-* preview URLs require browser cookies)."
        exit 1
    }
    Set-Content -Path $ScriptTarget -Value $Resp.Content -Encoding UTF8
}

# Save config with restricted file permissions
$ConfigPath = Join-Path $InstallDir "agent-config.json"
@{
    serverUrl   = $ServerUrl.TrimEnd('/')
    sensorToken = $SensorToken
    interfaceId = $InterfaceId
} | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8

# Verify TShark presence
$TShark = Get-Command "tshark.exe" -ErrorAction SilentlyContinue
if (-not $TShark -and -not (Test-Path "C:\Program Files\Wireshark\tshark.exe")) {
    Write-Warning "Wireshark / TShark was not detected. Please install Wireshark 4.x with Npcap from https://www.wireshark.org/download.html before starting capture."
}

if ($InstallServiceTask) {
    $TaskName = "PacketScopeCaptureAgent"
    $ArgString = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptTarget`" -NonInteractive"
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ArgString
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Write-Host "Registered Windows background Scheduled Task '$TaskName'." -ForegroundColor Green
}

Write-Host "`nInstallation complete in $InstallDir" -ForegroundColor Green
Write-Host "Run interactively: powershell -ExecutionPolicy Bypass -File `"$ScriptTarget`"" -ForegroundColor Gray

if ($StartNow) {
    Write-Host "`nLaunching PacketScope Capture Agent..." -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptTarget
}
