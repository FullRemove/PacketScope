# PacketScope Windows Capture Agent Installation & Sensor Registration Guide

## Prerequisites (Windows 10 / Windows 11)
1. **Wireshark 4.x with TShark**: Install from [wireshark.org](https://www.wireshark.org/download.html). Ensure `tshark.exe` is installed (default: `C:\Program Files\Wireshark\tshark.exe`).
2. **Npcap**: Included with the Wireshark installer. Enable **Install Npcap in WinPcap API-compatible Mode** if running legacy capture tooling.
3. **PowerShell 5.1+** (included natively in Windows 10 and Windows 11).
4. **Authorization**: Confirm you are legally and organizationally authorized to monitor the selected interface or switch SPAN port.

## Step 1: Register a Sensor in PacketScope
1. Sign in to the PacketScope Operations Console and select your Organization Workspace.
2. Navigate to **Sensors** in the left sidebar.
3. Enter a descriptive Sensor Name (e.g., `HQ-Gateway-Win11-01`) and select the target Network Segment.
4. Click **Register Sensor**.
5. Copy the **One-Time Sensor Credential** (`ps_live_...`). PacketScope stores only a SHA-256 hash of this token.

## Step 2: Download & Install the Agent
Download `PacketScope-Agent.ps1` and `Install-PacketScopeAgent.ps1` from the **Sensors** page (or `/api/agent/download/script` and `/api/agent/download/installer`).

Run an elevated PowerShell prompt:
```powershell
powershell -ExecutionPolicy Bypass -File .\Install-PacketScopeAgent.ps1 `
  -ServerUrl "https://YOUR_PACKETSCOPE_URL" `
  -SensorToken "ps_live_YOUR_TOKEN" `
  -InstallServiceTask
```

## Step 3: Interactive Interface Selection & Verification
To run interactively and choose from `tshark -D` interfaces:
```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\PacketScope\PacketScope-Agent.ps1"
```
- The agent discovers TShark automatically, lists Ethernet/Wi-Fi interfaces, and verifies dissector field compatibility (`tshark -G fields`).
- It starts **one continuous TShark process** extracting tab-separated metadata fields only (`-T fields -E separator=\t -E occurrence=f`) so empty fields never shift columns.
- When offline, records buffer locally in `%ProgramData%\PacketScope\queue.jsonl` (up to 50,000 records) and retry with exponential backoff.
- Periodic heartbeats report `captureRunning`, `interfaceAvailable`, `packetsObserved`, `recordsParsed`, `recordsQueued`, `recordsSubmitted`, `recordsAccepted`, `recordsRejected`, `lastHeartbeat`, and `lastError`.

## Step 4: Wider Network Visibility Topologies
A single Windows workstation NIC only sees packets addressed to or broadcast on that host. For organization-wide visibility:
- **Switch Mirror / SPAN Port**: Mirror corporate VLANs to a dedicated capture NIC on the Windows sensor host.
- **Gateway / Router Host**: Deploy on the inline routing gateway interface.
- **Access Point Uplink**: Mirror wireless controller/AP uplink traffic to a capture interface.
