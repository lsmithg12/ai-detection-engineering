# Mythic + Fawkes Red Team Setup

This guide covers setting up [Mythic C2](https://github.com/its-a-feature/Mythic) with the
[Fawkes](https://github.com/galoryber/fawkes) agent for true red vs. blue exercises in your lab.

> **This is optional Phase 2.** The log simulator provides synthetic Fawkes attack telemetry
> so you can build and validate detections without Mythic. Set up Mythic when you're ready
> for real attack traffic.

## Architecture

```
┌──────────────────────────────────┐
│         Mythic C2 Server         │
│  ┌────────────┐ ┌─────────────┐  │
│  │   Mythic   │ │   Fawkes    │  │
│  │   Server   │ │  Payload    │  │
│  │  :7443     │ │   Type      │  │
│  └────────────┘ └─────────────┘  │
└────────────┬─────────────────────┘
             │ HTTP C2 (port 80/443)
             │
┌────────────▼─────────────────────┐
│      Target Host(s)              │
│  ┌──────────────────────────┐    │
│  │  Fawkes Agent (implant)  │    │
│  └──────────────────────────┘    │
│  ┌──────────────────────────┐    │
│  │  Sysmon + Log Shipper    │───────────► Elastic / Splunk
│  │  (Elastic Agent or       │    │         (your blue team lab)
│  │   Splunk UF)             │    │
│  └──────────────────────────┘    │
└──────────────────────────────────┘
```

## Prerequisites

- Separate VM or host for Mythic (Ubuntu 22.04+, 4GB+ RAM, Docker installed)
- Target host(s) — Windows VM(s) for full Fawkes capabilities
- Network connectivity between Mythic, targets, and your SIEM lab

> **IMPORTANT**: Run Mythic and targets on an **isolated network** — never on your
> corporate network. Use a dedicated VLAN, virtual network, or air-gapped lab.

## Step 1: Install Mythic

On your Mythic server (NOT the same machine as your SIEM lab):

```bash
# Clone Mythic
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic

# Install
sudo ./install_docker_ubuntu.sh   # if Docker not installed
sudo make

# Start Mythic
sudo ./mythic-cli start

# Get the admin password
sudo ./mythic-cli config get MYTHIC_ADMIN_PASSWORD
```

Access Mythic UI at `https://<mythic-ip>:7443`

## Step 2: Install Fawkes Agent

```bash
# From the Mythic install directory
sudo ./mythic-cli install github https://github.com/galoryber/fawkes
```

Fawkes will appear as an available payload type in the Mythic UI.

## Step 3: Set Up Target Host(s)

### Windows Target VM

**Recommended**: Windows 10/11 VM with:

1. **Sysmon installed** (critical for detection telemetry):
   ```powershell
   # Download Sysmon from Sysinternals
   Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile Sysmon64.exe

   # Use SwiftOnSecurity's config (comprehensive logging)
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmon-config.xml

   # Install
   .\Sysmon64.exe -accepteula -i sysmon-config.xml
   ```

2. **PowerShell Script Block Logging** enabled:
   ```powershell
   # Enable via Group Policy or registry
   New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
   ```

3. **Command-line audit logging** enabled:
   ```powershell
   # Audit process creation with command line
   auditpol /set /subcategory:"Process Creation" /success:enable
   New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force
   ```

4. **Log shipper** installed — pick one:

   **Option A: Elastic Agent** (if using Elastic SIEM):
   ```powershell
   # Download from Kibana → Fleet → Add agent
   # Follow the enrollment wizard — select Windows integration
   # This ships Sysmon, Security, PowerShell logs automatically
   ```

   **Option B: Splunk Universal Forwarder** (if using Splunk):
   ```powershell
   # Download UF from splunk.com
   # Install with:
   msiexec /i splunkforwarder.msi RECEIVING_INDEXER="<your-lab-ip>:9997" /quiet

   # Configure inputs.conf to collect Sysmon + Security logs:
   # [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   # disabled = false
   # index = sysmon
   #
   # [WinEventLog://Security]
   # disabled = false
   # index = wineventlog
   ```

### Linux Target (Optional)

For testing Fawkes' cross-platform capabilities (crontab, ssh-keys):

```bash
# Install auditd
sudo apt install auditd audispd-plugins

# Install Elastic Agent or Splunk UF
# Configure to ship audit logs to your SIEM
```

## Step 4: Generate a Fawkes Payload

1. Open Mythic UI → **Payloads** → **Create Payload**
2. Select **fawkes** as the payload type
3. Select **HTTP** as the C2 profile
4. Configure:
   - **Callback Host**: `http://<mythic-ip>`
   - **Callback Port**: `80`
   - **Callback Interval**: `10` (seconds — fast for lab testing)
   - **Callback Jitter**: `20` (%)
5. Select target OS (Windows EXE for most testing)
6. Build the payload

## Step 5: Execute and Detect

1. Transfer the Fawkes payload to your Windows target
2. Execute it (you'll get a callback in Mythic)
3. Run Fawkes commands from Mythic — start with detection-friendly ones:
   ```
   # Discovery burst (should trigger detection)
   whoami
   ps
   net-enum -action users
   arp

   # Persistence (should trigger detection)
   persist -method registry -action install -name TestUpdate

   # Process injection (should trigger detection)
   vanilla-injection
   ```
4. Check your SIEM — do the blue team agent's detections fire?

## Step 6: Red vs Blue Loop

The ideal workflow:

1. **Red team** (your coworker): Runs Fawkes commands against the target
2. **Blue team** (Claude Code agent): Monitors SIEM, detects activity, tunes rules
3. **Red team**: Adapts — uses stealthier techniques (threadless-inject, PoolParty)
4. **Blue team**: Notices gaps, writes new detections for evasive techniques
5. **Iterate**: Each side improves against the other

### Automation Ideas

- Schedule Fawkes to run automated attack playbooks via Mythic's scripting API
- Have the blue team agent run periodic tuning sessions (via cron or Claude Code scheduled tasks)
- Log both sides' actions and build a report of detection coverage over time

## Cost & Resource Summary

| Component | Resource Needs | Cost |
|---|---|---|
| Mythic Server | 4GB RAM, 2 vCPU, 20GB disk | Free (self-hosted) |
| Windows Target VM | 4GB RAM, 2 vCPU, 40GB disk | Free (Windows eval ISO) |
| Fawkes Agent | Installed in Mythic | Free (BSD-3 license) |
| Sysmon | Runs on target | Free |
| Log Shipper | Elastic Agent or Splunk UF | Free |
| SIEM Lab | Already running | Already set up |

**Total additional cost**: $0 (assuming you have hardware for VMs)

## Troubleshooting

**Fawkes payload won't build**: Check Mythic logs: `sudo ./mythic-cli logs fawkes`

**No callbacks**: Verify network connectivity between target and Mythic. Check firewall rules. Try HTTP on port 80 first (simplest).

**Logs not appearing in SIEM**: Verify the log shipper is running on the target. Check that the SIEM receiving port is open. Test with a manual event first.

**Sysmon not logging**: Verify Sysmon service is running: `Get-Service Sysmon64`. Check Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational.
