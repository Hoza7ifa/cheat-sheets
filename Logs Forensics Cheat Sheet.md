
This cheat sheet provides a concise guide for collecting, acquiring, analyzing, and investigating logs in digital forensic investigations. It covers Windows and Linux systems, focusing on key commands, tools, and best practices to ensure integrity and efficiency. Commands are sourced from Volatility, Linux forensics, and general log analysis techniques

---

## 1. Log Collection and Acquisition

### General Principles

- **Preserve Integrity**: Collect logs without altering them to maintain admissibility in legal proceedings. Use write blockers or read-only access where possible.
- **Secure Storage**: Store logs in a high-security environment (password-protected, encrypted) to prevent tampering.
- **Regulatory Compliance**: Check for retention policies (e.g., GDPR, HIPAA, PCI DSS) dictating log archival periods.
- **Prioritize Volatile Data**: Capture logs from live systems first, as restarts or shutdowns may delete volatile data (e.g., memory-based logs).
- **Use Automation**: Tools like Splunk, ELK Stack, or EventLog Analyzer can streamline collection from multiple sources.

### Windows Log Collection

- **Event Log Location**: Logs are stored in `%SystemRoot%\System32\winevt\Logs` (EVTX format for Vista and later).
- **Acquire Offline Logs**:
    
    ```bash
    # Copy event logs to a secure location
    copy %SystemRoot%\System32\winevt\Logs\*.evtx D:\Forensic_Case\Logs\
    ```
    
- **Live System Collection**:
    
    ```powershell
    # Export specific event logs using PowerShell
    Get-WinEvent -LogName "Security" | Export-Csv -Path D:\Forensic_Case\Security_Log.csv
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-VHDMP-Operational'} | Export-Csv -Path D:\Forensic_Case\VHDMP_Log.csv
    ```
    
- **Sysmon Logs** (if installed):
    
    ```powershell
    # Export Sysmon logs (Event ID 1, 3, etc.)
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Select-Object TimeCreated,Message | Export-Csv -Path D:\Forensic_Case\Sysmon_Log.csv
    ```
    
    - **Note**: Sysmon provides detailed logs for process creation (Event ID 1), network connections (Event ID 3), and file time changes (Event ID 2).
- **KAPE for Automated Collection**:
    
    ```bash
    # Use KAPE to collect logs and other artifacts
    .\kape.exe --tsource E: --tdest D:\Forensic_Case --module EvtxECmd,LogParser,NirSoft_FullEventLogView_Security
    ```
    
    - **Note**: KAPE supports modules like `EvtxECmd` for parsing EVTX logs.

### Linux Log Collection

- **Log Locations**: Common logs in `/var/log/` (e.g., `syslog`, `auth.log`, `secure` for RHEL/CentOS).
- **Acquire Logs**:
    
    ```bash
    # Copy logs to a secure location
    cp /var/log/{syslog,auth.log,secure} /media/sf_tmp/forensic_logs/
    # Unzip compressed logs (e.g., syslog.2.gz)
    gunzip /var/log/syslog.2.gz
    ```
    
- **Disk Imaging for Offline Analysis**:
    
    ```bash
    # List disk devices
    lsblk
    # Create disk image with dd
    dd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img
    # Use dcfldd for hashing during imaging
    dcfldd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img hash=sha256 hashwindow=1M hashlog=/media/sf_tmp/linux_forensic.hash
    ```
    
    - **Note**: Disk images preserve logs and file system metadata (e.g., MFT).
- **Live System Collection**:
    
    ```bash
    # Capture last login activities
    last -f /var/log/wtmp
    # Capture failed login attempts
    last -f /var/log/btmp
    # Grep for specific keywords in auth logs
    grep -i "Accepted\|failed\|login:session" /var/log/auth.log*
    ```
    

### Network and Security Device Logs

- **Sources**: Routers, switches, firewalls, IDS/IPS, proxies, WAF.
- **Collection Methods**:
    
    - Use SIEM tools (e.g., Splunk, ELK Stack) to aggregate logs from network devices.
    - Manually export logs via device-specific interfaces (e.g., syslog servers).
    
    ```bash
    # Example: Export firewall logs via rsync
    rsync -av user@firewall:/logs /media/sf_tmp/firewall_logs/
    ```
    
- **Note**: Ensure logs are time-synced using NTP to maintain consistent timestamps.

---

## 2. Log Analysis

### General Techniques

- **Log Parsing**: Transform raw logs into readable formats using tools like Logstash or Splunk. Focus on timestamps, IP addresses, user actions, and error codes.
- **Timeline Analysis**: Create a super timeline to correlate events across multiple sources (e.g., system logs, network logs). Tools like Plaso can automate this.
- **Anomaly Detection**: Identify deviations from baseline behavior (e.g., unusual login times, unexpected IPs).
- **Keyword Search**: Use regex or keywords (e.g., “union” for SQL injection) to filter relevant entries.
- **Visualization**: Use tools like Kibana or Splunk for graphical representations of patterns and anomalies.

### Windows Log Analysis

- **Event Viewer**: Manually review logs on a live system (not forensically sound).
- **Volatility for Memory-Based Logs**:
    
    ```bash
    # Extract command history from memory
    python vol.py -f memory_image --profile=<PROFILE> cmdscan
    # Extract console output (including commands)
    python vol.py -f memory_image --profile=<PROFILE> consoles
    # Extract event logs (XP/2003 only)
    python vol.py -f memory_image --profile=<PROFILE> evtlogs -D D:\Forensic_Case\Logs
    ```
    
    - **Note**: `evtlogs` is limited to XP/2003 due to EVTX format changes.
- **Event Log Analysis Tools**:
    - **Hayabusa**: Fast EVTX analysis for threat hunting.
        
        ```bash
        hayabusa -i path_to_evtx_files -e 4624 --filter 'Channel == "Security" and LogonType == 10' --output-fields 'time,user,src_ip'
        ```
        
    - **EvtxECmd**: Parses EVTX logs for forensic analysis.
        
        ```bash
        .\EvtxECmd.exe -f Security.evtx --csv D:\Forensic_Case\Output
        ```
        
    - **Splunk**: Indexes and visualizes logs for real-time analysis.
- **Key Event IDs** (Security Log):
    - 4624: Successful logon
    - 4625: Failed logon
    - 4672: Privilege assignment
    - 4720: User account created
    - **Note**: Cross-reference with Sysmon Event IDs for detailed process/network activity.

### Linux Log Analysis

- **Manual Analysis**:
    
    ```bash
    # Search for login activity in auth.log
    grep -i "Accepted\|failed" /var/log/auth.log
    # Check for sudo usage
    grep -i "sudo" /var/log/auth.log
    # Analyze package installations
    cat /var/log/apt/history.log | grep "Commandline"
    cat /var/log/dpkg.log | grep installed
    ```
    
- **File System Metadata**:
    
    ```bash
    # Collect file metadata
    stat /path/to/file
    # Identify file type
    file /path/to/file
    # Extract strings for clues
    strings /path/to/file
    # Generate MD5 hash for integrity
    md5sum /path/to/file
    ```
    
- **Tools**:
    - **Autopsy**: Import disk images to analyze logs and file system artifacts.
    - **Plaso**: Create super timelines from logs and file system data.
    - **LogExpert**: Supports live log tailing and filtering for large files.

### Network Log Analysis

- **Tools**: Wireshark, Splunk, Logstash, EventLog Analyzer.
- **Commands**:
    
    ```bash
    # Analyze network traffic logs (e.g., firewall logs)
    grep "EXTERNAL" /path/to/firewall.log
    # Filter by IP address
    grep "10.10.0.15" /path/to/firewall.log
    ```
    
- **Note**: Look for unusual outbound traffic or unrecognized IPs.

---

## 3. Log Investigation

### Investigation Workflow

1. **Define Objectives**: Focus on specific incidents (e.g., unauthorized access, malware).
2. **Correlate Logs**: Use timelines to link events across system, application, and network logs.
3. **Identify Indicators of Compromise (IOCs)**:
    - Suspicious IPs, user accounts, or processes.
    - Unexpected file changes or privilege escalations.
4. **Reconstruct Events**: Build a timeline of actions (e.g., logon, file access, network activity).
5. **Validate Findings**: Cross-reference multiple sources (e.g., event logs, Sysmon, network traffic).

### Windows Investigation

- **Check for Unauthorized Access**:
    
    ```powershell
    # Find failed logins (Event ID 4625)
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Select-Object TimeCreated,@{Name='Account';Expression={$_.Properties[5].Value}}
    ```
    
- **Detect Malware**:
    
    ```powershell
    # Look for suspicious process creation (Sysmon Event ID 1)
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" | Select-Object TimeCreated,@{Name='CommandLine';Expression={$_.Properties[4].Value}}
    ```
    
- **Investigate Remote Access**:
    
    ```bash
    # Check RDP usage (Event ID 4624, LogonType 10)
    hayabusa -i Security.evtx -e 4624 --filter 'LogonType == 10'
    ```
    
    - **Note**: Look for tools like PSEXESVC in named pipes (`\\X.X.X.X\pipe\PSEXESVC-*`).

### Linux Investigation

- **Check User Activity**:
    
    ```bash
    # List active user accounts
    cat /etc/passwd | grep -E "bash|sh|dash"
    # Check for unauthorized SSH keys
    cat /home/$USER/.ssh/authorized_keys
    # Review recent files
    cat /home/$USER/.recently-used.xbel
    ```
    
- **Detect Privilege Escalation**:
    
    ```bash
    # Check sudo configurations
    cat /etc/sudoers /etc/sudoers.d/*
    ```
    
- **Investigate Network Activity**:
    
    ```bash
    # List active connections
    netstat -tulnp
    # Check DNS configurations
    cat /etc/resolv.conf
    ```
    

### Network Investigation

- **Analyze Traffic Logs**:
    
    ```bash
    # Look for unusual outbound traffic
    grep "dst=203.0.113.25" /path/to/firewall.log
    ```
    
- **Correlate with Endpoint Logs**:
    - Match timestamps and IPs between firewall and system logs to trace attacker activity.
- **Use SIEM Tools**:
    - EventLog Analyzer: Search raw logs for specific events and generate forensic reports.
    - Splunk: Build dashboards to visualize attack patterns.

### Advanced Techniques

- **Model Checking**: Use formal methods to verify log sequences against attack scenarios (e.g., temporal logic for event ordering).
- **MITRE ATT&CK Mapping**: Map log events to ATT&CK tactics/techniques to understand threat actor TTPs.
    
    ```bash
    # Example: Map Sysmon Event ID 1 to ATT&CK T1059 (Command and Scripting Interpreter)
    ```
    
- **Notepad++ for Manual Analysis**:
    
    ```bash
    # Filter lines with regex in Notepad++
    # In Replace (Ctrl+H): Use ".*keyword.*" with "Regular expression" checked
    ```
    
    - **Note**: Use plugins like TextFX to remove blank lines.

---

## General Notes

- **Backup Logs**: Create hot (1-4 weeks) and cold (6-12 months) backups to preserve evidence.
- **Time Sync**: Ensure all devices use NTP for consistent timestamps.
- **Automation Tools**: Use Splunk, ELK Stack, EventLog Analyzer, or Hayabusa to reduce manual effort.
- **Integrity Verification**: Hash logs (e.g., MD5, SHA256) to detect tampering.
- **Cross-Reference Artifacts**: Combine logs with memory forensics (e.g., Volatility) and file system analysis (e.g., MFT) for comprehensive investigations.
- **Legal Considerations**: Obtain authorization before collecting logs to ensure admissibility.
- **Date and Time**: Current date/time is 02:24 PM EEST, Tuesday, August 05, 2025.