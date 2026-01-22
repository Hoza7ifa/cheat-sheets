
## 1. Preparation

- **Document Everything**: Record case number, date/time, system details, and collection method in a chain of custody log.
- **Use Write-Protected Storage**: Save logs to an external, write-protected drive (`/mnt/forensics` or `D:\Forensics`).
- **Verify Permissions**: Ensure root/admin access to logs.
- **Minimize Impact**: Avoid running processes that could overwrite logs or alter system state.
- **Chain of Custody**: Log who handles logs, when, and where they’re stored.
- **Time Sync**: Ensure systems use NTP for consistent timestamps.
- **Hashing**: Calculate SHA256 hashes to verify log integrity post-collection.
- **Regulatory Compliance**: Adhere to laws (e.g., GDPR, HIPAA, PCI DSS) for log retention and handling.

---

## 2. Key Log Types to Collect

- **Windows**:
    - **Security Log**: Logons (4624, 4625), privilege changes (4672), log clearing (1102), account creation (4720), group changes (4732).
    - **System Log**: Service installs (7045), time changes (4616).
    - **Application Log**: App errors/crashes.
    - **PowerShell Operational**: Script execution (4104).
    - **Sysmon (if installed)**: Process creation (1), network connections (3).
    - **Other**: Terminal Services (21, RDP), Windows Defender (`%4Operational`).
    - Location: `C:\Windows\System32\winevt\Logs` (`.evtx` format).
- **Linux**:
    - **Authentication**: `/var/log/auth.log` (Ubuntu) or `/var/log/secure` (RHEL).
    - **System**: `/var/log/syslog` (Ubuntu) or `/var/log/messages` (RHEL).
    - **Audit**: `/var/log/audit/audit.log` (auditd).
    - **Command History**: `~/.bash_history`.
    - **Other**: `/var/log/kern.log`, `/var/log/dpkg.log` (package installs).
- **macOS**:
    - **System Logs**: `/var/log/system.log` or unified logging via `log` command.
    - **Audit Logs**: `/var/audit/*`.
    - **Command History**: `~/.zsh_history`, `~/.bash_history`.
    - **Other**: `/var/log/install.log` (software installs).

---

## 3. Collection Methods

### Windows

#### Method 1: PowerShell Scripts

1. **Export Security Logs to CSV**  
    Collect recent security events (e.g., 4624, 4625, 1102).
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Csv -Path "D:\Forensics\security_logs_20250805.csv" -NoTypeInformation
    ```
    
2. **Filter Critical Event IDs**  
    Target key IDs (4624, 4625, 4672, 7045, 1102, 4720, 4732).
    
    ```powershell
    $EventIDs = @(4624, 4625, 4672, 7045, 1102, 4720, 4732)
    Get-WinEvent -LogName Security | Where-Object { $EventIDs -contains $_.Id } | Export-Csv -Path "D:\Forensics\critical_events_20250805.csv" -NoTypeInformation
    ```
    
3. **Collect PowerShell Execution Logs**  
    Detect malicious scripts (4104).
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 } | Export-Csv -Path "D:\Forensics\powershell_logs_20250805.csv" -NoTypeInformation
    ```
    
4. **Collect System Logs**  
    Capture service installs (7045), time changes (4616).
    
    ```powershell
    Get-WinEvent -LogName System | Where-Object { $_.Id -in @(7045, 4616) } | Export-Csv -Path "D:\Forensics\system_logs_20250805.csv" -NoTypeInformation
    ```
    
5. **Collect Sysmon Logs (if installed)**  
    Capture process creation (1), network connections (3).
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -in @(1, 3) } | Export-Csv -Path "D:\Forensics\sysmon_logs_20250805.csv" -NoTypeInformation
    ```
    
6. **Collect Recent File Modifications**  
    Identify files changed in the last 24 hours.
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } | Export-Csv -Path "D:\Forensics\file_modifications_20250805.csv" -NoTypeInformation
    ```
    
7. **Collect Registry AutoRun Entries**  
    Check persistence mechanisms.
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Export-Csv -Path "D:\Forensics\autorun_registry_20250805.csv" -NoTypeInformation
    ```
    
8. **Remote Collection**  
    Collect logs from a remote Windows system.
    
    ```powershell
    Invoke-Command -ComputerName RemotePC -ScriptBlock { Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Csv -Path C:\Temp\security_logs.csv -NoTypeInformation }
    ```
    
9. **Extract Specific Logs to XML**  
    Collect Event IDs 4624, 4625 in XML for structured analysis.
    
    ```powershell
    $evtxFolder = Get-Location
    $outputFile = Join-Path -Path $evtxFolder -ChildPath "output_20250805.xml"
    if (Test-Path $outputFile) { Clear-Content -Path $outputFile }
    Add-Content -Path $outputFile -Value "<?xml version='1.0' encoding='UTF-8'?><Events>"
    $evtxFiles = Get-ChildItem -Path $evtxFolder -Recurse -Filter "*.evtx"
    foreach ($file in $evtxFiles) {
        $events = Get-WinEvent -Path $file.FullName -ErrorAction SilentlyContinue | Where-Object { $_.Id -in @(4624, 4625) } | ForEach-Object { $_.ToXml() }
        if ($events) { Add-Content -Path $outputFile -Value "<!-- Events from: $($file.FullName) -->`n$events" }
    }
    Add-Content -Path $outputFile -Value "</Events>"
    ```
    

#### Method 2: wevtutil (Command Line)

Export logs in `.evtx` format for forensic tools (e.g., Event Log Explorer, Belkasoft X).

```cmd
wevtutil epl Security D:\Forensics\security_20250805.evtx
wevtutil epl System D:\Forensics\system_20250805.evtx
wevtutil epl Application D:\Forensics\application_20250805.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" D:\Forensics\powershell_20250805.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" D:\Forensics\sysmon_20250805.evtx
```

#### Method 3: LogParser

Query logs with SQL-like syntax.

```cmd
LogParser "SELECT TimeGenerated, EventID, Message FROM 'C:\Windows\System32\winevt\Logs\Security.evtx' WHERE EventID IN (4624, 4625)" -i:EVT -o:CSV > "D:\Forensics\security_filtered_20250805.csv"
```

#### Method 4: Manual Collection

Copy raw `.evtx` files.

```cmd
copy C:\Windows\System32\winevt\Logs\*.evtx D:\Forensics\winevt_logs_20250805\
```

#### Method 5: Event Viewer

- Open `eventvwr.msc`.
- Navigate to `Windows Logs > Security/System/Application` or `Applications and Services Logs`.
- Right-click > `Save All Events As` > Save as `.evtx` to `D:\Forensics`.

#### Method 6: Forensic Tools

- **KAPE**: Automated collection with hashing.
    
    ```cmd
    kape.exe --tsource C: --tdest D:\Forensics --target EventLogs
    ```
    
- **FTK Imager**: Copy logs or include in disk image.
    1. Open FTK Imager.
    2. Select `File > Add Evidence Item > Contents of a Folder`.
    3. Choose `C:\Windows\System32\winevt\Logs`.
    4. Export to `D:\Forensics\winevt_logs_20250805`.
- **Belkasoft X**: Parse logs from disk images or live systems.
    1. Load system image or folder in Belkasoft X.
    2. Navigate to `Artifacts > System Files > Event Logs`.
    3. Export to `D:\Forensics\belkasoft_logs_20250805`.
- **EvtxECmd**: Parse `.evtx` files to CSV/JSON.
    
    ```cmd
    EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv D:\Forensics\evtx_output_20250805 --inc 4624,4625,4672,7045,1102
    ```
    
- **FullEventLogView (NirSoft)**: Export logs from local/remote systems.
    1. Open FullEventLogView.
    2. Select log source (local, remote, or `.evtx` file).
    3. Filter for Event IDs (e.g., 4624, 4625).
    4. Save as CSV to `D:\Forensics\fulleventlog_20250805.csv`.

### Linux

#### Method 1: Command Line

1. **Copy Authentication Logs**  
    Collect login attempts and sudo usage.
    
    ```bash
    sudo cp /var/log/auth.log /mnt/forensics/auth_log_20250805.log
    sudo cp /var/log/secure /mnt/forensics/secure_log_20250805.log  # RHEL-based
    ```
    
2. **Copy System Logs**  
    Capture system events (services, errors).
    
    ```bash
    sudo cp /var/log/syslog /mnt/forensics/syslog_20250805.log  # Ubuntu/Debian
    sudo cp /var/log/messages /mnt/forensics/messages_20250805.log  # RHEL/CentOS
    ```
    
3. **Copy Audit Logs (auditd)**  
    Collect system call and user action logs.
    
    ```bash
    sudo cp /var/log/audit/audit.log /mnt/forensics/audit_log_20250805.log
    ```
    
4. **Copy Command History**  
    Capture user commands.
    
    ```bash
    sudo cat /home/*/.bash_history /root/.bash_history > /mnt/forensics/bash_history_20250805.txt
    ```
    
5. **Filter Recent Logs by Time**  
    Extract logs from the last 24 hours.
    
    ```bash
    sudo grep "$(date -d '24 hours ago' '+%b %d')" /var/log/auth.log > /mnt/forensics/auth_recent_20250805.log
    ```
    
6. **Collect Systemd Logs**  
    For systemd-based systems.
    
    ```bash
    journalctl --since "24 hours ago" > /mnt/forensics/journal_logs_20250805.log
    ```
    
7. **Collect Package Installation Logs**  
    Track software installs.
    
    ```bash
    sudo cp /var/log/dpkg.log /mnt/forensics/dpkg_log_20250805.log  # Debian/Ubuntu
    sudo cp /var/log/yum.log /mnt/forensics/yum_log_20250805.log  # RHEL/CentOS
    ```
    
8. **Remote Collection via SSH**  
    Collect logs from a remote Linux system.
    
    ```bash
    ssh user@remotehost "cat /var/log/auth.log" > /mnt/forensics/remote_auth_log_20250805.log
    ```
    
9. **Unzip Compressed Logs**  
    Handle rotated logs (e.g., `.gz`).
    
    ```bash
    sudo gunzip /var/log/syslog.1.gz -c > /mnt/forensics/syslog_1_20250805.log
    ```
    
10. **Collect Last Login Activity**  
    Capture login history.
    
    ```bash
    last -f /var/log/wtmp > /mnt/forensics/wtmp_log_20250805.txt
    last -f /var/log/btmp > /mnt/forensics/btmp_log_20250805.txt  # Failed logins
    ```
    

#### Method 2: Manual Collection

Copy logs directly from `/var/log`.

```bash
sudo cp -r /var/log/* /mnt/forensics/var_log_20250805/
```

#### Method 3: auditd

Export audit logs if auditd is configured.

```bash
sudo aureport --summary > /mnt/forensics/audit_summary_20250805.txt
sudo ausearch --start yesterday > /mnt/forensics/audit_raw_20250805.log
```

#### Method 4: Forensic Tools

- **KAPE**: Collect logs with plugins.
    
    ```bash
    kape --tsource / --tdest /mnt/forensics --target LinuxLogs
    ```
    
- **Autopsy**: Import logs or disk images.
    1. Open Autopsy.
    2. Add data source (`/var/log` or disk image).
    3. Export logs to `/mnt/forensics/autopsy_logs_20250805`.
- **LiME**: Collect logs with memory dumps.
    
    ```bash
    sudo insmod lime.ko "path=/mnt/forensics/memory_logs_20250805.lime format=lime"
    ```
    

### macOS

#### Method 1: Command Line

1. **Collect System Logs**  
    Export unified logging system logs.
    
    ```bash
    log show --last 1d --predicate 'eventType == logEvent' > /Volumes/Forensics/system_logs_20250805.log
    ```
    
2. **Collect Authentication Logs**  
    Capture login and sudo events.
    
    ```bash
    sudo cp /var/log/system.log /Volumes/Forensics/system_log_20250805.log
    sudo cp /var/audit/* /Volumes/Forensics/audit_logs_20250805/
    ```
    
3. **Collect Command History**  
    Capture user commands.
    
    ```bash
    sudo cat /Users/*/.zsh_history /Users/*/.bash_history > /Volumes/Forensics/command_history_20250805.txt
    ```
    
4. **Filter Logs by Process**  
    Target specific processes (e.g., `sshd`).
    
    ```bash
    log show --last 1d --predicate 'process == "sshd"' > /Volumes/Forensics/sshd_logs_20250805.log
    ```
    
5. **Collect Installation Logs**  
    Track software installs.
    
    ```bash
    sudo cp /var/log/install.log /Volumes/Forensics/install_log_20250805.log
    ```
    
6. **Remote Collection via SSH**  
    Collect logs from a remote macOS system.
    
    ```bash
    ssh user@remotehost "log show --last 1d" > /Volumes/Forensics/remote_system_logs_20250805.log
    ```
    

#### Method 2: Manual Collection

Copy logs directly from `/var/log` and `/var/audit`.

```bash
sudo cp -r /var/log/* /Volumes/Forensics/var_log_20250805/
sudo cp -r /var/audit/* /Volumes/Forensics/audit_logs_20250805/
```

#### Method 3: Forensic Tools

- **BlackLight**: Collect macOS logs and audit data.
    1. Open BlackLight, select target system.
    2. Export logs from `/var/log` and `/var/audit` to `/Volumes/Forensics`.
- **FTK Imager**: Copy log files or include in disk image.
    1. Open FTK Imager.
    2. Select `File > Add Evidence Item > Contents of a Folder`.
    3. Choose `/var/log` and `/var/audit`.
    4. Export to `/Volumes/Forensics/macos_logs_20250805`.
- **Autopsy**: Import logs or disk images.
    1. Open Autopsy.
    2. Add data source (`/var/log` or disk image).
    3. Export logs to `/Volumes/Forensics/autopsy_logs_20250805`.

#### Method 4: Console App

- Open Console (`/Applications/Utilities/Console.app`).
- Select logs (System, Audit, or Process-specific).
- Export as `.log` to `/Volumes/Forensics`.

### Network and Security Devices

#### Method 1: Command Line

- **Syslog Servers**: Export logs from network devices (e.g., firewalls, routers).
    
    ```bash
    rsync -av user@firewall:/logs /mnt/forensics/firewall_logs_20250805/
    ```
    

#### Method 2: SIEM Tools

- **Splunk/ELK Stack**: Aggregate logs from network devices.
    1. Configure syslog forwarding on devices to SIEM.
    2. Export logs to `/mnt/forensics/network_logs_20250805`.
- **EventLog Analyzer**: Collect logs via device-specific interfaces.
    1. Access EventLog Analyzer.
    2. Export raw logs to `/mnt/forensics/eventlog_analyzer_20250805`.

#### Method 3: Manual Collection

- Access device web interface or CLI.
- Export logs to CSV or text format.
- Save to `/mnt/forensics/network_device_logs_20250805`.

#### Method 4: Forensic Tools

- **Wireshark**: Capture network traffic logs.
    1. Start capture on relevant interface.
    2. Filter for specific IPs/protocols.
    3. Save as `.pcap` to `/mnt/forensics/network_traffic_20250805.pcap`.

---
## 4. Preservation and Validation

- **Calculate Hashes**: Verify log integrity.  
    **Windows**:
    
    ```powershell
    Get-FileHash -Path "D:\Forensics\security_logs_20250805.csv" -Algorithm SHA256 | Export-Csv -Path "D:\Forensics\hashes_20250805.csv" -NoTypeInformation
    ```
    
    **Linux/macOS**:
    
    ```bash
    sha256sum /mnt/forensics/auth_log_20250805.log > /mnt/forensics/hashes_20250805.txt
    ```
    
- **Compress Logs**: Save space while preserving integrity.  
    **Windows**:
    
    ```powershell
    Compress-Archive -Path "D:\Forensics\*.csv" -DestinationPath "D:\Forensics\logs_archive_20250805.zip"
    ```
    
    **Linux/macOS**:
    
    ```bash
    tar -czf /mnt/forensics/logs_archive_20250805.tar.gz /mnt/forensics/*.log
    ```
    
- **Secure Storage**: Save to write-protected external drive.
    
- **Verify Tampering**: Check for log clearing (Windows Event ID 1102).
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 1102 } | Select-Object TimeCreated, Message
    ```
    
- **Backup Logs**: Create hot (1-4 weeks) and cold (6-12 months) backups.
    

-----
## 5. Additional Tools

- **Windows**:
    - **Event Viewer**: Manual log export.
    - **LogParser**: SQL-like queries for logs.
    - **Belkasoft X**: Parse logs from images, recover deleted logs.
    - **Hayabusa**: Fast `.evtx` analysis for threat hunting.
- **Linux**:
    - **Plaso**: Create super timelines from logs.
    - **LogExpert**: Live log tailing and filtering.
- **macOS**:
    - **Console**: Manual log export.
    - **BlackLight**: macOS-specific log collection.
- **Network**:
    - **Wireshark**: Network traffic logs.
    - **Splunk/ELK Stack/EventLog Analyzer**: Aggregate device logs.