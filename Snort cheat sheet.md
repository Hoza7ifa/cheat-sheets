### Pre-Installation Requirements
- **OS Compatibility**: Ensure a compatible OS (Ubuntu, Debian, CentOS, or Windows with proper setup).
- **Dependencies**: Install required packages like `libpcap`, `libpcre`, and `libdnet` before Snort.
  - **Command**: `sudo apt-get install libpcap-dev libpcre3-dev libdnet-dev`
  - **Usage**: Installs libraries needed for packet capture and rule processing.
- **Network Interface**: Verify the network interface (e.g., `eth0`) using `ifconfig` or `ip addr`.
- **Root Privileges**: Ensure root or sudo access for installation and configuration.

### Installation and Configuration

- **Command**: `sudo apt-get install snort*`
    
    - **Usage**: Installs Snort and related packages on a Linux (Ubuntu) system. Ensures all dependencies are met for Snort to function as an IDS.
        
- **Command**: `sudo nano /etc/snort/snort.conf`
    
    - **Usage**: Opens Snort's configuration file to define the network to protect (e.g., *ipvar HOME_NET 192.168.1.21 or 192.168.1.0/24* for a range). Specifies interfaces and network settings.
        
- **Command**: `sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i eth0`
    
    - **Usage**: Runs Snort in IDS mode with console alerts, quietly *(-q)*, as user/group *snort*, using the specified config file and interface *(eth0)*. Captures and alerts on malicious traffic.

### Snort Modes of Operation
##### - Sniffer Mode 
- `v`: Verbose mode, shows packet headers.
- `e`: Display link layer headers.
- `d`: Show application layer data (payload).
- `x`: Display packets with headers in hexadecimal format.
- `q`: Run Snort in quiet mode, less output to the console.
##### Packet Logger Mode 
- `r`: Read and process packets from a file (playback).
- `l <directory>`: Log the packets to a directory.
- `k <mode>`: Keep data link layer information. `<mode>` can be `none`, `normal`, or `strict`.

##### NIDS Mode 
- `c <config file>`: Use the specified configuration file.
- `T`: Test the current Snort configuration.
- `A <mode>`: Set the alert mode (`full`, `fast`, `console`, `none`).
- `s`: Send alert messages to the syslog.
- `M <IP>`: Send SMB alerts to the specified IP address.

### Additional Commands and Options 

- `i <interface>`: Listen on the specified network interface.
- `u <user>`: Run Snort under the specified user account.
- `g <group>`: Run Snort under the specified group account.
- `F <bpf file>`: Use the specified Berkley Packet Filter file.
- `t <chroot directory>`: Run Snort in a chroot jail.
- `D`: Run Snort as a daemon (background mode).

### Rule Management

- **Organize Rules**: Store custom rules in `/etc/snort/rules/local.rules` and categorize by threat type (e.g., `icmp.rules`, `sql.rules`).
- **Include Rules in Config**: Add rule files to `snort.conf` using `include $RULE_PATH/local.rules`.
- **Update Rules**: Regularly update community or subscription rules (`oinkmaster` or `pulledpork`).
  - **Command**: `sudo pulledpork.pl -c /etc/pulledpork.conf -l`
  - **Usage**: Automates rule updates from Snort’s community or subscription sources.
- **Backup Rules**: Save custom rules before updates to avoid overwrites.
  - **Command**: `cp /etc/snort/rules/local.rules /etc/snort/rules/local.rules.bak`
### Snort Rules Format 

- Actions include `alert`, `log`, `pass`, `activate`, `dynamic`, `drop`, `reject`, `sdrop`.
- Protocols include `tcp`, `udp`, `icmp`, `ip`.

### Snort Rule Example 

```css
Action Protocol Source_IP Source_Port Direction Destination_IP Destination_Port (Options)
```

```css 
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH scan"; flags:S; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000001;)
```
### Tips for Writing Snort Rules 

- Always start your rule with an action and protocol.
- Specify source and destination IPs and ports using `>` for direction.
	- *->* (one-way), *<>* (bidirectional).
- Use `msg` to define the alert message.
- Use `sid` to uniquely identify each rule.
- Use `rev` to specify the revision of the rule.

### Advanced Rule Options 

- `content`: Look for specific content in the payload.
- `flags`: Check for specific TCP flags.
- `threshold`: Define thresholds for alerts to minimize false positives.

### Log and Data Management 

- Use `/var/log/snort/` or your defined directory to check for logs.
- Regularly rotate and archive logs to prevent disk space issues.

### Troubleshooting 

- Use `v` for a more verbose output if you are not receiving the expected results.
- Make sure your Snort rules are correctly formatted and loaded.
- Check Snort’s documentation for complex rule writing.]

### Performance Optimization

- **Reduce Rule Scope**: Use specific IPs/ports (e.g., `192.168.1.0/24` instead of `any`) to limit processing.
- **Enable Multi-Threading**: Run Snort with multiple threads for better performance on multi-core systems.
  - **Command**: `sudo snort -c /etc/snort/snort.conf -i eth0 --num-threads 4`
  - **Usage**: Distributes packet processing across 4 CPU cores.
- **Use BPF Filters**: Apply Berkeley Packet Filters to focus on relevant traffic.
  - **Command**: `snort -F filter.bpf -i eth0`
  - **Example Filter**: `tcp port 80` in `filter.bpf` to monitor HTTP traffic only.
- **Offload Logging**: Use `-b` for binary logging to reduce disk I/O.
  - **Command**: `snort -b -l /var/log/snort -i eth0`
### Alert Output Customization

- **Unified2 Output**: Use for compatibility with tools like Barnyard2 for efficient log processing.
  - **Command**: `sudo snort -A unified2 -c /etc/snort/snort.conf -i eth0`
  - **Usage**: Outputs alerts in unified2 format for post-processing.
- **CSV Output**: Log alerts in CSV format for easy analysis.
  - **Command**: `sudo snort --alert-csv -c /etc/snort/snort.conf -i eth0`
  - **Usage**: Creates CSV files with alert details (e.g., timestamp, source IP).
- **Syslog Integration**: Send alerts to a remote syslog server.
  - **Command**: `sudo snort -s -c /etc/snort/snort.conf -i eth0`
  - **Usage**: Integrates with centralized logging systems.
  
### Advanced Rule Examples 

 **Detect Heartbleed Exploit**:  
	 `plaintext  alert tcp any any -> $HOME_NET 443 (msg:"Heartbleed SSL Exploit"; content:"|18 03|"; depth:2; content:"|01|"; distance:3; within:1; sid:10000020; rev:1;)` 
	 
	**Usage**: Detects Heartbleed attempts by matching SSL/TLS handshake patterns.

**Detect Brute Force SSH**:
	`alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flags:S; threshold: type threshold, track by_src, count 10, seconds 60; sid:10000021; rev:1;) 
	      `
	**Usage**: Alerts on 10 SSH connection attempts from a single source within 60 seconds.

### Integration with Other Tools
- **Wireshark**: Use Wireshark to analyze Snort’s packet captures for detailed inspection.
  - **Command**: `wireshark /var/log/snort/snort.log.* &`
  - **Usage**: Visualizes packets logged by Snort for deeper analysis.
- **Barnyard2**: Process unified2 logs for database storage or SIEM integration.
  - **Command**: `barnyard2 -c /etc/barnyard2.conf -d /var/log/snort`
  - **Usage**: Reads Snort’s unified2 logs and outputs to a database (e.g., MySQL).
- **SIEM Integration**: Forward alerts to Splunk or ELK Stack via syslog or unified2.
### Common Issues and Fixes
- **Issue**: Snort fails to start with "ERROR: Cannot open rules file".
  - **Fix**: Ensure rule files exist and are readable (e.g., `chmod 644 /etc/snort/rules/local.rules`).
- **Issue**: No alerts generated despite traffic.
  - **Fix**: Verify interface with `ifconfig`, check rules for correct IPs/ports, and use `-v` for verbose output.
- **Issue**: High CPU usage.
  - **Fix**: Reduce rule set size, use BPF filters, or enable multi-threading (`--num-threads`).
### Security Best Practices
- **Run as Non-Root**: Always use `-u snort -g snort` to avoid running as root.
- **Chroot Jail**: Use `-t /chroot/dir` to isolate Snort’s runtime environment.
- **Restrict Permissions**: Limit access to `/etc/snort/` and `/var/log/snort/` (e.g., `chmod 750 /etc/snort`).
- **Network Isolation**: Deploy Snort on a dedicated interface or VLAN to minimize exposure.
### Detecting NMAP Scans

- **Ping Scan**:
    
    - **Rule**: `alert icmp any any -> 192.168.1.105 any (msg:"NMAP ping sweep scan"; sid:1000000; rev:1;)`
        
    - **Command**: `nmap -sP 192.168.1.105 --disable-arp-ping`
        
    - **Usage**: Detects ICMP-based ping scans to identify live hosts. Disables ARP ping for accurate detection.
    
- **TCP Scan**:
    
    - **Rule**: `alert tcp any any -> 192.168.1.105 22 (msg:"NMAP TCP Scan"; flags:S; sid:1000007; rev:1;)`
        
    - **Command**: `nmap -sT -p 22 192.168.1.105`
        
    - **Usage**: Identifies TCP SYN scans targeting port 22 (SSH) by checking SYN flag.
    
- **XMAS Scan**:
    
    - **Rule**: `alert tcp any any -> 192.168.1.105 22 (msg:"NMAP XMAS Scan"; flags:FPU; sid:1000008; rev:1;)`
        
    - **Command**: `nmap -sX -p 22 192.168.1.105`
        
    - **Usage**: Detects XMAS scans using FIN, PSH, and URG flags for network enumeration.
    
- **FIN Scan**:
    
    - **Rule**: `alert tcp any any -> 192.168.1.105 22 (msg:"NMAP FIN Scan"; flags:F; sid:1000008; rev:1;)`
        
    - **Command**: `nmap -sF -p 22 192.168.1.105`
        
    - **Usage**: Identifies FIN scans using only FIN flags to probe ports.
    
- **NULL Scan**:
    
    - **Rule**: `alert tcp any any -> 192.168.1.105 22 (msg:"NMAP NULL Scan"; flags:0; sid:1000009; rev:1;)`
        
    - **Command**: `nmap -sN -p 22 192.168.1.105`
        
    - **Usage**: Detects NULL scans with no TCP flags set for stealthy enumeration.
    
- **UDP Scan**:
    
    - **Rule**: similar to TCP rules with `udp` protocol.
        
    - **Command**: `nmap -sU 192.168.1.105`
        
    - **Usage**: Detects UDP scans targeting open UDP ports.

### Detecting SQL Injection Attacks

- **Error-Based SQL Injection**:
    
    - **Rule**:
        
        ```css
        alert tcp any any -> any 80 (msg:"Error Based SQL Injection Detected"; content:"%27"; sid:100000011;)
        
        alert tcp any any -> any 80 (msg:"Error Based SQL Injection Detected"; content:"%22"; sid:100000012;)
        ```
        
    - **Test**: *192.168.1.20/sqli/less-1/?id=1'* or *192.168.1.20/sqli/less-1/?id=1"*
        
    - **Usage**: Captures single *(')* or double quotes *(")* in URLs, indicating error-based SQL injection attempts.

- **Boolean-Based SQL Injection**:
    
    - **Rule**:
        
        ```css
        alert tcp any any -> any 80 (msg:"AND SQL Injection Detected"; content:"and"; nocase; sid:1000000000;)
        
        alert tcp any any -> any 80 (msg:"OR SQL Injection Detected"; content:"or"; nocase; sid:10000000001;)
        ```
        
    - **Test**: *192.168.1.20/sqli/Less-8/?id=1' AND 1=1* or *192.168.1.20/sqli/Less-8/?id=1' OR 1=1*
        
    - **Usage**: Detects *AND/OR* operators in queries, case-insensitive, for Boolean-based attacks.

- **Encoded AND/OR**:
    
    - **Rule**: same as but use  *%26%26* for *(&&)* and *%7C%7C* for *(||)*.
        
    - **Test**: *192.168.1.20/sqli/Less-25/?id=1' %26%26 1=1* or *192.168.1.20/sqli/Less-25/?id=1' %7C%7C 1=1*
        
    - **Usage**: Captures URL-encoded Boolean operators for injection attempts.

- **Form-Based SQL Injection**:
    
    - **Rule**: `alert tcp any any -> any 80 (msg:"Form Based SQL Injection Detected"; content:"%27"; sid:100000013;)`
        
    - **Test**: Inject `'` in login form fields.
        
    - **Usage**: Detects single quotes in POST requests to login forms, indicating form-based attacks.

- **Order By SQL Injection**:
    
    - **Rule**: `alert tcp any any -> any 80 (msg:"order by SQL Injection Detected"; content:"order"; sid:10000005;)`
        
    - **Test**: *192.168.1.20/sqli/?id=1 order by 1*
        
    - **Usage**: Identifies *order* keyword in queries, used to probe database structure.

- **Union-Based SQL Injection**:
    
    - **Rule**: `alert tcp any any -> any 80 (msg:"UNION SELECT SQL Injection"; content:"union"; sid:10000006;)`
        
    - **Test**: *192.168.1.20/sqli/?id=1 union select 1,2,3*
        
    - **Usage**: Detects *union* keyword in queries, used to combine malicious SQL results.

### Detecting Metasploit Attacks

- **Metasploit Meterpreter Reverse TCP**:
    
    - **Rule**:
        
        ```css
        alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Metasploit Meterpreter Reverse TCP Detected"; content:"|00 00 00 01 00 00 00|"; sid:10000030; rev:1;)
        ```
        
    - **Test**: Launch a Meterpreter reverse TCP payload from Metasploit:
        
        ```bash
        msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.2; set LPORT 4444; exploit"
        ```
        
    - **Usage**: Detects Meterpreter’s initial reverse TCP connection by matching a common payload signature (|00 00 00 01 00 00 00|).
        
- **Metasploit SMB Exploit (e.g., EternalBlue)**:
    
    - **Rule**:
        
        ```css
        alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"Metasploit SMB Exploit (EternalBlue) Detected"; content:"|FF|SMB"; depth:4; content:"|00 00 00 85|"; distance:4; within:8; sid:10000031; rev:1;)
        ```
        
    - **Test**: Use Metasploit’s EternalBlue module:
        
        ```bash
        msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.1.105; exploit"
        ```
        
    - **Usage**: Identifies SMB exploit attempts (e.g., MS17-010) by matching SMB packet signatures.
        
- **Metasploit HTTP Exploit (e.g., Apache Struts)**:
    
    - **Rule**:
        
        ```css
        alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Metasploit Apache Struts Exploit Detected"; content:"Content-Type: application/x-www-form-urlencoded"; content:"%{(#_='multipart/form-data')"; sid:10000032; rev:1;)
        ```
        
    - **Test**: Launch an Apache Struts exploit:
        
        ```bash
        msfconsole -q -x "use exploit/multi/http/struts2_content_type_rce; set RHOSTS 192.168.1.20; exploit"
        ```
        
    - **Usage**: Detects HTTP-based Struts exploits by matching malicious content-type headers.
        
- **Metasploit FTP Exploit**:
    
    - **Rule**:
        
        ```css
        alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"Metasploit FTP Exploit Detected"; content:"USER"; nocase; content:"PASS"; nocase; threshold: type threshold, track by_src, count 10, seconds 60; sid:10000033; rev:1;)
        ```
        
    - **Test**: Use Metasploit’s FTP brute-force or exploit module:
        
        ```bash
        msfconsole -q -x "use auxiliary/scanner/ftp/ftp_login; set RHOSTS 192.168.1.105; exploit"
        ```
        
    - **Usage**: Alerts on rapid FTP login attempts, indicating brute-force or exploit activity.
        
- **Metasploit Shellcode Detection**:
    
    - **Rule**:
        
        ```css
        alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Metasploit Shellcode Detected"; content:"|90 90 90|"; content:"|EB|"; within:10; sid:10000034; rev:1;)
        ```
        
    - **Test**: Deploy a Metasploit payload with shellcode:
        
        ```bash
        msfconsole -q -x "use exploit/windows/smb/ms17_010_psexec; set RHOSTS 192.168.1.105; exploit"
        ```
        
    - **Usage**: Detects common shellcode patterns (e.g., NOP sleds |90 90 90| and jump instructions |EB|) used in Metasploit payloads.
### Snort Setup Commands

- **Live Capture from Interface**:
    
    - **Command**: `snort -c /etc/snort/snort.conf -i eth0`
        
    - **Usage**: Captures live traffic from the specified interface (e.g., *eth0*) for real-time analysis using the configuration file.
        
- **Analyze PCAP File**:
    
    - **Command**: `snort -r /path/to/file.pcap -c /etc/snort/snort.conf`
        
    - **Usage**: Analyzes packets from a previously captured PCAP file, ideal for offline forensic analysis.
        
- **Test Configuration File**:
    
    - **Command**: `snort -c /etc/snort/snort.conf -T`
        
    - **Usage**: Checks the configuration file for errors. Add *-i eth0* to test live capture simultaneously.
        
- **Background Monitoring (Daemon Mode)**:
    
    - **Command**: `snort -c /etc/snort/snort.conf -D`
        
    - **Usage**: Runs Snort as a daemon in the background, continuously monitoring traffic without terminal output.
        
- **Full Live Mode with Logging**:
    
    - **Command**: `snort -A console -i eth0 -c /etc/snort/snort.conf -l /var/log/snort`
        
    - **Usage**: Runs Snort in live mode, outputs alerts to the console, and logs packets to */var/log/snort*.
        
- **Enable Malware Rules (Ubuntu)**:
    
    - **Command**: `sudo grep malware /etc/snort/snort.conf`
        
    - **Usage**: Identifies disabled malware rules in the configuration file. Uncomment the following lines in */etc/snort/snort.conf* to enable them:
        
        ```plaintext
        include $RULE_PATH/malware-backdoor.rules
        include $RULE_PATH/malware-cnc.rules
        include $RULE_PATH/malware-other.rules
        include $RULE_PATH/malware-tools.rules
        ```
        
    - **Usage**: Enables detection of malware-related threats like backdoors and command-and-control (C2) traffic.

### Key Commands

- **Empty Rule Files**:
    
    - **Command**: `echo " " > icmp_rules` or `echo " " > icmp-info_rules`
        
    - **Usage**: Clears rule files to prepare for new rules.
        
- **Edit Rules**:
    
    - **Command**: `sudo gedit /etc/snort/rules/local.rules`
        
    - **Usage**: Opens the local rules file to add or modify Snort rules for custom detection.

