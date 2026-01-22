
## Installation

Install `tshark` (part of Wireshark CLI) on various systems:

- **Ubuntu/Debian**:
    
    ```bash
    sudo apt install tshark
    ```
    
- **Fedora**:
    
    ```bash
    sudo dnf install wireshark-cli
    ```
    
- **Red Hat/CentOS Stream**:
    
    ```bash
    sudo yum install wireshark-cli
    ```
    
- **Arch Linux**:
    
    ```bash
    sudo pacman -S wireshark-cli
    ```
    
- **Windows** (via installer): Download from [Wireshark.org](https://www.wireshark.org/).

---

## Basic Commands

### List Available Interfaces

List all network interfaces available for capture:

```bash
tshark -D
```

List data link types for an interface:

```bash
tshark -L -i wlan0
```

List timestamp types for an interface:

```bash
tshark --list-time-stamp-types -i wlan0
```

### Capture Traffic

Capture traffic on a specific interface (e.g., `wlan0`):

```bash
tshark -i wlan0
```

Capture a specific number of packets (e.g., 3):

```bash
tshark -i wlan0 -c 3
```

Capture for a specific duration (e.g., 10 seconds):

```bash
tshark -i wlan0 -a duration:10
```

Capture in monitor mode (for Wi-Fi interfaces):

```bash
tshark -i wlan0 -I
```

Disable promiscuous mode:

```bash
tshark -i wlan0 -p
```

Capture from a pipe or stdin:

```bash
tshark -i -
```

Capture from a remote interface (rpcap):

```bash
tshark -i "TCP@<host>:<port>" -A <user>:<password>
```

Set snapshot length (e.g., 96 bytes):

```bash
tshark -i wlan0 -s 96
```

Set link layer type (e.g., EN10MB):

```bash
tshark -i wlan0 -y EN10MB
```

Set timestamp type:

```bash
tshark -i wlan0 --time-stamp-type host
```

### Save Captured Data

Save captured packets to a PCAP file:

```bash
tshark -i wlan0 -w output.pcap
```

Save with compression (e.g., gzip):

```bash
tshark -i wlan0 -w output.pcap.gz --compress gzip
```

Add a capture comment:

```bash
tshark -i wlan0 -w output.pcap --capture-comment "Test capture"
```

### Read a PCAP File

Read and display packets from a PCAP file:

```bash
tshark -r output.pcap
```

Read without resolving names (faster):

```bash
tshark -nr output.pcap
```

Read with a specific file format:

```bash
tshark -r file.pcap -X read_format:"MIME Files Format"
```

### Colorize Output

Enable colored output (requires 24-bit color terminal):

```bash
tshark --color
```

---

## Filtering Traffic

Tshark supports **capture filters** (applied during capture, using libpcap syntax) and **display filters** (applied post-capture, using Wireshark syntax).

### Capture Filters

Use `-f` to apply filters during capture (lowercase recommended):

- Filter by IP address (e.g., `93.184.216.34`):
    
    ```bash
    tshark -i wlan0 -f "host 93.184.216.34"
    ```
    
- Filter by port (e.g., port 80):
    
    ```bash
    tshark -i wlan0 -f "port 80"
    ```
    
- Exclude ARP and DNS:
    
    ```bash
    tshark -i wlan0 -f "port not 53 and not arp"
    ```
    
- Filter DHCP traffic:
    
    ```bash
    tshark -i wlan0 -f "port bootpc"
    ```
    
- Use predefined capture filter:
    
    ```bash
    tshark -i wlan0 -f "predef:MyPredefinedHostOnlyFilter"
    ```
    

### Display Filters

Use `-Y` (or `-R` with `-2` for older versions) to filter displayed packets:

- Filter TCP packets on port 80:
    
    ```bash
    tshark -r output.pcap -Y "tcp.port == 80"
    ```
    
- Filter by source IP (e.g., `192.168.246.198`):
    
    ```bash
    tshark -r output.pcap -Y "ip.src == 192.168.246.198"
    ```
    
- Filter by TTL greater than 10:
    
    ```bash
    tshark -r output.pcap -Y "ip.ttl > 10"
    ```
    
- Exclude traffic to/from an IP:
    
    ```bash
    tshark -r output.pcap -Y "ip.addr != 93.184.216.34"
    ```
    
- Filter HTTP GET requests:
    
    ```bash
    tshark -r output.pcap -Y "http.request.method == GET"
    ```
    
- Filter TCP SYN packets (not port 80):
    
    ```bash
    tshark -r output.pcap -Y "not tcp.port == 80 and tcp.flags == 0x0002"
    ```
    

---

## Output Formatting

### Export to Different Formats

- Export to XML (PDML format):
    
    ```bash
    tshark -i wlan0 -T pdml > capture.xml
    ```
    
- Export to JSON:
    
    ```bash
    tshark -r output.pcap -T json
    ```
    
- Export to JSON with protocol filter:
    
    ```bash
    tshark -r output.pcap -T json -j "http tcp ip"
    ```
    
- Export to JSON with hex data:
    
    ```bash
    tshark -r output.pcap -T json -x
    ```
    
- Export to JSON (raw packet data):
    
    ```bash
    tshark -r output.pcap -T jsonraw
    ```
    
- Export to CSV with specific fields:
    
    ```bash
    tshark -i wlan0 -T fields -e frame.number -e ip.src -e ip.dst -e frame.len -e frame.time -e frame.time_relative -e _ws.col.Info -E header=y -E separator=, -E quote=d > capture.csv
    ```
    
- Export to PostScript:
    
    ```bash
    tshark -r output.pcap -T ps > capture.ps
    ```
    
- Export to Packet Summary Markup Language (PSML):
    
    ```bash
    tshark -r output.pcap -T psml > capture.psml
    ```
    
- Export objects (e.g., HTTP files):
    
    ```bash
    tshark -r output.pcap --export-objects http,/tmp/exported_files
    ```
    

### Field Selection

Use `-T fields` with `-e` to select specific fields:

- Extract HTTP host and user agent:
    
    ```bash
    tshark -i wlan0 -Y http.request -T fields -e http.host -e http.user_agent
    ```
    
- Extract DNS query and response:
    
    ```bash
    tshark -i wlan0 -f "src port 53" -T fields -e dns.qry.name -e dns.resp.addr
    ```
    
- Extract SSL Client Hello server names:
    
    ```bash
    tshark -r output.pcap -Y "ssl.handshake.type == 1" -T fields -e ip.src -e ip.dst -e ssl.handshake.extensions_server_name
    ```
    
- Append field to Info column:
    
    ```bash
    tshark -r output.pcap -z proto,colinfo,nfs.fh.hash,nfs.fh.hash
    ```
    

### Common Output Options

- `-E header=y`: Include header in output.
- `-E separator=,`: Use comma as field separator.
- `-E quote=d`: Quote field values with double quotes.
- `-E bom=y`: Add UTF-8 BOM to output.
- `-E occurrence=f|l|a`: Select first, last, or all occurrences of a field.
- `-E aggregator=,`: Use comma as aggregator for multiple field occurrences.
- `-E escape=n`: Disable C-style escapes for whitespace characters.
- `-V`: Display detailed packet information.
- `-O <protocol>`: Show detailed view for specific protocols (e.g., `-O http`).
- `-P`: Print packet summary even when writing to a file.
- `-S <separator>`: Set line separator between packets (e.g., `-S ,`).
- `-x`: Include hex and ASCII dump of packet data.
- `--hexdump frames`: Dump only frame data source.
- `--hexdump noascii`: Exclude ASCII dump text.
- `--hexdump delimit`: Delimit ASCII dump text with `|` characters.
- `-l`: Flush output after each packet (sets `--update-interval 0`).
- `--no-duplicate-keys`: Merge duplicate JSON keys into an array.

### Timestamp Formatting

Set timestamp format with `-t`:

- Absolute time (`-t a`): Local time, no date.
- Absolute with date (`-t ad`): YYYY-MM-DD, local time.
- Absolute with day of year (`-t adoy`): YYYY/DOY, local time.
- Delta time (`-t d`): Time since previous packet.
- Delta displayed (`-t dd`): Time since previous displayed packet.
- Epoch time (`-t e`): Seconds since Jan 1, 1970.
- Relative time (`-t r`): Time since first packet (default).
- UTC time (`-t u`): UTC, no date.
- UTC with date (`-t ud`): YYYY-MM-DD, UTC.
- UTC with day of year (`-t udoy`): YYYY/DOY, UTC.
- Set precision (e.g., 3 decimals): `-t ad.3`
- Auto precision: `-t ad.`
- Seconds format (`-u s`): Display relative times in seconds (default).
- Hours, minutes, seconds (`-u hms`): Display relative times in HH:MM:SS.

---

## Advanced Analysis

### Protocol Hierarchy Statistics

Display protocol hierarchy statistics:

```bash
tshark -r output.pcap -qz io,phs
```

### Conversation Statistics

Display conversation statistics (e.g., TCP):

```bash
tshark -r output.pcap -z conv,tcp
```

### Endpoint Statistics

Display endpoint statistics (e.g., IP):

```bash
tshark -r output.pcap -z endpoints,ip
```

### TCP Stream Analysis

Follow a TCP stream (ASCII format):

```bash
tshark -r output.pcap -z "follow,tcp,ascii,10.0.0.1:123,10.0.0.2:456"
```

### Count and Sort Fields

Sort and count HTTP user agents:

```bash
tshark -r output.pcap -Y http.request -T fields -e http.user_agent | sort | uniq -c | sort -n
```

### Service Response Time (SRT) Statistics

- SMB SRT statistics:
    
    ```bash
    tshark -r output.pcap -z smb,srt
    ```
    
- Diameter SRT statistics:
    
    ```bash
    tshark -r output.pcap -z diameter,srt
    ```
    
- RPC SRT for NFS v3:
    
    ```bash
    tshark -r output.pcap -z rpc,srt,100003,3
    ```
    

### Packet Length Statistics

Display packet length distribution:

```bash
tshark -r output.pcap -z plen,tree
```

### SSL/TLS Analysis

- Extract SSL Client Hello server names:
    
    ```bash
    tshark -r output.pcap -Y "ssl.handshake.type == 1" -T fields -e ip.src -e ip.dst -e ssl.handshake.extensions_server_name
    ```
    
- Extract SSL certificate domain names:
    
    ```bash
    tshark -r output.pcap -Y "ssl.handshake.type == 11" -T fields -e x509ce.dNSName
    ```
    
- List unique cipher suites with SHA1 signatures:
    
    ```bash
    tshark -r output.pcap -Y "ssl.handshake.type == 1" -T fields -e ssl.handshake.ciphersuite | sort -u | xargs -I {} sh -c 'echo -n {}" " && echo -n {} | sha1sum' | awk '{printf $2" "$1"\n"}'
    ```
    
- Export TLS session keys:
    
    ```bash
    tshark -r output.pcap --export-tls-session-keys keys.txt
    ```
    

### Decryption

- Decrypt WPA traffic:
    
    ```bash
    tshark -r output.pcap -o wlan.enable_decryption:TRUE -o "uat:80211_keys:\"wpa-pwd\",\"password:<w1F1-P4ssw0rD\"" -T fields -e http.file_data
    ```
    
- Decrypt SSL with private key:
    
    ```bash
    tshark -r output.pcap -o 'uat:rsa_keys:"./server_private_key.pem",""' -T fields -e text
    ```
    
- Decrypt SSL with pre-master secret:
    
    ```bash
    tshark -r output.pcap -o 'tls.keylog_file:./premastersecret.txt' -T fields -e http.request.uri
    ```
    
- Load Kerberos keys:
    
    ```bash
    tshark -r output.pcap -K krb5.keytab
    ```
    

### IO Statistics

- Packet/byte statistics per interval (e.g., 1 second):
    
    ```bash
    tshark -r output.pcap -z io,stat,1
    ```
    
- Statistics for specific filter (e.g., IP address):
    
    ```bash
    tshark -r output.pcap -z io,stat,1,ip.addr==1.2.3.4
    ```
    
- Calculate average SMB response time:
    
    ```bash
    tshark -r output.pcap -z io,stat,0,"AVG(smb.time)smb.time"
    ```
    

### Glossary Reports

Dump various glossaries (e.g., fields):

```bash
tshark -G fields
```

Available report types:

- `column-formats`, `currentprefs`, `decodes`, `defaultprefs`, `dissectors`, `dissector-tables`, `elastic-mapping`, `enterprises`, `fieldcount`, `fields`, `folders`, `ftypes`, `heuristic-decodes`, `manuf`, `plugins`, `protocols`, `services`, `values`

---

## Common Fields

List all available fields:

```bash
tshark -G fields
```

### Ethernet (`eth`)

- `addr`, `src`, `dst`, `len`, `type`, `multicast`

### IPv4 (`ip`)

- `addr`, `src`, `dst`, `proto`, `ttl`, `len`, `checksum`, `flags`

### IPv6 (`ipv6`)

- `addr`, `src`, `dst`, `nxt`, `hlim`, `plen`

### TCP (`tcp`)

- `port`, `srcport`, `dstport`, `flags`, `seq`, `ack`, `window_size`, `payload`

### UDP (`udp`)

- `port`, `srcport`, `dstport`, `length`, `checksum`

### HTTP (`http`)

- `request.method`, `request.full_uri`, `user_agent`, `host`, `response.code`, `content_type`, `file_data`

### SSL (`ssl`)

- `handshake.type`, `handshake.extensions_server_name`, `handshake.ciphersuite`, `x509ce.dNSName`

---

## Capture Options

- `-B <size>`: Set kernel buffer size (default: 2MB).
- `-c <count>`: Stop after capturing `count` packets.
- `-a <condition>`: Stop capture based on:
    - `duration:NUM` (seconds)
    - `filesize:NUM` (KB)
    - `files:NUM` (number of files)
    - `packets:NUM` (number of packets)
- `-b <ringbuffer>`: Configure ring buffer:
    - `duration:NUM` (switch file after seconds)
    - `filesize:NUM` (switch file after KB)
    - `files:NUM` (replace after number of files)
    - `packets:NUM` (switch after number of packets)
    - `interval:NUM` (switch at exact multiple of seconds)
    - `printname:FILE` (print filename to FILE)
    - `nametimenum:1|2` (set filename format: number before/after timestamp)
- `--update-interval <ms>`: Set packet report interval (default: 100ms).

---

## Dissection Options

- Enable specific protocol:
    
    ```bash
    tshark --enable-protocol http
    ```
    
- Disable specific protocol:
    
    ```bash
    tshark --disable-protocol http
    ```
    
- Enable only specific protocols:
    
    ```bash
    tshark --only-protocols http,tcp,ip
    ```
    
- Disable all protocols:
    
    ```bash
    tshark --disable-all-protocols
    ```
    
- Enable heuristic dissector:
    
    ```bash
    tshark --enable-heuristic quic
    ```
    
- Disable heuristic dissector:
    
    ```bash
    tshark --disable-heuristic quic
    ```
    
- Decode as (e.g., TCP port 8888 as HTTP):
    
    ```bash
    tshark -d tcp.port==8888,http
    ```
    

---

## Name Resolution

- Disable all name resolution:
    
    ```bash
    tshark -n
    ```
    
- Enable specific name resolution:
    
    ```bash
    tshark -N mntd
    ```
    
    - `m`: MAC address resolution
    - `n`: Network address resolution
    - `t`: Transport-layer port resolution
    - `d`: DNS packet resolution
    - `N`: External resolver (e.g., DNS)
    - `s`: SNI-based address resolution
    - `v`: VLAN ID resolution
    - `g`: IP geolocation lookup
- Read hosts file:
    
    ```bash
    tshark -H hosts.txt
    ```
    

---

## Diagnostic Options

- Set log level (e.g., debug):
    
    ```bash
    tshark --log-level debug
    ```
    
- Abort on specific log level:
    
    ```bash
    tshark --log-fatal warning
    ```
    
- Filter log domains:
    
    ```bash
    tshark --log-domains GUI,Epan
    ```
    
- Set debug log domains:
    
    ```bash
    tshark --log-debug GUI,Epan
    ```
    
- Set noisy log domains:
    
    ```bash
    tshark --log-noisy GUI,Epan
    ```
    
- Log to file:
    
    ```bash
    tshark --log-file log.txt
    ```
    
- Print processing timers:
    
    ```bash
    tshark -r output.pcap --print-timers
    ```
    

---

## Miscellaneous

- Use configuration profile:
    
    ```bash
    tshark -C myprofile
    ```
    
- Use global profile:
    
    ```bash
    tshark --global-profile
    ```
    
- Set temporary directory:
    
    ```bash
    tshark --temp-dir /tmp/custom
    ```
    
- Override preferences:
    
    ```bash
    tshark -o gui.scrollbar_on_right:TRUE
    ```
    
- Load Lua script:
    
    ```bash
    tshark -X lua_script:my.lua
    ```
    
- Pass argument to Lua script:
    
    ```bash
    tshark -X lua_script1:foo
    ```
    
- Suppress packet counts:
    
    ```bash
    tshark -q
    ```
    
- Suppress all non-error output:
    
    ```bash
    tshark -Q
    ```
    
- Show help:
    
    ```bash
    tshark -h
    ```
    
- Show version:
    
    ```bash
    tshark -v
    ```
    
- Perform two-pass analysis:
    
    ```bash
    tshark -2 -r output.pcap
    ```
    
- Auto reset session after packets:
    
    ```bash
    tshark -M 100000
    ```
    

---

## Environment Variables

- `WIRESHARK_CONFIG_DIR`: Override personal config directory.
- `WIRESHARK_DEBUG_WMEM_OVERRIDE`: Force memory allocator backend.
- `WIRESHARK_RUN_FROM_BUILD_DIRECTORY`: Load files from build directory.
- `WIRESHARK_DATA_DIR`: Override data file directory.
- `WIRESHARK_EXTCAP_DIR`: Override extcap directory.
- `WIRESHARK_PLUGIN_DIR`: Override plugin directory.
- `ERF_RECORDS_TO_CHECK`: Set ERF record check count.
- `IPFIX_RECORDS_TO_CHECK`: Set IPFIX record check count.
- `WIRESHARK_ABORT_ON_DISSECTOR_BUG`: Abort on dissector bug.
- `WIRESHARK_ABORT_ON_TOO_MANY_ITEMS`: Abort on excessive tree items.
- `WIRESHARK_LOG_LEVEL`: Set console log verbosity.
- `WIRESHARK_LOG_FATAL`: Set fatal log level.
- `WIRESHARK_LOG_DOMAINS`: Filter active log domains.
- `WIRESHARK_LOG_DEBUG`: Set debug log domains.
- `WIRESHARK_LOG_NOISY`: Set noisy log domains.

---

## Configuration Files

- **Preferences**: `$HOME/.config/wireshark/preferences` (Unix) or `%APPDATA%\Wireshark\preferences` (Windows).
- **Disabled Protocols**: `disabled_protos` in preferences directory.
- **Enabled Protocols**: `enabled_protos` in preferences directory.
- **Heuristic Dissectors**: `heuristic_protos` in preferences directory.
- **Hosts**: `hosts` in preferences directory for IP resolution.
- **Subnets**: `subnets` for partial IP matches.
- **Ethers**: `ethers` for MAC address resolution.
- **Manuf**: `manuf` for vendor OUI resolution.
- **Services**: `services` for port-to-name mapping.
- **IPX Networks**: `ipxnets` for IPX network resolution.
- **SS7 Point Codes**: `ss7pcs` for SS7 point code resolution.
- **VLANs**: `vlans` for VLAN ID resolution.
- **Color Filters**: `colorfilters` for packet coloring rules.

---

## Tips

- Use capture filters (`-f`) to reduce capture size and save disk space.
- Use display filters (`-Y`) for flexible post-capture analysis.
- Combine `-T fields` with `-e` to extract specific packet data.
- Press `Ctrl+C` to stop capturing.
- Check Wireshark documentation for protocol-specific fields: [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/).
- Enable BPF JIT for better performance (Unix):
    
    ```bash
    echo 1 > /proc/sys/net/core/bpf_jit_enable
    ```
    

---

## Notes

- Some older versions use `-R` instead of `-Y` for display filters with `-2`.
- Ensure capture filter strings are lowercase.
- Use `-2` for two-pass analysis with complex display filters (not supported for live captures).
- For SSL decryption, ensure key files are accessible and correctly formatted.
- Output is UTF-8; on Windows consoles, use `chcp 65001` for proper display.
- Statistics (`-z`) are calculated independently of display filters but can include their own filters.