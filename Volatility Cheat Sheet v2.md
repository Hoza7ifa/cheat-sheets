## INFO
A quick reference for key Volatility Framework commands used in memory forensics across Windows, Linux, and Mac OS X. Run commands in a terminal (e.g., Kali Linux) with the syntax:  
`vol.py -f <memory_dump> --profile=<profile> <plugin> [options]`  
Replace `<memory_dump>` with your memory dump file (e.g., `ram.mem`) and `<profile>` with the OS profile (e.g., `Win7SP1x64`, `LinuxUbuntu`, `MacYosemite`). Use `vol.py --info` for profiles, address spaces, and plugins.

## General Usage

|**Command**|**Description**|**Example**|
|---|---|---|
|`--info`|Lists profiles, address spaces, and plugins.|`vol.py --info`|
|`--help`|Shows global command-line options.|`vol.py --help`|
|`[plugin] --help`|Displays plugin-specific arguments.|`vol.py pslist --help`|
|`--plugins=[path]`|Loads plugins from an external directory.|`vol.py --plugins=/path/to/plugins pslist`|
|`--dtb=[addr]` `--kdbg=[addr]`|Specifies DTB or KDBG address for analysis.|`vol.py --dtb=0x00319000 pslist`|
|`--output-file=[file]`|Specifies an output file for results.|`vol.py pslist --output-file=output.txt`|

## Image Identification

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**imageinfo**|Suggests OS profiles and architecture.|`vol.py -f ram.mem imageinfo`|
|**kdbgscan**|Parses Kernel Debugger Data Block for profile detection.|`vol.py -f ram.mem kdbgscan`|

## Windows: Process Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**pslist**|Lists active processes (PIDs, PPIDs, threads, timestamps).|`vol.py -f ram.mem --profile=Win7SP1x64 pslist`|
|**psscan**|Scans for hidden or terminated processes.|`vol.py -f ram.mem --profile=Win7SP1x64 psscan`|
|**pstree**|Shows processes in a parent/child tree.|`vol.py -f ram.mem --profile=Win7SP1x64 pstree`|
|**psxview**|Cross-references process listings to detect hidden processes.|`vol.py -f ram.mem --profile=Win7SP1x64 psxview`|
|**dlllist**|Lists DLLs loaded by a process.|`vol.py -f ram.mem --profile=Win7SP1x64 dlllist -p 116`|
|**dlldump**|Dumps DLLs from a process to a directory.|`vol.py -f ram.mem --profile=Win7SP1x64 dlldump --dump-dir /root/ramdump`|
|**cmdline**|Shows process command-line arguments.|`vol.py -f ram.mem --profile=Win7SP1x64 cmdline -p 116`|
|**vadinfo**|Displays Virtual Address Descriptor (VAD) details.|`vol.py -f ram.mem --profile=Win7SP1x64 vadinfo -p 116`|
|**vaddump**|Dumps VAD allocations to individual files.|`vol.py -f ram.mem --profile=Win7SP1x64 vaddump --dump-dir /root/ramdump`|
|**memdump**|Dumps all valid process pages to a single file.|`vol.py -f ram.mem --profile=Win7SP1x64 memdump --dump-dir /root/ramdump`|
|**handles**|Lists open handles (files, keys, etc.).|`vol.py -f ram.mem --profile=Win7SP1x64 handles -t File`|
|**getsids**|Lists Security Identifiers (SIDs) for a process.|`vol.py -f ram.mem --profile=Win7SP1x64 getsids -p 464`|
|**privs**|Displays process privileges.|`vol.py -f ram.mem --profile=Win7SP1x64 privs -p 464`|
|**envars**|Shows process environment variables.|`vol.py -f ram.mem --profile=Win7SP1x64 envars -p 464`|

## Windows: Malware & Code Injection

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**malfind**|Detects and extracts injected code blocks.|`vol.py -f ram.mem --profile=Win7SP1x64 malfind --dump-dir /root/ramdump`|
|**ldrmodules**|Cross-references DLLs with memory-mapped files.|`vol.py -f ram.mem --profile=Win7SP1x64 ldrmodules`|
|**impscan**|Scans for imported APIs in process/kernel memory.|`vol.py -f ram.mem --profile=Win7SP1x64 impscan -p 116`|
|**procdump**|Dumps process executables to a directory.|`vol.py -f ram.mem --profile=Win7SP1x64 procdump --dump-dir /root/ramdump`|

## Windows: Registry & File Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**hivelist**|Locates registry hives with addresses and paths.|`vol.py -f ram.mem --profile=Win7SP1x64 hivelist`|
|**printkey**|Displays registry key values and data.|`vol.py -f ram.mem --profile=Win7SP1x64 printkey -K "Microsoft\\Windows\\CurrentVersion\\Run"`|
|**hashdump**|Extracts cached domain credentials from registry.|`vol.py -f ram.mem --profile=Win7SP1x64 hashdump`|
|**lsadump**|Dumps LSA secrets (e.g., passwords, RDP keys).|`vol.py -f ram.mem --profile=Win7SP1x64 lsadump`|
|**userassist**|Dumps UserAssist registry data (application usage).|`vol.py -f ram.mem --profile=Win7SP1x64 userassist`|
|**shellbags**|Parses shellbag information from registry.|`vol.py -f ram.mem --profile=Win7SP1x64 shellbags`|
|**shimcache**|Dumps Shim Cache (application compatibility data).|`vol.py -f ram.mem --profile=Win7SP1x64 shimcache`|
|**filescan**|Finds open files, including hidden ones.|`vol.py -f ram.mem --profile=Win7SP1x64 filescan`|
|**dumpfiles**|Dumps files from memory (e.g., registry hives).|`vol.py -f ram.mem --profile=Win7SP1x64 dumpfiles -p 4 --regex=config\\user --name -D /root/ramdump`|

## Windows: Networking & Logs

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**netscan**|Scans for network connections and ports (Vista/7).|`vol.py -f ram.mem --profile=Win7SP1x64 netscan`|
|**connections**|Lists active connections (XP/2003).|`vol.py -f ram.mem --profile=WinXPSP3x86 connections`|
|**sockets**|Lists open sockets (XP/2003).|`vol.py -f ram.mem --profile=WinXPSP3x86 sockets`|
|**connscan**|Scans for residual connections (XP/2003).|`vol.py -f ram.mem --profile=WinXPSP3x86 connscan`|
|**sockscan**|Scans for residual sockets (XP/2003).|`vol.py -f ram.mem --profile=WinXPSP3x86 sockscan`|
|**evtlogs**|Recovers event logs (XP/2003).|`vol.py -f ram.mem --profile=WinXPSP3x86 evtlogs --save-evt -D /root/ramdump`|
|**cmdscan**|Extracts cmd.exe command history.|`vol.py -f ram.mem --profile=Win7SP1x64 cmdscan`|
|**consoles**|Recovers console command history.|`vol.py -f ram.mem --profile=Win7SP1x64 consoles`|
|**iehistory**|Recovers Internet Explorer history (URLs, cache).|`vol.py -f ram.mem --profile=Win7SP1x64 iehistory`|

## Windows: Kernel Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**modules**|Lists loaded kernel modules.|`vol.py -f ram.mem --profile=Win7SP1x64 modules`|
|**modscan**|Scans for hidden or residual kernel modules.|`vol.py -f ram.mem --profile=Win7SP1x64 modscan`|
|**moddump**|Dumps kernel modules to a directory.|`vol.py -f ram.mem --profile=Win7SP1x64 moddump --dump-dir /root/ramdump`|
|**unloadedmodules**|Lists recently unloaded kernel modules.|`vol.py -f ram.mem --profile=Win7SP1x64 unloadedmodules`|
|**timers**|Displays kernel timers and DPCs.|`vol.py -f ram.mem --profile=Win7SP1x64 timers`|
|**callbacks**|Lists kernel callbacks and notification routines.|`vol.py -f ram.mem --profile=Win7SP1x64 callbacks`|
|**ssdt**|Audits System Service Descriptor Table (SSDT).|`vol.py -f ram.mem --profile=Win7SP1x64 ssdt --verbose`|
|**idt**|Audits Interrupt Descriptor Table (x86 only).|`vol.py -f ram.mem --profile=WinXPSP3x86 idt`|
|**gdt**|Audits Global Descriptor Table (x86 only).|`vol.py -f ram.mem --profile=WinXPSP3x86 gdt`|
|**driverirp**|Audits driver dispatch (IRP) tables.|`vol.py -f ram.mem --profile=Win7SP1x64 driverirp --regex=tcpip`|
|**devicetree**|Displays device tree (stacked drivers).|`vol.py -f ram.mem --profile=Win7SP1x64 devicetree`|
|**pooltracker**|Shows kernel pool tag usage statistics.|`vol.py -f ram.mem --profile=Win7SP1x64 pooltracker`|

## Windows: General Investigations

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**yarascan**|Scans memory for Yara signatures.|`vol.py -f ram.mem --profile=Win7SP1x64 yarascan -Y "http://[a-z]+\.com" --wide`|
|**mftparser**|Parses Master File Table (MFT) entries.|`vol.py -f ram.mem --profile=Win7SP1x64 mftparser --output-body > mft.txt`|
|**timeliner**|Creates timeline in body format for SleuthKit.|`vol.py -f ram.mem --profile=Win7SP1x64 timeliner --output=body > time.txt`|
|**clipboard**|Extracts ASCII/Unicode clipboard content.|`vol.py -f ram.mem --profile=Win7SP1x64 clipboard`|
|**wndscan**|Scans for window stations (e.g., clipboard spying).|`vol.py -f ram.mem --profile=Win7SP1x64 wndscan`|

## Linux: Process Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**linux_pslist**|Lists active processes.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_pslist`|
|**linux_pidhashtable**|Lists processes and threads via PID hash table.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_pidhashtable`|
|**linux_pstree**|Shows processes in a parent/child tree.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_pstree`|
|**linux_psxview**|Cross-references process listings.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_psxview`|
|**linux_psaux**|Shows command-line arguments.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_psaux -p 1234`|
|**linux_library_list**|Lists shared libraries for a process.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_library_list -p 1234`|
|**linux_threads**|Lists threads for a process.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_threads -p 1234`|
|**linux_proc_maps**|Displays memory ranges for a process.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_proc_maps -p 1234`|
|**linux_dump_map**|Dumps memory ranges to files.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_dump_map --dump-dir /root/ramdump`|
|**linux_lsof**|Lists open file handles.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_lsof -p 1234`|
|**linux_psenv**|Shows environment variables.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_psenv -p 1234`|

## Linux: Malware & Code Injection

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**linux_malfind**|Detects injected code blocks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_malfind --dump-dir /root/ramdump`|
|**linux_ldrmodules**|Cross-references libraries with memory-mapped files.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_ldrmodules`|
|**linux_process_hollow**|Checks for process hollowing.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_process_hollow -p 1234`|
|**linux_apihooks**|Scans for userland API hooks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_apihooks`|
|**linux_plthook**|Scans for GOT/PLT hooks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_plthook`|

## Linux: Networking & File System

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**linux_netstat**|Lists active network connections.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_netstat`|
|**linux_ifconfig**|Shows network interface information.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_ifconfig`|
|**linux_arp**|Displays ARP cache.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_arp`|
|**linux_route_cache**|Shows routing cache.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_route_cache`|
|**linux_netfilter**|Lists Netfilter entries.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_netfilter`|
|**linux_mount**|Lists mount points.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_mount`|
|**linux_enumerate_files**|Enumerates files in memory.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_enumerate_files`|
|**linux_find_file**|Extracts cached files.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_find_file --find=/etc/passwd`|

## Linux: Kernel Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**linux_lsmod**|Lists loaded kernel modules.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_lsmod`|
|**linux_check_syscall**|Checks for system call hooks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_check_syscall`|
|**linux_check_afinfo**|Checks for network stack hooks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_check_afinfo`|
|**linux_check_fop**|Checks for file operation hooks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_check_fop`|
|**linux_check_inline_kernel**|Checks for inline kernel hooks.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_check_inline_kernel`|
|**linux_check_modules**|Checks for hidden kernel modules.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_check_modules`|
|**linux_dmesg**|Prints kernel debug buffer.|`vol.py -f linux.mem --profile=LinuxUbuntu linux_dmesg`|

## Mac OS X: Process Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**mac_pslist**|Lists active processes.|`vol.py -f mac.mem --profile=MacYosemite mac_pslist`|
|**mac_pid_hash_table**|Lists PID hash table.|`vol.py -f mac.mem --profile=MacYosemite mac_pid_hash_table`|
|**mac_pstree**|Shows processes in a parent/child tree.|`vol.py -f mac.mem --profile=MacYosemite mac_pstree`|
|**mac_psxview**|Cross-references process listings.|`vol.py -f mac.mem --profile=MacYosemite mac_psxview`|
|**mac_psaux**|Shows command-line arguments.|`vol.py -f mac.mem --profile=MacYosemite mac_psaux -p 1234`|
|**mac_dyld_maps**|Lists shared libraries.|`vol.py -f mac.mem --profile=MacYosemite mac_dyld_maps -p 1234`|
|**mac_proc_maps**|Displays memory ranges for a process.|`vol.py -f mac.mem --profile=MacYosemite mac_proc_maps -p 1234`|
|**mac_lsof**|Lists open file handles.|`vol.py -f mac.mem --profile=MacYosemite mac_lsof -p 1234`|
|**mac_psenv**|Shows environment variables.|`vol.py -f mac.mem --profile=MacYosemite mac_psenv -p 1234`|
|**mac_list_sessions**|Lists login sessions.|`vol.py -f mac.mem --profile=MacYosemite mac_list_sessions`|

## Mac OS X: Malware & Code Injection

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**mac_malfind**|Detects injected code blocks.|`vol.py -f mac.mem --profile=MacYosemite mac_malfind --dump-dir /root/ramdump`|
|**mac_ldrmodules**|Cross-references libraries with memory-mapped files.|`vol.py -f mac.mem --profile=MacYosemite mac_ldrmodules`|
|**mac_apihooks**|Scans for API hooks.|`vol.py -f mac.mem --profile=MacYosemite mac_apihooks`|
|**mac_process_hollow**|Checks for process hollowing.|`vol.py -f mac.mem --profile=MacYosemite mac_process_hollow -p 1234`|
|**mac_plthook**|Scans for GOT/PLT hooks.|`vol.py -f mac.mem --profile=MacYosemite mac_plthook`|

## Mac OS X: Networking & File System

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**mac_netstat**|Lists active network connections.|`vol.py -f mac.mem --profile=MacYosemite mac_netstat`|
|**mac_network_conns**|Lists connections from network stack.|`vol.py -f mac.mem --profile=MacYosemite mac_network_conns`|
|**mac_ifconfig**|Shows network interface information.|`vol.py -f mac.mem --profile=MacYosemite mac_ifconfig`|
|**mac_arp**|Displays ARP cache.|`vol.py -f mac.mem --profile=MacYosemite mac_arp`|
|**mac_route**|Shows routing table.|`vol.py -f mac.mem --profile=MacYosemite mac_route`|
|**mac_mount**|Lists mount points.|`vol.py -f mac.mem --profile=MacYosemite mac_mount`|
|**mac_list_files**|Lists cached files and their vnode addresses.|`vol.py -f mac.mem --profile=MacYosemite mac_list_files`|
|**mac_dump_file**|Extracts cached files.|`vol.py -f mac.mem --profile=MacYosemite mac_dump_file --file-offset=0x1234`|

## Mac OS X: Kernel Analysis

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**mac_lsmod**|Lists loaded kernel modules.|`vol.py -f mac.mem --profile=MacYosemite mac_lsmod`|
|**mac_apihooks_kernel**|Checks for kernel API hooks.|`vol.py -f mac.mem --profile=MacYosemite mac_apihooks_kernel`|
|**mac_check_syscalls**|Checks for system call hooks.|`vol.py -f mac.mem --profile=MacYosemite mac_check_syscalls`|
|**mac_check_sysctl**|Checks sysctl handlers.|`vol.py -f mac.mem --profile=MacYosemite mac_check_sysctl`|
|**mac_check_trap_table**|Checks trap table.|`vol.py -f mac.mem --profile=MacYosemite mac_check_trap_table`|
|**mac_dmesg**|Prints kernel debug buffer.|`vol.py -f mac.mem --profile=MacYosemite mac_dmesg`|

## Advanced Analysis (Cross-Platform)

|**Plugin**|**Description**|**Example Command**|
|---|---|---|
|**yarascan**|Scans for Yara signatures (Windows/Linux/Mac).|`vol.py -f mem.mem --profile=Win7SP1x64 yarascan -Y "http://[a-z]+\.com" --wide`|
|**timeliner**|Creates timeline for SleuthKit (combine with mactime).|`vol.py -f mem.mem --profile=Win7SP1x64 timeliner --output=body > time.txt`|
|**volshell**|Interactive shell for memory analysis.|`vol.py -f mem.mem --profile=Win7SP1x64 volshell`|
|**strings**|Translates extracted strings (platform-specific).|`vol.py -f mem.mem --profile=LinuxUbuntu linux_strings -s strings.txt`|

## Volatility Workbench

A free, open-source GUI for Volatility on Windows, simplifying memory dump analysis.

- **Features**:
    - No need to memorize command-line parameters.
    - Stores dump information to disk.
    - Drop-down list with commands and descriptions.
- **Usage**: Download from [volatilityfoundation.org](https://volatilityfoundation.org/), select a dump file, choose the profile, click _Refresh Process List_, and run commands.

## Notes

- **Supported Formats**: Raw, Hibernation File, VM Snapshot, Microsoft Crash Dump.
- **Profile Selection**: Use `imageinfo` or `kdbgscan` to identify the correct profile.
- **Performance**: Commands may take time based on dump size.
- **Timeline Creation**: Combine `timeliner`, `shellbags`, and `mftparser` output with `mactime -b time.txt -d > csv.txt`.
- **Volshell Commands**:
    - List processes: `ps()`
    - Switch context: `cc(pid=3028)` or `cc(name="explorer.exe")`
    - Disassemble: `dis(address, length)`
    - Display structures: `dt("EPROCESS", 0x1820c92a0)`

