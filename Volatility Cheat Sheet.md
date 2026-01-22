## Image Identification

### `imageinfo`

- **Purpose**: Identifies OS, service pack, architecture, DTB address, and sample collection time.
- **Syntax**: `python vol.py -f <memory_image> imageinfo`
- **Key Output**:
    - Suggested profiles (e.g., `Win7SP0x64`)
    - KDBG address, KPCR, image date/time
- **Notes**:
    - Use `--profile=PROFILE` from output for other plugins.
    - Does not work on hibernation files without correct profile.

### `kdbgscan`

- **Purpose**: Confirms correct profile and KDBG address, reducing false positives.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> kdbgscan`
- **Key Output**:
    - KDBG addresses, profile suggestions, process/module counts
- **Notes**:
    - Use `--kdbg=ADDRESS` to specify valid KDBG for other plugins (e.g., `pslist`).

### `kpcrscan`

- **Purpose**: Scans for KPCR structures, providing CPU details (IDT, GDT, threads, CR3).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> kpcrscan`
- **Key Output**:
    - KPCR offsets, CPU details, KdVersionBlock
- **Notes**:
    - Can help find KDBG via `KPCR.get_kdbg()`.

---

## Processes and DLLs

### `pslist`

- **Purpose**: Lists active processes via `PsActiveProcessHead`.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> pslist [-P]`
- **Options**:
    - `-P`: Show physical offsets.
- **Key Output**:
    - Process name, PID, PPID, threads, handles, session ID, Wow64 status, start/exit times
- **Notes**:
    - Does not detect hidden/unlinked processes.

### `pstree`

- **Purpose**: Displays processes in a tree view, showing parent-child relationships.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> pstree`
- **Key Output**:
    - Hierarchical process list with indentation
- **Notes**:
    - Uses same method as `pslist`, misses hidden processes.

### `psscan`

- **Purpose**: Scans for processes (including hidden/terminated) using `_POOL_HEADER`.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> psscan`
- **Key Output**:
    - Process offsets, names, PIDs, creation/exit times
- **Notes**:
    - Use `--offset=OFFSET` for further analysis of hidden processes.

### `psdispscan`

- **Purpose**: Enumerates processes via `DISPATCHER_HEADER` (alternative to `psscan`).
- **Syntax**: `python vol.py --plugins=contrib/plugins -f <memory_image> --profile=<PROFILE> psdispscan`
- **Notes**:
    - XP x86 only, less maintained.

### `dlllist`

- **Purpose**: Lists loaded DLLs for a process.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> dlllist [-p PID | --offset=OFFSET]`
- **Options**:
    - `-p PID`: Filter by process ID.
    - `--offset=OFFSET`: Analyze hidden process.
- **Key Output**:
    - DLL base, size, load count, path
- **Notes**:
    - For Wow64 processes, use `ldrmodules` for complete DLL list.

### `dlldump`

- **Purpose**: Extracts DLLs from process memory to disk.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> dlldump -D <DIR> [-p PID | --offset=OFFSET | --base=BASEADDR | --regex=REGEX]`
- **Options**:
    - `-D DIR`: Output directory.
    - `--base=BASEADDR`: Dump PE from specific address.
    - `--regex=REGEX`: Match DLL names.
    - `--ignore-case`: Case-insensitive regex.
- **Notes**:
    - Fails if PE header is paged; use `vaddump` for partial extraction.

### `handles`

- **Purpose**: Lists open handles (files, registry keys, mutexes, etc.) for a process.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> handles [-p PID | --physical-offset=OFFSET | -t OBJECTTYPE]`
- **Options**:
    - `-t OBJECTTYPE`: Filter by object type (e.g., `Process`, `File`).
    - `--silent`: Show only named objects.
- **Key Output**:
    - Handle value, access, type, details

### `getsids`

- **Purpose**: Displays SIDs associated with processes.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> getsids`
- **Key Output**:
    - Process name, PID, SIDs (e.g., `Local System`, `Administrators`)

### `cmdscan`

- **Purpose**: Extracts command history from `csrss.exe` (XP/2003/Vista) or `conhost.exe` (Win7).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> cmdscan [--max_history=NUMBER]`
- **Options**:
    - `--max_history=NUMBER`: Set max command history (default: 50).
- **Key Output**:
    - Commands, process name, history buffer details

### `consoles`

- **Purpose**: Extracts console input/output, including screen buffers.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> consoles`
- **Key Output**:
    - Commands, screen output, window titles, aliases, attached processes

### `privs`

- **Purpose**: Displays process privileges, identifying enabled, disabled, or default states.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> privs [-p PID | --offset=OFFSET]`
- **Options**:
    - `-p PID`: Filter by process ID.
    - `--offset=OFFSET`: Analyze hidden process.
- **Key Output**:
    - Privilege name, status (Enabled, Disabled, Default), description
- **Notes**:
    - Useful for detecting privilege escalation.

### `envars`

- **Purpose**: Lists environment variables for a process.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> envars [-p PID | --offset=OFFSET]`
- **Options**:
    - `-p PID`: Filter by process ID.
    - `--offset=OFFSET`: Analyze hidden process.
- **Key Output**:
    - Variable name, value
- **Notes**:
    - Helps identify process-specific configurations or paths.

### `verinfo`

- **Purpose**: Extracts version information from process executables or DLLs.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> verinfo [-p PID | --offset=OFFSET]`
- **Options**:
    - `-p PID`: Filter by process ID.
    - `--offset=OFFSET`: Analyze hidden process.
- **Key Output**:
    - File version, product name, company, etc., from PE resources
- **Notes**:
    - Useful for identifying software versions.

### `enumfunc`

- **Purpose**: Enumerates imported and exported functions from process DLLs.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> enumfunc [-p PID | --offset=OFFSET]`
- **Options**:
    - `-p PID`: Filter by process ID.
    - `--offset=OFFSET`: Analyze hidden process.
- **Key Output**:
    - Function names, addresses, import/export tables
- **Notes**:
    - Helps analyze code injection or hooking.

---

## Process Memory

### `memmap`

- **Purpose**: Maps process memory pages.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> memmap -p <PID>`
- **Key Output**:
    - Virtual/physical address mappings

### `memdump`

- **Purpose**: Dumps process memory to disk.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> memdump -p <PID> -D <DIR>`
- **Options**:
    - `-D DIR`: Output directory.

### `procdump`

- **Purpose**: Dumps process executable to disk.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> procdump -p <PID> -D <DIR>`
- **Options**:
    - `-D DIR`: Output directory.

### `vadinfo`, `vadwalk`, `vadtree`, `vaddump`

- **Purpose**:
    - `vadinfo`: Displays VAD (Virtual Address Descriptor) details.
    - `vadwalk`: Walks VAD nodes.
    - `vadtree`: Shows VAD structure as a tree.
    - `vaddump`: Dumps VAD regions to disk.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> <command> [-p PID | --offset=OFFSET] [-D DIR]`
- **Options** (for `vaddump`):
    - `-D DIR`: Output directory.

---

## Kernel Memory and Objects

### `modules`

- **Purpose**: Lists loaded kernel modules.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> modules`

### `modscan`

- **Purpose**: Scans for kernel modules, including hidden ones.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> modscan`

### `moddump`

- **Purpose**: Dumps kernel modules to disk.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> moddump -D <DIR>`
- **Options**:
    - `-D DIR`: Output directory.

### `ssdt`

- **Purpose**: Displays System Service Descriptor Table.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> ssdt`

### `driverscan`, `filescan`, `mutantscan`, `symlinkscan`, `thrdscan`, `dumpfiles`

- **Purpose**: Scans for kernel objects (drivers, files, mutexes, symbolic links, threads, file objects).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> <command> [-D DIR]`
- **Options** (for `dumpfiles`):
    - `-D DIR`: Output directory.

### `unloadedmodules`

- **Purpose**: Lists unloaded kernel modules.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> unloadedmodules`

---

## Networking

### `connections`, `connscan`, `sockets`, `sockscan`, `netscan`

- **Purpose**:
    - `connections`: Lists active network connections (XP/2003).
    - `connscan`: Scans for connections, including terminated ones.
    - `sockets`: Lists socket objects.
    - `sockscan`: Scans for socket objects.
    - `netscan`: Comprehensive network scan (Vista+).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> <command>`

---

## Registry

### `hivescan`, `hivelist`

- **Purpose**:
    - `hivescan`: Scans for registry hives.
    - `hivelist`: Lists registry hives with virtual/physical addresses.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> <command>`

### `printkey`

- **Purpose**: Displays registry key values.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> printkey -K <KEY_PATH>`

### `hivedump`, `hashdump`, `lsadump`, `userassist`, `shellbags`, `shimcache`, `getservicesids`, `dumpregistry`

- **Purpose**:
    - `hivedump`: Dumps registry hive data.
    - `hashdump`: Extracts password hashes.
    - `lsadump`: Dumps LSA secrets.
    - `userassist`: Shows UserAssist entries.
    - `shellbags`: Lists shellbag entries.
    - `shimcache`: Displays Shim Cache data.
    - `getservicesids`: Retrieves service SIDs.
    - `dumpregistry`: Dumps registry hives to disk.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> <command> [-D DIR]`
- **Options** (where applicable):
    - `-D DIR`: Output directory.

---

## Event Logs

### `evtlogs`

- **Purpose**: Extracts Windows Event Log entries from memory (XP/2003 only).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> evtlogs [-D DIR]`
- **Options**:
    - `-D DIR`: Output directory for dumped logs.
- **Key Output**:
    - Event log records, including timestamps, event IDs, and details
- **Notes**:
    - Limited to XP/2003 due to event log structure changes in later systems.

---

## Internet Explorer History

### `iehistory`

- **Purpose**: Reconstructs Internet Explorer browsing history from process memory.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> iehistory [-p PID | --offset=OFFSET]`
- **Options**:
    - `-p PID`: Filter by process ID (e.g., `iexplore.exe`).
    - `--offset=OFFSET`: Analyze hidden process.
- **Key Output**:
    - URLs, timestamps, cache types, and user details
- **Notes**:
    - Focuses on `iexplore.exe` processes; use `psscan` to find relevant PIDs.

---

## Crash Dumps, Hibernation, and Conversion

### `crashinfo`

- **Purpose**: Analyzes crash dump metadata.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> crashinfo`

### `hibinfo`

- **Purpose**: Analyzes hibernation file metadata.
- **Syntax**: `python vol.py -f <hibernation_file> --profile=<PROFILE> hibinfo`

### `imagecopy`

- **Purpose**: Copies memory image to a new file.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> imagecopy -O <OUTPUT_FILE>`

### `raw2dmp`

- **Purpose**: Converts raw memory dump to Microsoft crash dump.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> raw2dmp -O <OUTPUT_FILE>`

### `vboxinfo`, `vmwareinfo`, `hpakinfo`, `hpakextract`

- **Purpose**:
    - `vboxinfo`: Extracts VirtualBox core dump details.
    - `vmwareinfo`: Analyzes VMware saved state/snapshot metadata.
    - `hpakinfo`: Shows info from HPAK memory dumps.
    - `hpakextract`: Extracts/decompresses HPAK memory dumps.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> <command>`

---

## File System

### `mbrparser`

- **Purpose**: Scans and parses Master Boot Records (MBRs).
- **Syntax**: `python vol.py -f <memory_image> mbrparser [-H | -o OFFSET | -M HASH | -F FULLHASH | -C]`
- **Options**:
    - `-H`: Hex dump of bootcode.
    - `-o OFFSET`: Specify MBR offset.
    - `-M HASH`: Match bootcode MD5 hash.
    - `-F FULLHASH`: Match full bootcode MD5 hash.
    - `-C`: Filter for valid partition tables.
- **Notes**:
    - Requires `distorm3` for disassembly.

### `mftparser`

- **Purpose**: Scans and parses Master File Table (MFT) entries.
- **Syntax**: `python vol.py -f <memory_image> mftparser [--machine=MACHINE | -D DIR | --output=body | --no-check | -E SIZE | -o OFFSET]`
- **Options**:
    - `--machine=MACHINE`: Add machine name to timeline.
    - `-D DIR`: Dump resident data files.
    - `--output=body`: Output in Sleuthkit body format.
    - `--no-check`: Include null timestamp entries.
    - `-E SIZE`: Set MFT entry size (default: 1024).
    - `-o OFFSET`: Parse specific MFT entry.
- **Key Output**:
    - File paths, timestamps, attributes ($STANDARD_INFORMATION, $FILE_NAME, $DATA)

---

## Miscellaneous

### `strings`

- **Purpose**: Maps physical offset strings to process virtual addresses.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> strings -s <STRINGS_FILE> [--output-file=FILE] [-S | -o OFFSET]`
- **Options**:
    - `-s STRINGS_FILE`: Input file from `strings` utility.
    - `-S`: Include hidden processes (from `psscan`).
    - `-o OFFSET`: Specify EPROCESS offset.
- **Notes**:
    - Use Sysinternals `strings -q -o` or GNU `strings -td` for input.
    - Convert EnCase UTF-16 exports to UTF-8/ANSI.

### `volshell`

- **Purpose**: Interactively explores memory image (processes, structures, disassembly).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> volshell`
- **Key Commands**:
    - `ps()`: List processes.
    - `cc(pid=PID)`: Switch process context.
    - `dd(address)`: Display dwords.
    - `db(address)`: Display hexdump.
    - `dt(type, address)`: Overlay structure.
    - `dis(address)`: Disassemble code.
- **Notes**:
    - Supports IPython for tab-completion/history.

### `bioskbd`

- **Purpose**: Reads keystrokes from BIOS memory (e.g., passwords).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> bioskbd`

### `patcher`

- **Purpose**: Applies patches to memory based on XML configuration.
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> patcher -x <XML_FILE> [-w]`
- **Options**:
    - `-w`: Write changes to memory.

### `pagecheck`

- **Purpose**: Diagnoses memory-resident page issues.
- **Syntax**: `python vol.py --plugins=contrib/plugins -f <memory_image> --profile=<PROFILE> pagecheck`
- **Notes**:
    - XP x86 only, less maintained.

### `timeliner`

- **Purpose**: Creates a timeline from memory artifacts (processes, DLLs, threads, etc.).
- **Syntax**: `python vol.py -f <memory_image> --profile=<PROFILE> timeliner [--type=TYPE | --output=body|xlsx | --output-file=FILE | --machine=MACHINE | --hive=HIVE | --user=USER]`
- **Options**:
    - `--type=TYPE`: Filter by artifact (e.g., `Process`, `Registry`, `EvtLog`, `IEHistory`).
    - `--output=body|xlsx`: Output format (TSK body or Excel).
    - `--hive=HIVE`, `--user=USER`: Filter registry data.
- **Key Output**:
    - Timestamps, artifact details
- **Notes**:
    - Includes `evtlogs` and `iehistory` artifacts when specified with `--type`.

---

## General Notes

- **Profile Specification**: Always use `--profile=PROFILE` from `imageinfo` or `kdbgscan` for accuracy.
- **Hidden Processes**: Use `psscan` or `psdispscan` to detect unlinked/hidden processes.
- **Output Directory**: Use `-D DIR` for commands that dump files (e.g., `dlldump`, `vaddump`, `evtlogs`).
- **Offset Usage**: Specify `--offset=OFFSET` for hidden processes/objects from scans.
- **Dependencies**: Some plugins (e.g., `mbrparser`, `timeliner --output=xlsx`) require additional libraries (`distorm3`, `OpenPyxl`).
- **Date and Time**: Current date/time is 01:57 PM EEST, Tuesday, August 05, 2025.