# Advanced Digital Forensics & Artifact Analysis

**Level**: Advanced (20+ years forensics and incident response experience)
**Focus**: Memory forensics, disk analysis, steganography, and data extraction techniques

## Memory Forensics (Volatility & Manual Analysis)

### Memory Dump Acquisition

#### Volatility Framework Workflow
- **Identify OS**: `imageinfo` plugin (memory profile contains Windows version, kernel, etc.)
- **Essential commands**:
  - `processes`: List all running processes (compare against tasklist for hidden processes)
  - `dlllist`: Loaded DLLs per process (identify injected code)
  - `netscan`: Network connections (open ports, established connections)
  - `filescan`: Open file handles (what files are currently accessed)
  - `cmdscan` / `consoles`: Command history from cmd.exe, PowerShell

#### Process Memory Extraction
- **Dump process**: `vol.py -f dump.bin --profile=Win7SP1x64 memdump -p PID -D ./output/`
- **Analyze strings**: Search for flags, credentials, URLs in extracted memory
- **API hooks**: Check if DLL base addresses are suspicious (injected code detection)

#### Kernel-Level Analysis
- **Rootkit detection**: Volatility's `rootkit` plugin detects kernel hooks
- **SSDT hooks**: System Service Dispatch Table manipulation (common malware technique)
- **IRQ/IDT hooks**: Interrupt table manipulation
- **Driver enumeration**: Unrecognized drivers often malicious

### Malware Behavior Analysis

#### Injected Code Detection
- **Compare processes**: Parent-child relationships (legitimate parent-child is: explorer.exe → cmd.exe → program)
- **Suspicious patterns**: svchost.exe should have no children; cmd.exe spawning powershell is suspicious
- **Memory anomalies**: PE header detection in non-standard memory regions
- **Packer detection**: Entropy analysis, UPX magic bytes, VirtualAlloc + WriteProcessMemory pattern

#### Credential & Session Extraction
- **LSASS.exe**: Contains hashed passwords, Kerberos tickets, CredMan secrets
  - Dump LSASS: `vol.py -f dump.bin --profile=Win7SP1x64 memdump -p LSASS_PID -D ./output/`
  - Run mimikatz on dump: `sekurlsa::minidump lsass.dmp`
  - Extract hashes, plaintext passwords (if cached), Kerberos tickets
- **Browser memory**: Chrome/Firefox process contains session cookies, cached passwords, autofill data
  - Dump process, search for known patterns (JSESSIONID=, auth=, Cookie:)
- **Clipboard**: Windows clipboard data persists in memory
  - Volatility: `clipboard` plugin (recent versions)
  - Search memory for recently copied data (flags often copy-pasted)

### Suspicious Artifacts

#### Code Caves & Anomalies
- **Allocated but unexecuted**: VirtualAlloc memory with suspicious content (staging area)
- **Heap spraying**: Many allocations of same size/content (pre-exploitation technique)
- **Shellcode signatures**: Known shellcode patterns (pwntools, metasploit signatures)

#### Process Injection Techniques
- **CreateRemoteThread**: API call to inject code into another process (detect via API hooking)
- **SetWindowsHookEx**: Inject DLL via hook (common rootkit technique)
- **Reflective DLL injection**: Custom bootstrap code without direct DLL import
- **Process hollowing**: Replace legitimate process with malware (check entry point)

### Live Memory Analysis Without Volatility

- **Strings**: `strings dump.bin | grep -i password | head`
- **Hexdump + search**: `xxd dump.bin | grep "ff ff ff"` (find shellcode preamble)
- **Binary search**: `objdump`, `radare2` for inline analysis

## Disk Forensics & File System Analysis

### File System Recovery

#### NTFS Specifics (Windows)
- **$MFT (Master File Table)**: Index of all files; recovery via $MFT parsing
- **$LogFile**: Transaction log; reveals deleted file operations
- **Alternate Data Streams (ADS)**: Filename:stream_name allows hidden data (e.g., `flag.txt:secret`)
  - Detection: `dir /R` or `Get-Item -Stream *`
  - Extraction: `cat flag.txt:secret` on Windows
- **$Recycle.Bin**: Deleted files; metadata reveals original path + deletion timestamp

#### FAT32/exFAT (USB Drives, Phones)
- **Directory entries**: 32-byte entries in root directory
- **Deleted entries**: First byte = 0xe5; rest of entry remains readable
- **FAT chain**: Links show which clusters belong to file; can reconstruct file from clusters even if header deleted
- **Recovery tools**: PhotoRec, TestDisk recover via FAT chain following

#### ext4 (Linux)
- **Journaling**: ext4 journal records metadata changes; deleted file references may remain
- **Inode**: Inode number identifies file; even deleted inode data may persist
- **Extents**: ext4 uses extents (block ranges); can enumerate via inode recovery
- **Unallocated space**: Deleted file content remains until overwritten

### Hidden Data Locations

#### File Slack & Unallocated Space
- **Slack space**: Difference between file size and allocated space; stores hidden data
- **Unallocated clusters**: Deleted file fragments, previous file remnants
- **Volume shadow copies**: Windows maintains prior file versions (System Restore)
  - Extract via VSS reader: `vssadmin list shadows`
  - Access shadow copy: `/Volumes/VSS_NAME/path/to/file`

#### Steganography in Files

##### Image Steganography
- **LSB (Least Significant Bit)**: Hide data in color channel low bits; invisible to eye
  - Detection: Entropy analysis (hiding data increases randomness)
  - Extraction: Use `steg_reveal.py`, `steghide`, `outguess`, or custom LSB extraction
- **JPEG metadata**: EXIF data, thumbnail, ICC color profile hide data
  - Extraction: `exiftool`, `jhead`, hex editor for direct JPEG segment inspection
- **PNG chunks**: Critical (required) vs. ancillary (optional) chunks; ancillary can hide data
  - Detection: pngcheck, hex editor to find non-standard chunks
  - Extraction: Parse PNG structure, extract unrecognized chunks

##### Audio Steganography
- **LSB hiding**: Low 1-2 bits of audio samples hide data (imperceptible)
- **Frequency analysis**: Hide data in inaudible frequencies (ultrasonic)
- **Spectral analysis**: Use Audacity to visualize spectrum; hidden data appears as patterns
- **Extraction**: sox, ffmpeg to isolate channels; analyze raw audio bytes

##### Document Steganography
- **PDF**: Trailing data after EOF (PDF reader ignores it)
  - Check file size vs. reported size in PDF trailer
  - Extract: `tail -c +OFFSET file.pdf > hidden_data`
- **Office documents**: ZIP structure; extract, inspect for hidden files in internal structure
- **ZIP files**: Data appended after central directory (ZIP reader ignores trailing data)

#### Embedded Payloads in Binaries
- **Appended data**: `file_with_payload` might be `image.jpg + payload` concatenated
  - Detection: File signature inconsistencies (JPEG marker + extra data)
  - Extraction: Find second magic bytes (e.g., PK for ZIP, FF D8 for JPEG)
- **Resource sections**: Binaries embed resources (icons, dialogs, strings) that hide data
  - Tools: Resource Hacker (Windows), `objdump -s` (Linux)
- **Overlays**: Some executable formats support data overlay (COM files, etc.)

### File Carving & Recovery

#### Magic Bytes & File Signatures
- **Known signatures**:
  - JPEG: FF D8 FF E*
  - PNG: 89 50 4E 47
  - GIF: 47 49 46 38
  - ZIP/DOCX: 50 4B 03 04
  - PDF: 25 50 44 46 (% P D F)
  - ELF: 7F 45 4C 46
- **Carving process**: Scan disk sector-by-sector for magic bytes, extract until next magic byte
- **Tools**: PhotoRec, Scalpel, Foremost automatically carve by signature

#### Entropy Analysis
- **High entropy**: Compressed, encrypted, or random data
- **Low entropy**: Plaintext, formatted data with repetition
- **Finding flags**: Flags often plaintext with low entropy; compress/encrypt regions have high entropy
- **Tools**: `binwalk` analyzes entropy per offset; shows compressed/encrypted regions

### Data Extraction Techniques

#### Disk Image Analysis
- **Mount image**: `mount -o ro,loop image.img /mnt/forensics`
- **List partitions**: `fdisk -l image.img` reveals partition table
- **Extract partition**: `dd if=image.img of=partition.img bs=512 skip=START_SECTOR count=SECTORS`
- **Filesystem tools**: `fls`, `icat` (SLEUTH Kit) recover files even from unallocated space

#### Database Recovery
- **SQLite**: Recover from unallocated space (SQLite has clear structure)
  - Deleted rows often remain in file
  - Recovery: `sqlite3` tool can sometimes repair corrupted DB
  - Manual recovery: Parse B-tree structure from sectors
- **MySQL/PostgreSQL**: Heavier format; harder recovery but same principle
  - Identify data pages by structure, carve around signatures

## Network Forensics (PCAP Analysis)

### Wireshark Advanced Filtering

```
tcp.stream eq 0         # Follow single TCP stream
ip.src == 192.168.1.1   # Source IP filter
tcp.port == 443         # Port filter
http.request.method == "POST"  # HTTP method
dns.qry.name contains "attacker"  # DNS queries to domain
```

### Protocol-Specific Extraction

#### HTTP/HTTPS
- **HTTP streams**: Right-click TCP stream → Follow → HTTP Stream to see plaintext requests/responses
- **HTTPS**: If key available (pcap has private key logged), Wireshark decrypts automatically
- **Credentials**: HTTP Basic Auth in Authorization header (Base64 encoded, easily decoded)
- **Files**: Extract transferred files via "Export Objects → HTTP"

#### DNS
- **DNS queries**: DNS name lookups; reveals accessed domains
- **Poisoning detection**: Compare multiple DNS responses for same query (different IPs = poisoning)
- **Exfiltration via DNS**: DNS queries often used for data exfiltration (base32/base64 in hostname)

#### FTP/TELNET
- **Plaintext protocols**: Username, password, commands all visible in PCAP
- **Credential extraction**: Filter FTP traffic, read USER/PASS commands directly

#### SSH
- **Encrypted traffic**: SSH protocol itself encrypted, but flow analysis possible
- **Public key exchange**: Initial handshake reveals version, algorithm info
- **Timing analysis**: Request timing may leak command length/output

### Packet-Level Analysis

#### Malicious Payload Detection
- **Shellcode patterns**: Look for NOP sleds (0x90 0x90 0x90 ...) followed by suspicious opcodes
- **Exploit signatures**: Known CVE exploit patterns (buffer overflow signatures, etc.)
- **Protocol violations**: Unexpected packet structure, malformed headers

#### Connection Analysis
- **Handshake completion**: Incomplete 3-way handshakes (SYN without SYN-ACK) indicate filtering
- **Retransmissions**: Excessive retransmissions suggest packet loss, congestion, or intentional blocking
- **Flow reconstruction**: Piece together partial connections from packet fragments

## Metadata Analysis

### File Metadata Extraction

#### EXIF (Images)
- **Camera info**: Camera model, GPS coordinates (location leak)
- **Timestamp**: Creation date/time often reveals when screenshot/photo taken
- **Software**: Editing software used; version can be exploited
- **Tool**: `exiftool file.jpg` displays all metadata

#### PDF Metadata
- **Producer**: PDF creation software (reveals tool used)
- **CreationDate**: When PDF created
- **Author**: May contain username or organization
- **Embedded files**: PDFs can contain hidden files inside
- **Extraction**: `pdfinfo`, `exiftool`, or PDF reader's metadata dialog

#### Document Properties (Office)
- **Author**: Username of document creator
- **Last modified**: By whom and when
- **Revision history**: Some versions track all edits
- **Comments & annotations**: Hidden comments in document properties
- **Extraction**: Open ZIP (Office = ZIP format), read `docProps/core.xml`

### Artifact Timeline Analysis

#### Windows Artifacts
- **Prefetch files** (`C:\Windows\Prefetch`): Records program execution, timestamps
- **Registry keys**: Software run, network configuration, user activity
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: Startup programs
  - `HKCU\Software\Microsoft\Internet Explorer\TypedURLs`: Browser history
- **Event logs**: `C:\Windows\System32\winevt\Logs\` contain all system/security events
  - ID 4688: Process creation (shows commandline)
  - ID 7045: Service installed
- **Shellbags**: Folder navigation history (`HKCU\Software\Microsoft\Windows\Shell\Bags`)
- **Recycle bin metadata**: `$I` files paired with actual files in `$Recycle.Bin`

#### Linux Artifacts
- **Bash history**: `~/.bash_history`, `~/.zsh_history` contain command history
- **Log files**: `/var/log/auth.log` (login attempts), `/var/log/apache2/` (web server), etc.
- **Temporary files**: `/tmp/`, `/var/tmp/` may contain evidence
- **System journals**: `journalctl` queries systemd journal (newer systems)
- **Access times**: inode times (atime, ctime, mtime) reveal file access patterns

#### Timeline Reconstruction
- **Create timeline**: Extract timestamps from all artifacts (files, logs, registry)
- **Identify suspicious clusters**: Activity not explained by normal OS behavior
- **Correlation**: Did access log entry match file modification time? Suspicious if not.

## Steganography Detection & Extraction

### Entropy-Based Detection
- **Expected entropy by file type**:
  - Plaintext: ~4.8 bits/byte
  - JPEG: ~7.5 bits/byte (compressed image)
  - Encrypted/high noise: ~8.0 bits/byte
- **Tool**: `binwalk -E image.jpg` shows entropy graph
- **Interpretation**: Flat entropy may indicate data compression; sudden spikes indicate distinct data

### Steganalysis Tools

#### Steghide (Hides data in JPEG/WAV)
- **Detection**: File size inconsistency (file reports smaller size than actual)
- **Extraction** (if password known): `steghide extract -sf image.jpg -p password`
- **Brute-force**: Try common passwords or empty password

#### OutGuess (LSB hiding in JPEG)
- **Detection**: Color palette anomalies, statistical analysis
- **Extraction**: `outguess -r image.jpg output.txt` (tries empty password)

#### OpenSteg, SilentEye
- **Detection**: Entropy analysis, metadata inspection
- **Extraction**: Tools often support batch analysis

### Manual Steganography Analysis

#### PNG Chunk Inspection
```
xxd image.png | head -20   # Look at PNG header & chunks
# PNG structure: 8-byte header, then 4-byte length + 4-byte type + data + 4-byte CRC
# Standard chunks: IHDR, PLTE, IDAT, IEND
# Unknown chunks: potential hidden data
```

#### JPEG Segment Inspection
```
xxd image.jpg | grep "ffd8|ffe0|ffe1"   # JPEG markers
# FFD8: SOI (start of image)
# FFE0: APP0 (JFIF)
# FFE1: APP1 (EXIF)
# Hidden data: APPn segments, or trailing data after FFD9 (end of image)
```

## Archive & Compressed File Analysis

### ZIP File Inspection

#### Structure Analysis
- **Central directory**: Lists all files (offset, CRC, compressed size)
- **Compare to actual data**: Discrepancies indicate tampering or hidden data
- **Trailing data**: After central directory end marker (PK\x05\x06)
  - Extract: `tail -c +OFFSET file.zip > hidden`

#### Password-Protected Archives
- **Brute-force**: `fcrackzip -D -p wordlist.txt archive.zip`
- **Known plaintext attack**: If plaintext of encrypted file known, recover key more efficiently
- **Encryption weakness**: ZIP's traditional encryption is very weak; can sometimes break via CRC

### TAR/GZIP Analysis
- **TAR structure**: Uncompressed archive (just concatenated files)
- **Extract manually**: `tar xf archive.tar -O filename`
- **GZIP wrapper**: Decompress first with `gunzip`, then extract TAR
- **Trailing data**: Not standard; indicates appended hidden data

## Real-World Exploitation Patterns

### Multi-Stage Recovery
1. **Acquire memory dump** if running (may have decrypted data, keys)
2. **Image disk** before analysis
3. **Run Volatility** on memory (faster than disk for some artifacts)
4. **Carve deleted files** from unallocated space
5. **Extract from steganography** if images/audio present
6. **Timeline analysis** to understand attack sequence

### Persistence Indicators
- **Unusual startup items**: Check Run registry keys, startup folders, cron jobs
- **Hidden processes**: Compare running processes to expected OS processes
- **Rootkit signatures**: Kernel hooks, SSDT modifications, hidden drivers
- **Network listeners**: Unexpected services on unusual ports (e.g., port 666, 777, etc.)

### Evidence Chain Validation
- **Cryptographic hashing**: MD5/SHA256 of all evidence before/after analysis
- **Write blockers**: Use hardware write blocker on acquisition to ensure no modification
- **Chain of custody**: Document who accessed evidence, when, for how long
- **Documentation**: Screenshots, logs, analysis notes for reproducibility

## CTF-Specific Winning Patterns

1. **Check obvious locations first**: Recycle bin, temp folders, hidden files (.hidden)
2. **Entropy analysis**: Find compressed/encrypted regions quickly via binwalk
3. **Strings extraction**: `strings dump.bin | grep -i flag` often finds hardcoded data
4. **Metadata**: Author names, timestamps reveal hints about flag location
5. **PCAP first**: If network capture available, extract credentials/transmitted data directly
6. **Steganography assumption**: If image/audio file present with no obvious content, assume steganography
7. **Registry hives**: If Windows disk, check registry for artifact history
8. **Multiple layers**: Zip inside zip inside PNG → decompress/extract iteratively
9. **Timestamps matter**: Compare file creation time with modification time (suspicious mismatches)
10. **Artifact clustering**: Artifacts in same directory often related; check entire directory, not just one file
