# File carving & recovery (extracting files from raw data/corruption)

**Category**: Forensics, Misc
**Prevalence**: Moderate — common when dealing with disk dumps or corrupted archives
**Signal**: A challenge gives you a raw binary blob, a disk dump, or a corrupted file that
contains multiple files or partially recoverable data. You need to extract them.

## The technique: File signatures (magic bytes)

Every common file format has a distinctive header (magic bytes):
- **JPEG**: `FF D8 FF`
- **PNG**: `89 50 4E 47`
- **ZIP/DOCX/XLSX**: `50 4B 03 04`
- **ELF binary**: `7F 45 4C 46`
- **PDF**: `25 50 44 46` (`%PDF`)
- **GIF**: `47 49 46` (`GIF`)

If you have a blob containing multiple files concatenated or scattered, you can:
1. Scan for these magic bytes
2. Extract from that offset to the next file's magic byte

## The technique: Carved extraction with binwalk

`binwalk` automatically scans for file signatures and extracts them:

```bash
binwalk -e blob.bin     # Extract all files found in blob.bin
# Output: _blob.bin.extracted/ containing recovered files
```

This works even if files are partially corrupted or overlapping.

## The technique: Hex offset extraction

If you know the start and end offsets of a file:

```bash
# Extract from offset 0x1000 to 0x2000
dd if=blob.bin of=extracted.file bs=1 skip=0x1000 count=$((0x2000 - 0x1000))
# Or using xxd/hexdump to find offsets visually
hexdump -C blob.bin | grep "magic_bytes_you_found"
```

## The technique: Entropy analysis

Compressed/encrypted files have high entropy (random-looking). Plaintext has low entropy. You
can visualize where different file types likely begin/end:

```bash
binwalk -E blob.bin   # Entropy analysis, shows compressed/encrypted regions
```

Regions of high entropy often indicate the start of a ZIP, GZIP, or encrypted segment.

## The technique: Partition recovery

If you have a disk dump and want to extract partitions:

```bash
# List detected partitions
parted disk.img unit s print
# Or use testdisk (interactive recovery tool)
testdisk disk.img
```

## Real gotcha

**Partial/corrupted files**: Carving often recovers incomplete files. The extracted file may
be missing its end (if the end-of-file marker is corrupted). You might need to:
1. Manually identify the correct end offset
2. Repair the file header/structure
3. Accept that only partial data is recoverable (e.g., first half of an image)

## Competition approach

1. **Identify the blob**: Use `file` to see if it's recognized; if not, it's a raw dump.
2. **Scan for files**:
   ```bash
   binwalk blob.bin           # Automatic extraction
   strings blob.bin | head    # Look for ASCII clues
   hexdump -C blob.bin | head # Look for magic bytes visually
   ```
3. **Extract manually** if needed:
   ```bash
   grep -a -b -o "^PNG" blob.bin  # Find PNG offsets
   dd if=blob.bin of=image.png bs=1 skip=<offset>
   ```
4. **Test recovered files**: Try opening them, check for errors, examine with `file`.

## Tools

- **binwalk**: Automated file signature scanning and extraction
- **dd**: Extract specific byte ranges
- **strings**: Extract printable ASCII (flags are often readable as text)
- **hexdump/xxd**: Visual hex inspection
- **file**: Identify file types
- **foremost**: Another file carving tool (often slower than binwalk, but comprehensive)
- **scalpel**: Configurable file carving (allows custom signatures)

## Source

Common in forensics challenges — tests your understanding of file formats and recovery
techniques.

## Related

- [[steganography-detection-extraction]] — embedded files often need carving to extract
- [[log-analysis-pattern-hunting]] — recovered logs often contain useful data
