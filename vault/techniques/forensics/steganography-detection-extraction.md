# Steganography detection & extraction (images, audio, archives)

**Category**: Forensics, Misc
**Prevalence**: Moderate — common in CTF Misc category
**Signal**: A challenge gives you a file (image, audio, video, archive) that appears normal but
may contain hidden data embedded inside. The flag is hidden within the file.

## The technique: Image steganography (LSB - least significant bits)

In digital images, each pixel is represented by RGB values (0–255 each). The **least significant
bit (LSB)** of each value is often unused visually — changing it doesn't noticeably affect the
image to human eyes.

**Steganography via LSB**: Replace the LSB of many pixels with bits from a hidden message.

To extract:
```python
from PIL import Image
img = Image.open('image.png')
pixels = img.load()
hidden_bits = []
for x in range(img.width):
    for y in range(img.height):
        r, g, b = pixels[x, y][:3]  # Extract RGB, ignore alpha
        hidden_bits.append(r & 1)  # LSB of red channel
        hidden_bits.append(g & 1)  # LSB of green channel
        hidden_bits.append(b & 1)  # LSB of blue channel
# Convert bits to bytes and decode
hidden_message = bytes([int(''.join(map(str, hidden_bits[i:i+8])), 2) for i in range(0, len(hidden_bits), 8)])
```

## The technique: Audio steganography (frequency domain)

Hidden data can be encoded in:
1. **Frequency spectrum** (FFT/spectrogram) — embed data at frequencies humans can't hear
2. **Phase shifts** — subtle timing differences in audio samples
3. **Parity encoding** — use LSBs of audio samples like image LSBs

**Tools**: `Audacity` (visual inspection of spectrograms), `SoX` (command-line audio processing)

## The technique: Archive/file padding

Hidden data is sometimes appended after the end of a file format (after the "end of file"
marker).

Example:
```
[PNG image data][PNG end-of-file marker][hidden ZIP file][hidden text]
```

To extract:
```bash
# Check file size and check for extra data
hexdump -C archive.png | tail
# Extract everything after the PNG marker
tail -c +<offset> archive.png > hidden_data.zip
```

## The technique: Metadata (EXIF, ID3, etc.)

Images and audio files contain metadata:
- **EXIF** (images): camera settings, GPS location, thumbnail data (can hide content)
- **ID3** (audio): tags like artist, album, cover art (can hide content)
- **ZIP comments**: ZIP archives can have comments appended to the central directory

**Tools**: `exiftool`, `strings`, `zipinfo -1` (list ZIP comments)

## The technique: File format confusion

A file might have multiple interpretations:
- A PNG that's also a valid ZIP (polyglot file)
- A JPEG with a hidden ZIP appended
- A GIF with multiple frames (only first visible, others hidden)

## Competition approach

1. **Examine the file**: Use `file`, `hexdump`, `strings` to understand its structure.
2. **Try common extraction tools first**:
   ```bash
   strings filename              # Extract printable ASCII
   binwalk filename              # Scan for embedded files
   exiftool filename             # Read metadata
   steghide extract -sf filename # LSB extraction (if steghide was used to hide)
   ```
3. **Extract LSBs** (if image): Use the Python code above or `stegsolve` (Java tool).
4. **Check for appended data**: Use `tail -c` or `hexdump` to inspect the end of the file.
5. **Analyze audio/video spectrograms**: Open in Audacity, look for visible patterns in
   frequency domain.

## Real gotcha

**Not every hidden message is text.** It might be another image, a ZIP archive, or binary
data. After extracting, try to identify the format of the hidden data (`file` command).

## Tools

- **binwalk**: Scans for embedded files and extracts them automatically
- **steghide**: Hides/extracts LSB data in images and audio (also has a GUI)
- **stegsolve**: Java tool for visual LSB extraction and analysis
- **exiftool**: Reads/writes EXIF, ID3, and other metadata
- **Audacity**: Visual audio analysis (spectrograms, frequency visualization)
- **SoX**: Command-line audio manipulation

## Source

Common in CTF Misc/Forensics categories — steganography challenges teach about file formats
and hidden data extraction.

## Related

- [[file-carving-recovery]] — extract files from raw data or corrupted blobs (often contains
  steganographic files)
- [[log-analysis-pattern-hunting]] — extracted hidden messages might be encoded logs or
  credentials
