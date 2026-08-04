# Forensics & Misc

## Overview

[[Digital forensics]] is the practice of examining files, devices, network traffic, memory, and logs to understand what happened and recover evidence. In [[CTF]] challenges, forensics usually means inspecting artifacts such as images, archives, [[PCAP]] files, disk images, or [[memory dumps]] to find a hidden [[flag]].

[[Miscellaneous]] challenges are puzzles that do not fit neatly into categories like [[web security]], [[cryptography]], or [[reverse engineering]]. They may involve file formats, encodings, obscure tools, logic puzzles, data recovery, scripting, or careful observation. For beginners, [[forensics]] and [[misc]] are often about asking: "What kind of file is this, what information does it contain, and what looks unusual?"

This note is for educational CTF practice only.

## Key Concepts

- [[Metadata]]: Extra information stored about a file, such as creation time, author, camera model, software used, coordinates, comments, or document history. In CTFs, [[metadata]] may contain clues, suspicious timestamps, usernames, or even the [[flag]] itself.
- [[EXIF]]: A common type of [[metadata]] found in image files, especially photos. [[EXIF]] can include camera settings, GPS location, device details, thumbnails, and editing history.
- [[File Signatures]]: Identifying patterns that help determine a file's real type. A file extension like `.jpg` or `.zip` can be misleading, so [[file signatures]] help confirm what the file actually is.
- [[Magic Bytes]]: The first bytes of many file formats that identify the format, such as `FF D8 FF` for many [[JPEG]] files or `50 4B` for many [[ZIP files]]. [[Magic bytes]] are useful when a file has the wrong extension.
- [[Hidden Files]]: Files that are not immediately visible, sometimes because of naming conventions, archive settings, filesystem attributes, or being embedded inside another file. In CTFs, [[hidden files]] may hold clues or the [[flag]].
- [[ZIP Files]]: Archive files that can contain many files and folders. [[ZIP files]] in CTFs may include hidden entries, misleading names, comments, nested archives, or password-protected content.
- [[PCAP]]: A packet capture file containing recorded [[network traffic]]. A [[PCAP]] may show protocols, transferred files, chat messages, DNS queries, HTTP requests, or other communication artifacts.
- [[Wireshark]]: A graphical tool for inspecting [[PCAP]] files and network packets. [[Wireshark]] helps beginners filter traffic, follow streams, identify protocols, and extract visible clues from captures.
- [[Memory Dumps]]: Snapshots of system memory. [[Memory dumps]] may contain process data, command history, loaded files, credentials used in a challenge environment, or fragments of text.
- [[Logs]]: Records of events from systems, applications, servers, or tools. [[Logs]] may reveal timelines, errors, usernames, file paths, IP addresses, or unusual activity.
- [[Steganography]]: The practice of hiding information inside another medium, such as an image, audio file, or document. In CTFs, [[steganography]] often involves hidden text, altered pixels, appended data, or embedded files.
- [[Strings]]: Human-readable text found inside binary files. Searching for [[Strings Tool]] can reveal paths, comments, URLs, error messages, embedded clues, or flags.
- [[File Carving]]: Recovering embedded or deleted files by searching for known [[file signatures]] and boundaries. [[File carving]] is useful when files are hidden inside larger blobs, disk images, or damaged archives.

## Common Public Tools

| Tool | Purpose | Typical CTF Use |
|---|---|---|
| [[ExifTool]] | Reads and edits [[metadata]], especially [[EXIF]] data in images and documents. | Check images, PDFs, and documents for comments, author names, GPS data, timestamps, or suspicious metadata fields. |
| [[Wireshark]] | Inspects [[PCAP]] files and live network packets. | Review packet captures, follow TCP streams, inspect HTTP traffic, find transferred files, and search for visible flag text. |
| [[binwalk]] | Analyzes files for embedded data, compressed sections, and known [[file signatures]]. | Look for hidden archives, firmware sections, embedded images, or appended files inside a larger file. |
| [[Strings Tool]] | Extracts readable text from binary files. | Quickly search unknown files for flags, clues, URLs, file paths, comments, or readable fragments. |
| [[File Command]] | Identifies a file type using [[magic bytes]] and other signatures. | Confirm whether a file extension is truthful and identify unknown challenge files. |
| [[xxd]] | Displays files as hexadecimal and text. | Inspect [[magic bytes]], spot file headers, compare binary data, and view hidden text near the start or end of a file. |
| [[CyberChef]] | Browser-based data transformation tool for encoding, decoding, compression, hashing, and analysis. | Decode suspicious text, convert between formats, inspect byte data, and chain simple transformations. |
| [[foremost]] | Performs [[file carving]] based on headers, footers, and file structures. | Recover embedded or deleted files from disk images, raw data blobs, or challenge files. |

## Where Flags Usually Hide

In beginner [[forensics]] and [[misc]] challenges, flags often hide in places that reward careful inspection rather than advanced exploitation.

- [[Metadata]]: Image comments, document properties, author fields, GPS fields, timestamps, or tool-specific metadata.
- [[Images]]: Visible text, hidden layers, color channels, appended data, unusual pixels, thumbnails, or embedded files.
- [[Audio]]: Spectrogram text, reversed audio, metadata fields, unusual silence, or hidden data patterns.
- [[Archives]]: File names, comments, nested folders, hidden entries, compressed files, or password-protected challenge material.
- [[Packet captures]]: HTTP requests, DNS queries, chat messages, file transfers, stream contents, or readable protocol data.
- [[Memory dumps]]: Process names, command history, strings, file paths, clipboard-like fragments, or remnants of opened files.
- [[Hidden text]]: Plain text inside binaries, whitespace, comments, encoded strings, or text placed at the end of a file.
- [[File names]]: Suspicious names, extensions that do not match the real type, ordered file sequences, or clues hidden in folder paths.

## Beginner Study Links

- [picoCTF](https://picoctf.org/) - Beginner-friendly CTF platform with many [[forensics]] and [[misc]] problems.
- [OverTheWire](https://overthewire.org/wargames/) - Wargames that build Linux, command-line, and problem-solving fundamentals.
- [TryHackMe](https://tryhackme.com/) - Guided cybersecurity labs, including introductory rooms on [[digital forensics]] and tooling.
- [CTF Field Guide](https://trailofbits.github.io/ctf/) - Reference-style guide for CTF categories, techniques, and study paths.

## Related Notes

- [[CTF Basics]]
- [[Linux Commands]]
- [[Hexadecimal]]
- [[Encoding]]
- [[Cryptography]]
- [[Reverse Engineering]]
- [[Web Security]]
- [[Network Forensics]]
- [[Steganography]]
- [[File Formats]]

