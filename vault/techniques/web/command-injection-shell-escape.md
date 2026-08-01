# Command injection via shell escape (post-processing exploits)

**Category**: Web
**Prevalence**: Moderate — common when apps invoke system tools for image processing, archive
handling, or log parsing
**Signal**: User input reaches a command-line invocation without proper escaping. Look for code
that constructs shell commands with string concatenation: `os.system()`, `shell_exec()`,
`subprocess.call()`, backticks, pipes.

## The technique

If an app processes user-uploaded images:

```python
import subprocess
filename = request.files['image'].filename  # User-supplied
subprocess.call(f"convert {filename} -resize 100x100 output.jpg", shell=True)  # VULNERABLE
```

An attacker uploads a file named: `image.jpg; rm -rf /tmp; #`

The command executed becomes:
```bash
convert image.jpg; rm -rf /tmp; # -resize 100x100 output.jpg
```

The shell interprets `;` as a command separator, so it runs three commands:
1. `convert image.jpg`
2. `rm -rf /tmp` (the injected payload)
3. (the `#` comments out the rest)

## Common injection contexts

- **ImageMagick** (`convert`, `identify`, `mogrify`): take filename/path as args
- **Archive tools** (`tar`, `unzip`, `7z`): take archive path and extract destination
- **Video processing** (`ffmpeg`, `ffprobe`): filename and options
- **PDF processing** (`pdftotext`, `ghostscript`): file paths
- **Log parsing** (`grep`, `awk`, `sed`): user-supplied search terms

## Defense bypass techniques

Apps sometimes try to "sanitize" by blacklisting certain characters (`; | & $`), but escaping
is imperfect:

- **Bash command substitution**: `$(command)` or `` `command` `` (often not blacklisted). Try
  both if one is blocked.
- **Newlines**: `\n`, `%0A` in filenames can inject new commands on a new line:
  `image.jpg%0Aid%0A.jpg`
- **Glob expansion**: `*`, `?`, `[a-z]` match files and pass arguments unquoted:
  `image[a-z].jpg` matches `image.jpg`, `image` wildcard might match more than expected.
- **Variable expansion**: `${IFS}` expands to space, `${PATH:0:1}` expands to `/`:
  `image${IFS}||${IFS}id.jpg` becomes `image || id.jpg`
- **Pipes and redirection**: `>`, `>>`, `<`, `2>&1` redirect output: `image.jpg > /tmp/output.txt`
- **Hex/octal escaping**: `\x3b` (semicolon), `\073` (semicolon) — try when ASCII is blocked

## Competition approach

1. **Identify points where user input reaches a shell**: Filename uploads, search queries, log
   paths, report generation.
2. **Test simple payloads first**: `image; id #`, `image | whoami`, `image$(whoami).jpg`
3. **If characters are blacklisted, iterate**: Try command substitution variants (`$(...)` vs
   backticks), newlines, glob patterns, environment variable expansion.
4. **Escalate**:  If you get RCE, read `/etc/passwd`, check `/proc/self/environ` for keys,
   list cron jobs, find writable directories, read source code.

## Real gotcha

**Properly escaping command injection requires `shlex.quote()` (Python),
`posix_escape_string()` (PHP), or passing args as separate array elements** — not just
blacklisting bad characters. If the app tries to "fix" injection by filtering, there's almost
always a bypass.

## Source

Recurring pattern in 0xdf's HTB writeups — image processing, archive extraction, and log
handling are common vectors for shell escape in real applications.

## Related

- [[deserialization-rce]] — another RCE vector
- [[server-side-template-injection-ssti]] — yet another path to code execution
