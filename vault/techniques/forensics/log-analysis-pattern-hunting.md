# Log analysis & pattern hunting (extracting secrets from logs)

**Category**: Forensics, Misc
**Prevalence**: Moderate — logs often contain credentials, command history, or other secrets
**Signal**: A challenge gives you log files (access logs, command history, application logs,
network traffic) and you need to find patterns, extract credentials, or reconstruct events.

## The technique: Grepping for keywords

Log files often leak secrets in predictable patterns:

```bash
# Search for common keywords
grep -i "password\|secret\|key\|token\|flag" logfile.txt
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" logfile.txt  # IP addresses
grep -E "(\w+@\w+\.\w+)" logfile.txt  # Email addresses
grep -E "Bearer [A-Za-z0-9_\-.]+" logfile.txt  # Auth tokens
grep -E "(sql|select|insert|update|delete)" logfile.txt -i  # SQL queries
```

**In bash history** (`~/.bash_history`, `~/.zsh_history`):
```bash
grep -i "password\|token\|curl.*auth" ~/.bash_history
# Commands often leak credentials as command-line arguments
```

## The technique: Reconsting HTTP requests/responses

Access logs (Apache, Nginx) show request URLs, which might contain:
- Query parameters with credentials: `GET /api/login?user=admin&pass=secret123`
- Hidden endpoints: `GET /admin/backup.zip`
- Interesting data: `GET /user/download?id=1001`

```bash
# Extract all unique URLs from access log
awk '{print $7}' access.log | sort | uniq
# Look for unusual or suspicious patterns
grep "admin\|backup\|config\|download" access.log
```

## The technique: Timing analysis

If logs have timestamps, you can reconstruct **when** something happened and cross-reference
events:

```bash
# Find all events for a specific user at a specific time
grep "2024-08-01 14:3[0-9]" logfile.txt | grep "username"
# Look for brute-force patterns (many failed logins in short time)
grep "login failed" logfile.txt | awk -F'[[]' '{print $2}' | uniq -c | sort -rn
```

## The technique: Parsing structured logs (JSON, CSV)

Modern logs are often structured:

```bash
# Pretty-print JSON logs
cat logfile.json | python3 -m json.tool | grep -i "password\|secret"
# Extract fields from CSV
awk -F',' '$3 ~ /admin/ {print $0}' logfile.csv
```

## The technique: Traffic analysis (PCAP files)

Network captures (`tcpdump`, Wireshark `.pcap` files) can reveal:
- Unencrypted HTTP requests (with credentials, secrets, endpoints)
- DNS queries (reveals visited domains)
- Timing analysis of requests (might correlate with events)

```bash
# Extract HTTP requests from PCAP
tcpdump -r capture.pcap -A tcp port 80 | grep -E "^GET|^POST"
# Or use Wireshark (GUI) to inspect individual packets
wireshark capture.pcap
```

## Real gotcha

**Logs can be massive.** Don't try to read them manually — automate with `grep`, `awk`, `sed`.
And watch out for **log rotation** — if you see gaps in timestamps, there might be rotated logs
elsewhere (e.g., `access.log.1`, `access.log.2.gz`).

## Competition approach

1. **Identify the log type**: Check file extension and headers.
2. **Search for keywords**: Grep for common secret patterns (password, token, flag, secret).
3. **Look for anomalies**: Brute-force attempts, unusual IP addresses, repeated errors.
4. **Reconstruct events**: Use timestamps to correlate multiple log sources.
5. **Extract credentials**: If found, test them on other services (credential reuse).

## Tools

- **grep/awk/sed**: Standard Unix tools for log parsing
- **Wireshark**: GUI for inspecting network captures
- **tcpdump**: Command-line network capture analysis
- **jq**: JSON query language (great for structured logs)
- **logwatch**: Automated log analysis and reporting

## Source

Common in forensics challenges — teaches about information hiding in plain sight.

## Related

- [[credential-reuse-enumeration-pattern]] — credentials found in logs can often be reused
- [[file-carving-recovery]] — logs might be embedded in files that need extraction
