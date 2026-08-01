# Zip Slip via symlink bypass (archive extraction directory traversal)

**Category**: Web, Forensics (archive handling)
**Signal**: An app extracts user-uploaded archives (`.tar`, `.zip`, `.tar.gz`) into a
predictable, web-accessible directory. Direct `../` path-traversal entries in the archive are
blocked (revalidated per-entry), but symlink entries are not revalidated the same way.

## The technique

If archive extraction logic looks like:

```go
archiver.Unarchive(uploadedFile, outputDir)  // Unarchive does revalidate ../
```

...the library typically does check regular file paths for traversal (`../../../etc/passwd`
attempts). **But symlink entries (`type: SYMTYPE, linkname: /etc/passwd`) are often not
revalidated the same way** — they're extracted as-is, creating a symlink pointing *outside*
the sandbox directory. Files written "through" that symlink during a later extraction step
(or by the app reading the symlink without realizing where it points) land outside the sandbox.

This is a Zip Slip variant: the traversal happens via symlink indirection rather than directly
in a file path.

## Example attack

1. Create a tar archive with:
   - A symlink entry: `sess_link → /tmp/sessions` (absolute path outside the sandbox)
   - Regular files intended to be "written through" the symlink:
     `sess_link/admin/forged_session_id.json` (in the tar, this unpacks to
     `/tmp/sessions/admin/forged_session_id.json`, not `./files/user/sess_link/...`)

2. The app extracts the archive via `archiver.Unarchive(tar, "./files/<user>/")`.

3. The symlink is created at `./files/<user>/sess_link → /tmp/sessions`.

4. The file `/tmp/sessions/admin/forged_session_id.json` is created (outside the sandbox).

5. Later, the app or another service reads `./files/<user>/sess_link/admin/sessionid` expecting
   a sandbox-local file, but resolves to `/tmp/sessions/admin/sessionid` instead — the
   traversal succeeded.

**Real gotcha**: this only works if the app or another service *actually follows the symlink*
when reading files. If the app extracts the archive but never reads from it (or uses a
symlink-aware function like `readlink` that returns the path without dereferencing), the
symlink exists but is useless. Test whether reads are symlink-aware before committing to this
attack.

## Source challenge

HackTheBox "Desires". `UploadEnigma` extracted archives via `archiver.Unarchive(file, path)`
into `./files/<user>/`. Direct `../` traversal was blocked — confirmed by trying 6 different
traversal depths, with an oracle check (attempted to overwrite the served `static/styles.css`).
Symlink entries were not revalidated. Combined with [[cookie-trust-auth-bypass]] and
[[predictable-session-id-timestamp-hash]] to plant a forged admin session file at
`/tmp/sessions/noexist/<sessionid>` where both the Go Fiber session middleware and the Node
SSO backend would read it. Flag captured: `HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}`.

**Full run write-up**: see `evals/practice_runs.md`, "Real HackTheBox target — 'Desires'".

## Related

- [[cookie-trust-auth-bypass]]
- [[predictable-session-id-timestamp-hash]]
