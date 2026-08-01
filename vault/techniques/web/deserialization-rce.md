# Unsafe deserialization to RCE

**Category**: Web
**Prevalence**: High across Java, Python, PHP, .NET frameworks
**Signal**: An app accepts a serialized object from user input (cookies, POST body, uploaded
file) and deserializes it without validation. Look for: Java serialized streams (`\xac\xed`
magic bytes), PHP serialized objects (starting with `O:`), Python pickle, .NET binary format.

## The technique

If an app trusts deserialization:

```python
import pickle
data = request.form['object']
obj = pickle.loads(data)  # VULNERABLE — pickle can execute code
```

An attacker crafts a malicious serialized object that, when unpickled, executes arbitrary code.
Pickle specifically allows defining functions/classes during deserialization — a deliberate
feature that becomes a vulnerability here.

Similar patterns exist in:
- **Java**: XStream, JacksonXML, ROME, Commons Collections (ROP gadget chains)
- **PHP**: `unserialize()` with certain magic methods (`__wakeup()`, `__destruct()`)
- **.NET**: BinaryFormatter, DataContractSerializer

## Why it's dangerous

Serialization was designed to preserve object state, not for security. Most frameworks allow
embedded class definitions or magic method calls during deserialization — which can be abused
for RCE.

## Competition approach

1. **Identify serialized input**: Look for base64-encoded blobs, known magic bytes, or
   suspiciously opaque cookie values.
2. **Identify the framework/language**: Check error messages, stack traces, or known file
   extensions (`.java`, `.php`, etc.) to determine the serialization format.
3. **Use existing tools**:
   - **ysoserial** (Java): generates malicious serialized objects using known gadget chains
     (CommonsCollections, Spring1, etc.)
   - **phpgcc** (PHP): generates PHP serialized objects with magic method exploits
   - **python -c "import pickle; pickle.dumps(...)"** (Python): craft pickle objects with
     `__reduce__` method for code execution
4. **Replace the serialized input**: Inject the malicious object into the cookie/POST body and
   trigger deserialization.

## Real gotcha

**Java gadget chains are version-specific.** If the target has `commons-collections 3.1` but
ysoserial generates for 4.0, the chain might not work. Iterate through multiple gadget types
(`CommonsCollections1` through `CommonsCollections7`) and multiple tool-generated payloads.

For **Python pickle**, you can sometimes control *part* of the pickle data directly without
needing ysoserial — test if the server lets you inject `__reduce__` or `__setstate__` methods.

## Source

Common across 0xdf's HTB writeups — Java and PHP deserialization vulnerabilities appear
frequently in real-world scenarios. Deserialization is one of the highest-impact RCE vectors
when present.

## Related

- [[command-injection-shell-escape]] — command injection is another RCE vector, different exploit
  chain but same goal
- [[server-side-template-injection-ssti]] — SSTI is another high-impact RCE vector
