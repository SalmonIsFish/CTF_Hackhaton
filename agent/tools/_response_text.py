"""Shared helper for decoding an HTTP response body, used by every tool that reads response.text
(fetch_url, upload_file, keyed_decode) instead of each reimplementing the same fix.

Not a @tool itself -- the leading underscore in the module name marks it as internal, same
convention agent/tools/_header_repair.py uses.
"""


def decode_response_body(response) -> str:
    """requests' own response.text can't be trusted here: per RFC 2616, requests falls back to
    ISO-8859-1 when the server's Content-Type omits a charset -- confirmed live against a real
    picoCTF target (`Content-Type: text/html`, no charset) whose HTML legitimately contains
    non-ASCII bytes (a challenge's encrypted flag string): every UTF-8 multi-byte character came
    back as two mojibake characters instead of one correct one, silently corrupting the exact
    ciphertext a decode tool needs byte-for-byte. response.apparent_encoding (requests' own
    chardet/charset_normalizer guess) isn't a safe fallback either -- it guessed CP949 on that
    same real response. UTF-8 is the correct default for virtually all modern web content when
    undeclared (the HTML5 spec's own default, unlike the older HTTP RFC's Latin-1 default), so
    decode the raw bytes as UTF-8 first and only fall back to Latin-1 (which can decode any byte
    sequence without raising, guaranteeing this never throws) if the body isn't valid UTF-8."""
    try:
        return response.content.decode("utf-8")
    except UnicodeDecodeError:
        return response.content.decode("latin-1")
