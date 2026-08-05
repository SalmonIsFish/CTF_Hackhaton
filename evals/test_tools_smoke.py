import http.server
import socketserver
import threading

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, ToolMessage

from agent.graph import (
    MAX_CONTEXT_MESSAGES,
    _last_tool_calls_repeated,
    build_system_prompt,
    extract_allowed_hosts,
    extract_tool_trace,
    message_text,
    observe,
    trim_context,
)
from agent.tools import fetch_url as fetch_url_module
from agent.tools import tcp_session
from agent.tools.dir_enum import dir_enum
from agent.tools.fetch_fragments import fetch_and_join_fragments
from agent.tools.extract_metadata import extract_metadata
from agent.tools.fetch_url import fetch_url
from agent.tools.find_flag_pattern import (
    DEFAULT_PREFIXES,
    _looks_like_placeholder,
    build_flag_pattern,
    find_flag_pattern,
)
from agent.tools.math_tools import dh_shared_secret_decrypt, modpow
from agent.tools.identify_and_decode import identify_and_decode
from agent.tools.keyed_decode import fetch_and_decode_cipher, keyed_byte_decode
from agent.tools.port_scan import port_scan
from agent.tools.radare2_analyze import radare2_analyze
from agent.tools.read_local_file import read_local_file
from agent.tools.rsa_tools import extract_hidden_key, rsa_decrypt_file
from agent.tools.crack_hash import crack_hash
from agent.tools._local_file_check import check_local_file
from agent.tools.search_skills import search_skills
from agent.tools.search_vault import search_vault
from agent.tools.tcp_session import tcp_close, tcp_open, tcp_send
from agent.tools.web_search import web_search

print("=== find_flag_pattern: string containing a flag ===")
print(find_flag_pattern.invoke({"text": "the answer is flag{abc123}, don't lose it"}))

print("\n=== find_flag_pattern: string with no flag ===")
print(find_flag_pattern.invoke({"text": "just some ordinary sentence, nothing to see here"}))

print("\n=== find_flag_pattern: picoCTF{...} format (real flag from a live picoCTF run) ===")
picoctf_result = find_flag_pattern.invoke(
    {"text": "session admin key leaked: picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}"}
)
print(picoctf_result)
assert "picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}" in picoctf_result, (
    f"expected the picoCTF-format flag to be recognized -- 'ctf' has no word boundary right "
    f"after 'pico', which is exactly the bug this regression-tests, got {picoctf_result}"
)

print(
    "\n=== find_flag_pattern: unfilled template placeholders (picoCTF{...}, picoCTF{???}) are "
    "rejected, not reported as real flags -- regression test for a real, confirmed failure: a "
    "picoCTF 'Shared Secrets' challenge's OWN generator script (encryption.py) literally "
    "contained `flag = b\"picoCTF{...}\"` as an unfilled template. [^{}]{1,300} placed no "
    "requirement on the content being real, only on it not containing another brace, so it "
    "matched straight out of the raw source -- and since agent/graph.py's observe() treats any "
    "match as a solved flag, this ended the run immediately with a fabricated 'flag' before the "
    "agent ever found or read the challenge's actual captured data file ==="
)
for placeholder_text in (
    'flag = b"picoCTF{...}"',
    "the flag is picoCTF{???}",
    "picoCTF{REDACTED}",
    "picoCTF{}",  # empty content -- also not a real flag
):
    placeholder_result = find_flag_pattern.invoke({"text": placeholder_text})
    print(f"{placeholder_text!r} -> {placeholder_result!r}")
    assert placeholder_result == "No flag pattern found.", (
        f"expected the placeholder in {placeholder_text!r} to be rejected, got {placeholder_result!r}"
    )

print(
    "\n=== find_flag_pattern: a real flag alongside a placeholder in the same text still gets "
    "found -- the placeholder check filters individual matches, not the whole text ==="
)
mixed_result = find_flag_pattern.invoke({
    "text": 'template: flag = b"picoCTF{...}" but the real one is picoCTF{dh_s3cr3t_9982ffe6}',
})
print(mixed_result)
assert mixed_result == "picoCTF{dh_s3cr3t_9982ffe6}", (
    f"expected only the real flag to survive, with the placeholder filtered out, got {mixed_result}"
)

print("\n=== _looks_like_placeholder: sanity checks on the helper directly ===")
assert _looks_like_placeholder("picoCTF{...}")
assert _looks_like_placeholder("picoCTF{???}")
assert _looks_like_placeholder("picoCTF{  }")
assert not _looks_like_placeholder("picoCTF{dh_s3cr3t_9982ffe6}"), (
    "a real flag with actual alphanumeric content must never be treated as a placeholder"
)

print(
    "\n=== build_flag_pattern: a custom competition prefix (FLAG_PREFIXES) is matched, while the "
    "default pattern does NOT match it -- so the day's real flag format can be added without a "
    "code change, and defaults stay unchanged when unset ==="
)
_custom_text = "the winning submission is HACKHATON{c0mp3t1t10n_d4y_f0rm4t} nice"
_custom_pattern = build_flag_pattern("hackhaton")
assert _custom_pattern.search(_custom_text), (
    "expected build_flag_pattern('hackhaton') to match HACKHATON{...}"
)
_default_pattern = build_flag_pattern()
assert not _default_pattern.search(_custom_text), (
    "expected the default pattern (no extra prefixes) to NOT match a custom HACKHATON{...} format "
    "-- proving the extra prefix is what enables detection, and that unset FLAG_PREFIXES is a no-op"
)

print("\n=== build_flag_pattern: all default prefixes still match, custom prefix is additive ===")
for _prefix in DEFAULT_PREFIXES:
    _sample = f"see {_prefix}{{still_matches_after_change}}"
    assert _default_pattern.search(_sample), (
        f"expected the default prefix {_prefix!r} to still match after making prefixes configurable"
    )
# The 4 defaults AND the extra one all match under a configured pattern (additive, not replacing).
_both_pattern = build_flag_pattern("hackhaton")
assert _both_pattern.search("picoCTF{a}") and _both_pattern.search("HACKHATON{b}"), (
    "expected a configured pattern to match both the built-in defaults and the extra prefix"
)

print(
    "\n=== build_flag_pattern: a garbage FLAG_PREFIXES value can't break the regex or the "
    "binary/deflate false-match guard ==="
)
# Regex metacharacters in a fat-fingered env value must be sanitized, not spliced in raw.
_junk_pattern = build_flag_pattern("bad(){|]prefix, , 123")
assert _junk_pattern.search("badprefix{ok}") or _junk_pattern.search("123{ok}"), (
    "expected junk prefixes to be sanitized to word chars and still compile into a working pattern"
)
# The [^{}] + length cap that stopped a deflate stream's stray '{...}' from being read as a flag
# must survive: an over-long brace run is not a match.
assert not _default_pattern.search("flag{" + "A" * 400 + "}"), (
    "expected the length cap to still reject a runaway brace span (binary false-match guard)"
)

print("\n=== identify_and_decode: known base64 (aGVsbG8gd29ybGQ= -> hello world) ===")
print(identify_and_decode.invoke({"text": "aGVsbG8gd29ybGQ="}))

print("\n=== identify_and_decode: known hex (68656c6c6f -> hello) ===")
print(identify_and_decode.invoke({"text": "68656c6c6f"}))

print(
    "\n=== keyed_byte_decode: subtract-mode round trip (regression test for the picoCTF "
    "'Bookmarklet' hallucination -- the model tried this arithmetic by hand, corrupted several "
    "characters, and fabricated a flag instead of using a real tool) ==="
)
_keyed_plain = "picoCTF{keyed_decode_smoke_test}"
_keyed_key = "testkey"
_keyed_cipher = "".join(
    chr((ord(c) + ord(_keyed_key[i % len(_keyed_key)])) % 256) for i, c in enumerate(_keyed_plain)
)
keyed_result = keyed_byte_decode.invoke({"text": _keyed_cipher, "key": _keyed_key, "mode": "subtract"})
print(keyed_result)
assert keyed_result == _keyed_plain, f"expected the exact plaintext back, got {keyed_result!r}"

print("\n=== keyed_byte_decode: unsupported mode is a clean error, not an exception ===")
bad_mode_result = keyed_byte_decode.invoke({"text": "abc", "key": "k", "mode": "rot13"})
print(bad_mode_result)
assert "Unsupported mode" in bad_mode_result, f"expected a clean error, got {bad_mode_result}"

print("\n=== extract_metadata: PNG with a tEXt chunk, expect the chunk reported ===")
import tempfile as _tempfile  # local import, avoids polluting the module-level namespace above

from PIL import Image as _Image
from PIL.PngImagePlugin import PngInfo as _PngInfo

with _tempfile.TemporaryDirectory() as _tmpdir:
    png_path = f"{_tmpdir}/flag.png"
    png_info = _PngInfo()
    png_info.add_text("flag", "flag{extract_metadata_smoke_test}")
    _Image.new("RGB", (4, 4)).save(png_path, pnginfo=png_info)

    png_result = extract_metadata.invoke({"file_path": png_path})
    print(png_result)
    assert "flag{extract_metadata_smoke_test}" in png_result, (
        f"expected the PNG tEXt chunk's content in the report, got {png_result}"
    )
    assert "format: PNG" in png_result, f"expected the image format reported, got {png_result}"

    print("\n=== extract_metadata: missing file, expect a clean error string, not an exception ===")
    missing_result = extract_metadata.invoke({"file_path": f"{_tmpdir}/does_not_exist.png"})
    print(missing_result)
    assert "no such file" in missing_result.lower(), f"expected a clean missing-file message, got {missing_result}"

    print("\n=== extract_metadata: not an image, expect a clean error string, not an exception ===")
    not_image_path = f"{_tmpdir}/not_an_image.txt"
    with open(not_image_path, "w") as f:
        f.write("just plain text, not image bytes")
    not_image_result = extract_metadata.invoke({"file_path": not_image_path})
    print(not_image_result)
    assert "could not open" in not_image_result.lower(), (
        f"expected a clean not-an-image message, got {not_image_result}"
    )

    print("\n=== extract_metadata: PDF /Info dict, expect the metadata reported ===")
    from pypdf import PdfWriter as _PdfWriter

    pdf_path = f"{_tmpdir}/flag.pdf"
    pdf_writer = _PdfWriter()
    pdf_writer.add_blank_page(width=72, height=72)
    pdf_writer.add_metadata({"/Author": "picoCTF{pdf_metadata_smoke_test}"})
    with open(pdf_path, "wb") as f:
        pdf_writer.write(f)

    pdf_result = extract_metadata.invoke({"file_path": pdf_path})
    print(pdf_result)
    assert "picoCTF{pdf_metadata_smoke_test}" in pdf_result, (
        f"expected the PDF /Author field's content in the report, got {pdf_result}"
    )
    assert "format: PDF" in pdf_result, f"expected the PDF format reported, got {pdf_result}"

    print("\n=== extract_metadata: corrupt PDF (magic bytes but invalid structure), expect a clean error ===")
    corrupt_pdf_path = f"{_tmpdir}/corrupt.pdf"
    with open(corrupt_pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\nnot actually a valid pdf body")
    corrupt_pdf_result = extract_metadata.invoke({"file_path": corrupt_pdf_path})
    print(corrupt_pdf_result)
    assert "could not open" in corrupt_pdf_result.lower(), (
        f"expected a clean corrupt-PDF message, not an exception, got {corrupt_pdf_result}"
    )

print(
    "\n=== read_local_file: text file, expect the content returned directly ==="
)
with _tempfile.TemporaryDirectory() as _tmpdir2:
    text_path = f"{_tmpdir2}/cipher.txt"
    with open(text_path, "w") as f:
        f.write("picoCTF{read_local_file_text_smoke_test}")
    text_result = read_local_file.invoke({"file_path": text_path})
    print(text_result)
    assert "picoCTF{read_local_file_text_smoke_test}" in text_result, (
        f"expected the text file's content in the result, got {text_result}"
    )
    assert "type: text" in text_result, f"expected the file type reported as text, got {text_result}"

    print("\n=== read_local_file: binary file, expect a hex preview and base64 content ===")
    enc_path = f"{_tmpdir2}/secret.enc"
    binary_content = bytes(range(256))
    with open(enc_path, "wb") as f:
        f.write(binary_content)
    enc_result = read_local_file.invoke({"file_path": enc_path})
    print(enc_result)
    assert "type: binary" in enc_result, f"expected the file type reported as binary, got {enc_result}"
    import base64 as _base64  # local import, avoids polluting the module-level namespace above

    assert _base64.b64encode(binary_content).decode() in enc_result, (
        f"expected the full raw content base64-encoded in the result, got {enc_result}"
    )

    print("\n=== read_local_file: search_pattern searches the full text file, not just the cap ===")
    large_text_path = f"{_tmpdir2}/large.txt"
    padding = "x" * (8192 * 2)
    with open(large_text_path, "w") as f:
        f.write(f"{padding}picoCTF{{buried_past_the_cutoff}}{padding}")
    default_large_result = read_local_file.invoke({"file_path": large_text_path})
    assert "buried_past_the_cutoff" not in default_large_result, (
        "test setup assumption broken: the flag should be past the default 8192-char cutoff"
    )
    assert "truncated" in default_large_result, "expected the default path to report truncation"

    search_large_result = read_local_file.invoke({
        "file_path": large_text_path, "search_pattern": r"picoCTF\{[^}]{1,60}\}",
    })
    print(search_large_result)
    assert "picoCTF{buried_past_the_cutoff}" in search_large_result, (
        f"expected search_pattern to find the flag past the truncation cutoff, got {search_large_result}"
    )

    print("\n=== read_local_file: missing file, expect a clean error string, not an exception ===")
    missing_file_result = read_local_file.invoke({"file_path": f"{_tmpdir2}/does_not_exist.enc"})
    print(missing_file_result)
    assert "no such file" in missing_file_result.lower(), (
        f"expected a clean missing-file message, got {missing_file_result}"
    )

print(
    "\n=== extract_hidden_key + rsa_decrypt_file: end-to-end RSA-key-in-image-metadata pipeline "
    "-- regression test for a real, confirmed fabrication: given this exact challenge shape with "
    "no tool to actually perform the steps, the model never called any tool at all and stated a "
    "flag with a made-up suffix instead. Real flag: picoCTF{rs4_k3y_1n_1mg_4eedd678}, recovered "
    "here via the actual tools end to end, not by hand ==="
)
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import padding as _rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

with _tempfile.TemporaryDirectory() as _tmpdir3:
    _private_key = _rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _pem_bytes = _private_key.private_bytes(
        encoding=_serialization.Encoding.PEM,
        format=_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_serialization.NoEncryption(),
    )
    _plaintext = b"picoCTF{rsa_tools_smoke_test}"
    _ciphertext = _private_key.public_key().encrypt(_plaintext, _rsa_padding.PKCS1v15())

    stego_image_path = f"{_tmpdir3}/image.jpg"
    stego_png_info = _PngInfo()  # PNG for simplicity -- extract_hidden_key reads via Pillow's
    # generic .info dict, same mechanism regardless of JPEG/PNG, matching the real challenge shape
    stego_png_info.add_text("comment", _pem_bytes.hex())
    _Image.new("RGB", (4, 4)).save(stego_image_path.replace(".jpg", ".png"), pnginfo=stego_png_info)
    stego_image_path = stego_image_path.replace(".jpg", ".png")

    ciphertext_path = f"{_tmpdir3}/flag.enc"
    with open(ciphertext_path, "wb") as f:
        f.write(_ciphertext)

    key_out_path = f"{_tmpdir3}/private.pem"
    extract_result = extract_hidden_key.invoke({
        "source_path": stego_image_path, "output_key_path": key_out_path,
        "encoding": "hex", "field": "comment",
    })
    print(extract_result)
    assert "Wrote" in extract_result, f"expected a success message, got {extract_result}"
    assert "-----BEGIN PRIVATE KEY-----" in extract_result, (
        f"expected the PEM preview in the result, got {extract_result}"
    )

    decrypt_result = rsa_decrypt_file.invoke({
        "key_path": key_out_path, "ciphertext_path": ciphertext_path,
    })
    print(decrypt_result)
    assert "picoCTF{rsa_tools_smoke_test}" in decrypt_result, (
        f"expected the correct decrypted plaintext, got {decrypt_result}"
    )
    assert "pkcs1v15: SUCCESS" in decrypt_result, (
        f"expected auto mode to report which padding succeeded, got {decrypt_result}"
    )

    print("\n=== extract_hidden_key: unknown metadata field is a clean error, not an exception ===")
    unknown_field_result = extract_hidden_key.invoke({
        "source_path": stego_image_path, "output_key_path": key_out_path,
        "encoding": "hex", "field": "does_not_exist",
    })
    print(unknown_field_result)
    assert "not found" in unknown_field_result.lower(), (
        f"expected a clean field-not-found message, got {unknown_field_result}"
    )

    print("\n=== rsa_decrypt_file: missing key file is a clean error, not an exception ===")
    missing_key_result = rsa_decrypt_file.invoke({
        "key_path": f"{_tmpdir3}/does_not_exist.pem", "ciphertext_path": ciphertext_path,
    })
    print(missing_key_result)
    assert "no such file" in missing_key_result.lower(), (
        f"expected a clean missing-key message, got {missing_key_result}"
    )

    print("\n=== rsa_decrypt_file: wrong padding_mode alone reports failure, not a crash ===")
    wrong_padding_result = rsa_decrypt_file.invoke({
        "key_path": key_out_path, "ciphertext_path": ciphertext_path, "padding_mode": "oaep-sha256",
    })
    print(wrong_padding_result)
    assert "Decryption failed" in wrong_padding_result, (
        f"expected a clean decryption-failure message, got {wrong_padding_result}"
    )

    print(
        "\n=== local-file tools: given a directory instead of a file, list its contents "
        "instead of just saying 'no such file' -- regression test for a real, confirmed "
        "failure: a challenge prompt gave the agent a directory path (not individual "
        "filenames), the model reasonably tried that path directly, got a bare 'no such file' "
        "from the old check, concluded the challenge's files didn't exist at all, and gave up "
        "on local files entirely -- falling back to web_search and lifting a wrong flag from a "
        "public writeup of a DIFFERENT instance of the same challenge ==="
    )
    dir_check_result = check_local_file(_tmpdir3)
    print(dir_check_result)
    assert dir_check_result is not None, "expected an error string for a directory, not None"
    assert "is a directory, not a file" in dir_check_result, (
        f"expected the directory case to be distinguished from 'no such file', got {dir_check_result}"
    )
    assert "image.png" in dir_check_result and "flag.enc" in dir_check_result, (
        f"expected the directory's actual contents listed, got {dir_check_result}"
    )

    read_local_file_dir_result = read_local_file.invoke({"file_path": _tmpdir3})
    print(read_local_file_dir_result)
    assert "is a directory, not a file" in read_local_file_dir_result, (
        f"expected read_local_file to list directory contents, got {read_local_file_dir_result}"
    )

    extract_metadata_dir_result = extract_metadata.invoke({"file_path": _tmpdir3})
    assert "is a directory, not a file" in extract_metadata_dir_result, (
        f"expected extract_metadata to list directory contents, got {extract_metadata_dir_result}"
    )

    extract_hidden_key_dir_result = extract_hidden_key.invoke({
        "source_path": _tmpdir3, "output_key_path": key_out_path, "encoding": "hex",
    })
    assert "is a directory, not a file" in extract_hidden_key_dir_result, (
        f"expected extract_hidden_key to list directory contents, got {extract_hidden_key_dir_result}"
    )

    rsa_decrypt_dir_result = rsa_decrypt_file.invoke({
        "key_path": _tmpdir3, "ciphertext_path": ciphertext_path,
    })
    assert "is a directory, not a file" in rsa_decrypt_dir_result, (
        f"expected rsa_decrypt_file to list directory contents, got {rsa_decrypt_dir_result}"
    )

print(
    "\n=== modpow + dh_shared_secret_decrypt: real Diffie-Hellman shared-secret computation -- "
    "regression test for a real, confirmed failure: given this exact challenge shape, a model "
    "correctly identified the whole algorithm and even wrote real-looking Python narrating the "
    "computation in its final answer, but never actually executed it -- the flag it stated as "
    "if the code had run was completely wrong. Real numbers from picoCTF's 'Shared Secrets' "
    "challenge; real flag: picoCTF{dh_s3cr3t_9982ffe6} ==="
)
_dh_p = "2549189574813286838731164889759660985718829773591105476199519705873412196312430317020838926243603568621442315899465054113173947320336232433955810978828549997135650568305743237094254970976323874275496906890604182065479938670042325573071240425116728265626285703063369264515156139785599306841009782845534345233632656299"
_dh_A = "985445375040965660286925493195705022105311734388727844225279873957046781773616909873718436322630406874986079724535489250394868561673679481570937115431819833192904575232350968046861369069756001815958202523940582773045326660550531101765085548729437758998731821183288714745944939562470177082773230192655925648636693128"
_dh_b = "2531748005435027320362428017101462589109367420602712788105635351744163633032425558043495896092073893867970357855640982255766093320905998447373338799811757556564212066483256443137066327562660885114225713445384050398429354624442622758857644344928037376358520893635120478670063221879818261074326351747274950092218676710"
_dh_enc = "4d545e527e697b465955624e0e5e4f0e49620404050f5b5b580b40"

modpow_result = modpow.invoke({"base": _dh_A, "exponent": _dh_b, "modulus": _dh_p})
print(modpow_result)
assert modpow_result == "1611677189114812825149716158968732160651122397471791833467001594009658299196717372486042257866544376266445988905569334709388744891111642232673722817301720967498664742191954389210720275730748315629194771205794593361542504869803156206850438554554059621309092234711061578703901789188801310777808741046746170047523346237", (
    f"expected the real, correct modular exponentiation result, got {modpow_result}"
)

dh_result = dh_shared_secret_decrypt.invoke({
    "public_key": _dh_A, "exponent": _dh_b, "modulus": _dh_p, "ciphertext_hex": _dh_enc,
})
print(dh_result)
assert "picoCTF{dh_s3cr3t_9982ffe6}" in dh_result, (
    f"expected the real, correctly-decrypted flag, got {dh_result}"
)

print("\n=== modpow: non-numeric input is a clean error, not an exception ===")
bad_modpow_result = modpow.invoke({"base": "not_a_number", "exponent": "2", "modulus": "7"})
print(bad_modpow_result)
assert "must all be decimal integers" in bad_modpow_result, (
    f"expected a clean input-validation message, got {bad_modpow_result}"
)

print("\n=== modpow: zero modulus is a clean error, not a ZeroDivisionError ===")
zero_modulus_result = modpow.invoke({"base": "2", "exponent": "3", "modulus": "0"})
print(zero_modulus_result)
assert "modulus must not be zero" in zero_modulus_result, (
    f"expected a clean zero-modulus message, got {zero_modulus_result}"
)

print("\n=== dh_shared_secret_decrypt: invalid hex ciphertext is a clean error, not an exception ===")
bad_hex_result = dh_shared_secret_decrypt.invoke({
    "public_key": "5", "exponent": "3", "modulus": "23", "ciphertext_hex": "not hex at all",
})
print(bad_hex_result)
assert "not valid hex" in bad_hex_result, f"expected a clean invalid-hex message, got {bad_hex_result}"

print(
    "\n=== crack_hash: cracks all 3 real hashes from a live picoCTF 'hashcrack' run "
    "(MD5, SHA-1, SHA-256), auto-detecting algorithm from hex length -- regression test for a "
    "real, confirmed run where the agent had no way to crack a hash at all and just read the "
    "banner without attempting a password ==="
)
md5_result = crack_hash.invoke({"target_hash": "482c811da5d5b4bc6d497ffa98491e38"})
print(md5_result)
assert md5_result == "Cracked (md5): password123", f"expected the real MD5 crack, got {md5_result}"

sha1_result = crack_hash.invoke({"target_hash": "b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3"})
print(sha1_result)
assert sha1_result == "Cracked (sha1): letmein", f"expected the real SHA-1 crack, got {sha1_result}"

print(
    "\n=== crack_hash: cracks a password needing a full 3-digit numeric suffix (qwerty098), not "
    "just the small fixed suffix set (1/123/year) -- regression test for a real, confirmed miss: "
    "the built-in wordlist first reported this SHA-256 hash 'not found', forcing a web_search "
    "detour to locate the password from a public writeup instead of cracking it directly ==="
)
sha256_result = crack_hash.invoke({
    "target_hash": "916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745",
})
print(sha256_result)
assert sha256_result == "Cracked (sha256): qwerty098", f"expected the real SHA-256 crack, got {sha256_result}"

print("\n=== crack_hash: a hash with no match in the built-in wordlist is a clean message, not a crash ===")
no_match_result = crack_hash.invoke({"target_hash": "a" * 64})
print(no_match_result)
assert no_match_result.startswith("Not found in "), f"expected a clean no-match message, got {no_match_result}"

print("\n=== crack_hash: an unrecognized hash length can't auto-detect, expect a clean error ===")
bad_length_result = crack_hash.invoke({"target_hash": "abc123"})
print(bad_length_result)
assert "Could not auto-detect" in bad_length_result, f"expected a clean auto-detect failure, got {bad_length_result}"

print("\n=== crack_hash: an unknown explicit algorithm is a clean error, not an exception ===")
bad_algo_result = crack_hash.invoke({"target_hash": "abc123", "algorithm": "not_a_real_algo"})
print(bad_algo_result)
assert "Unknown hash algorithm" in bad_algo_result, f"expected a clean unknown-algorithm message, got {bad_algo_result}"

print("\n=== crack_hash: wordlist_path lets a custom/bigger list be used instead of the built-in one ===")
with _tempfile.TemporaryDirectory() as _tmpdir_wordlist:
    wordlist_file = f"{_tmpdir_wordlist}/custom.txt"
    with open(wordlist_file, "w") as f:
        f.write("not_the_one\nsuper_obscure_password_42\nalso_not_it\n")
    import hashlib as _hashlib  # local import, avoids polluting module namespace above

    custom_target = _hashlib.md5(b"super_obscure_password_42").hexdigest()
    custom_result = crack_hash.invoke({"target_hash": custom_target, "wordlist_path": wordlist_file})
    print(custom_result)
    assert custom_result == "Cracked (md5): super_obscure_password_42", (
        f"expected the custom wordlist entry to be found, got {custom_result}"
    )

    print("\n=== crack_hash: wordlist_path pointing at a directory lists its contents, same as other local-file tools ===")
    wordlist_dir_result = crack_hash.invoke({"target_hash": custom_target, "wordlist_path": _tmpdir_wordlist})
    print(wordlist_dir_result)
    assert "is a directory, not a file" in wordlist_dir_result, (
        f"expected the directory case to be handled the same as other local-file tools, got {wordlist_dir_result}"
    )

print(
    "\n=== build_system_prompt: priority-order guardrail present -- regression test for a real, "
    "confirmed failure: with a matched skill-pack category, the system prompt told the model to "
    "call search_skills 'before relying on general knowledge' unconditionally, so given a local "
    "file challenge (category: forensics), the model's ONLY action the entire run was a "
    "search_skills call -- it never touched the actual challenge files at all ==="
)
priority_prompt = message_text(build_system_prompt("forensics"))
print(priority_prompt[:600])
assert "PRIORITY ORDER" in priority_prompt, (
    f"expected an explicit priority-order instruction to inspect real data before searching "
    f"reference material, got {priority_prompt[:300]}"
)
assert "never the default first action when real data is already available" in priority_prompt, (
    "expected search_vault/search_skills/web_search framed as a fallback, not the default "
    "first move, in the system prompt"
)

print("\n=== search_vault: known term ('cookies', present in Web_Placeholder.md) ===")
found = search_vault.invoke({"query": "cookies"})
print(found)
assert "Web_Placeholder.md" in found, "expected Web_Placeholder.md in results"
assert "cookie" in found.lower(), "expected matched line in results"

print("\n=== search_vault: term not present anywhere in the vault ===")
not_found = search_vault.invoke({"query": "zzz_definitely_not_in_vault_zzz"})
print(not_found)
assert "Web_Placeholder.md" not in not_found, "unexpected filename in no-match result"
assert "No matches" in not_found, "expected clean no-match message"

print("\n=== search_skills: known term ('Wiener', present in ctf-crypto's RSA attack notes) ===")
skills_found = search_skills.invoke({"query": "Wiener"})
print(skills_found)
assert "ctf-crypto" in skills_found, "expected a ctf-crypto file in results"

print("\n=== search_skills: term not present anywhere in installed skills ===")
skills_not_found = search_skills.invoke({"query": "zzz_definitely_not_in_skills_zzz"})
print(skills_not_found)
assert "No matches" in skills_not_found, "expected clean no-match message"

print("\n=== web_search: empty query ===")
empty_search = web_search.invoke({"query": "  "})
print(empty_search)
assert empty_search == "Empty query.", f"expected clean empty-query message, got {empty_search}"

print("\n=== web_search: no TAVILY_API_KEY set, expect graceful degradation not a crash ===")
import os as _os  # local import, avoids polluting the module-level namespace above

_saved_key = _os.environ.pop("TAVILY_API_KEY", None)
try:
    no_key_result = web_search.invoke({"query": "zip slip symlink bypass"})
    print(no_key_result)
    assert "TAVILY_API_KEY not set" in no_key_result, (
        f"expected the graceful unavailable message, got {no_key_result}"
    )
finally:
    if _saved_key is not None:
        _os.environ["TAVILY_API_KEY"] = _saved_key
# A real live-API call is deliberately not part of this automated suite (same reasoning as
# evals/real_target_check.py) -- verify manually with a real TAVILY_API_KEY set if needed.

print("\n=== trim_context: under threshold, expect no-op ===")
small_state = {
    "messages": [HumanMessage(content="hi", id="human-1")]
    + [AIMessage(content=f"turn {i}", id=f"msg-{i}") for i in range(4)],
}
small_result = trim_context(small_state)
print(small_result)
assert small_result == {}, "expected no trimming below MAX_CONTEXT_MESSAGES"

print("\n=== trim_context: over threshold, expect oldest non-anchor messages removed ===")
overflow = 5
trimmable_count = MAX_CONTEXT_MESSAGES + overflow
big_messages = [HumanMessage(content="the actual challenge prompt", id="human-1")]
big_messages += [
    ToolMessage(content=f"tool result {i}", name="echo", tool_call_id=f"call-{i}", id=f"msg-{i}")
    for i in range(trimmable_count)
]
big_state = {"messages": big_messages}
big_result = trim_context(big_state)
print(big_result)
removed_ids = {rm.id for rm in big_result["messages"]}
assert all(isinstance(m, RemoveMessage) for m in big_result["messages"]), "expected only RemoveMessage entries"
assert "human-1" not in removed_ids, "the first HumanMessage (the challenge prompt) must never be trimmed"
assert removed_ids == {f"msg-{i}" for i in range(overflow)}, (
    f"expected exactly the oldest {overflow} trimmable messages removed, got {removed_ids}"
)

print("\n=== observe: ignores a flag-shaped string inside a search_vault/search_skills/web_search "
      "result (regression test -- confirmed live: search_vault surfaced a real flag from an "
      "unrelated, already-solved challenge's vault write-up, and observe() wrongly reported it) ===")
vault_only_state = {
    "messages": [
        ToolMessage(
            content="...see techniques/web/offlinea-full-solve.md: Flag: HTB{not_this_ones_flag}...",
            name="search_vault",
            tool_call_id="call-1",
        ),
    ]
}
vault_only_result = observe(vault_only_state)
print(vault_only_result)
assert vault_only_result == {}, "a flag-shaped string from search_vault must not be reported as the answer"

print("\n=== observe: still detects a real flag from a live-target tool result ===")
live_flag_state = {
    "messages": [
        ToolMessage(
            content="...a decoy from vault: HTB{decoy}...",
            name="search_vault",
            tool_call_id="call-1",
        ),
        ToolMessage(
            content="<untrusted_data>...HTB{real_target_flag}...</untrusted_data>",
            name="fetch_url",
            tool_call_id="call-2",
        ),
    ]
}
live_flag_result = observe(live_flag_state)
print(live_flag_result)
assert live_flag_result == {"flag": "HTB{real_target_flag}"}, "expected the real fetch_url-derived flag, not the vault decoy"

print(
    "\n=== observe: ignores an unfilled template placeholder in a local-file tool's raw source "
    "code -- regression test for the exact live 'Shared Secrets' failure: read_local_file "
    "returned encryption.py's content verbatim, which contains flag = b\"picoCTF{...}\" as a "
    "template, and observe() used to accept that bare match as a solved flag, ending the run "
    "before the agent ever found the real captured-data file ==="
)
placeholder_source_state = {
    "messages": [
        ToolMessage(
            content='file: encryption.py\n\nflag = b"picoCTF{...}"\nenc = bytes([...])',
            name="read_local_file",
            tool_call_id="call-1",
        ),
    ]
}
placeholder_source_result = observe(placeholder_source_state)
print(placeholder_source_result)
assert placeholder_source_result == {}, (
    f"expected the placeholder in the source code to be ignored, not treated as a solved flag, "
    f"got {placeholder_source_result}"
)

print(
    "\n=== observe: a real flag is still found even after skipping an earlier placeholder match "
    "in the same tool result ==="
)
placeholder_then_real_state = {
    "messages": [
        ToolMessage(
            content='flag = b"picoCTF{...}"  # template\nDecrypted: picoCTF{dh_s3cr3t_9982ffe6}',
            name="dh_shared_secret_decrypt",
            tool_call_id="call-1",
        ),
    ]
}
placeholder_then_real_result = observe(placeholder_then_real_state)
print(placeholder_then_real_result)
assert placeholder_then_real_result == {"flag": "picoCTF{dh_s3cr3t_9982ffe6}"}, (
    f"expected the real flag to be found despite an earlier placeholder in the same message, "
    f"got {placeholder_then_real_result}"
)

print(
    "\n=== build_system_prompt: fabrication guardrail present (regression test -- confirmed live "
    "against a real picoCTF target: fetch_url failed to connect, and instead of reporting that, "
    "the model called web_search, found a public writeup of the same challenge, and confidently "
    "stated that writeup's flag as if it had been read from the real target. picoCTF/HTB randomize "
    "the flag per deployment -- confirmed via two writeups of the identical challenge with two "
    "different flag suffixes -- so that flag was simply wrong) ==="
)
guardrail_prompt = message_text(build_system_prompt("web"))
print(guardrail_prompt)
assert "reference-only" in guardrail_prompt, (
    "expected search_vault/search_skills/web_search to be explicitly marked reference-only, "
    "not a valid flag source, in the system prompt"
)
assert "target is unreachable" in guardrail_prompt, (
    "expected an explicit instruction to report an unreachable target instead of substituting "
    "a flag found via web_search"
)
assert "1of2" in guardrail_prompt and "stray space" in guardrail_prompt, (
    "expected explicit guidance on precisely concatenating a multi-part flag (regression test "
    "-- confirmed live against picoCTF's 'Includes' challenge: two genuine flag fragments, each "
    "read correctly from its own tool result, were joined with an extra space introduced by "
    "hand, producing a flag that reads as wrong despite every individual piece being real)"
)

print("\n=== extract_tool_trace: pairs an AIMessage's tool call with its ToolMessage result ===")
trace_messages = [
    HumanMessage(content="decode this", id="h-1"),
    AIMessage(
        content="",
        id="ai-1",
        tool_calls=[{"name": "identify_and_decode", "args": {"text": "abc"}, "id": "call-1"}],
    ),
    ToolMessage(content="base64: xyz", name="identify_and_decode", tool_call_id="call-1", id="tm-1"),
]
trace = extract_tool_trace(trace_messages)
print(trace)
assert trace == [{"name": "identify_and_decode", "args": {"text": "abc"}, "result": "base64: xyz"}], (
    f"expected a single paired trace entry, got {trace}"
)

print("\n=== extract_tool_trace: a call with no ToolMessage yet has result=None ===")
pending_trace = extract_tool_trace(trace_messages[:2])
print(pending_trace)
assert pending_trace == [{"name": "identify_and_decode", "args": {"text": "abc"}, "result": None}], (
    f"expected result=None while the ToolMessage hasn't arrived yet, got {pending_trace}"
)

print("\n=== extract_allowed_hosts: IPv4, nc-style, host:port, and URL forms ===")
hosts_ip = extract_allowed_hosts("Connect to 10.0.0.5 on port 1337 to grab the flag.")
assert "10.0.0.5" in hosts_ip, f"expected IPv4 extraction, got {hosts_ip}"

hosts_nc = extract_allowed_hosts("nc chal.example.org 1337 to interact with the service.")
assert "chal.example.org" in hosts_nc, f"expected nc-style host extraction, got {hosts_nc}"

hosts_hostport = extract_allowed_hosts("The service is at chal.example.org:1337, good luck.")
assert "chal.example.org" in hosts_hostport, f"expected host:port extraction, got {hosts_hostport}"

hosts_url = extract_allowed_hosts("The challenge is at http://chal.example.org:8080/index.html")
assert "chal.example.org" in hosts_url, f"expected URL host extraction, got {hosts_url}"

print("\n=== extract_allowed_hosts: additional real-world phrasings (Phase 1 stress test) ===")
hosts_colon_port = extract_allowed_hosts("Target: 10.0.0.7:4000")
assert "10.0.0.7" in hosts_colon_port, f"expected 'Target: host:port' extraction, got {hosts_colon_port}"

hosts_service_domain = extract_allowed_hosts("Connect to service.chal.ctf:9999")
assert "service.chal.ctf" in hosts_service_domain, (
    f"expected multi-label hostname:port extraction, got {hosts_service_domain}"
)

hosts_parenthetical_port = extract_allowed_hosts("The box is 172.16.5.20 (port 31337)")
assert "172.16.5.20" in hosts_parenthetical_port, (
    f"expected IPv4 extraction alongside a parenthetical port mention, got {hosts_parenthetical_port}"
)

print("\n=== _last_tool_calls_repeated: 3 identical calls trigger, 3 varied calls don't ===")
repeated_calls = [
    AIMessage(
        content="", id=f"rep-{i}",
        tool_calls=[{"name": "fetch_url", "args": {"url": "http://x"}, "id": f"rc-{i}"}],
    )
    for i in range(3)
]
assert _last_tool_calls_repeated(repeated_calls) is True, (
    "expected 3 identical tool calls to be flagged as repeated"
)

varied_calls = [
    AIMessage(
        content="", id=f"var-{i}",
        tool_calls=[{"name": "fetch_url", "args": {"url": f"http://x{i}"}, "id": f"vc-{i}"}],
    )
    for i in range(3)
]
assert _last_tool_calls_repeated(varied_calls) is False, (
    "expected varied tool call args to NOT be flagged as repeated"
)

print("\n=== fetch_url: local throwaway HTTP server, expect status/header/body + untrusted_data wrapper ===")


class _EchoHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Test-Flag", "flag{fetch_url_smoke_test}")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


http_httpd = socketserver.TCPServer(("127.0.0.1", 0), _EchoHTTPHandler)
http_port = http_httpd.server_address[1]
http_thread = threading.Thread(target=http_httpd.serve_forever, daemon=True)
http_thread.start()
try:
    fetch_result = fetch_url.invoke({"url": f"http://127.0.0.1:{http_port}/"})
    print(fetch_result)
    assert "<untrusted_data" in fetch_result, "expected untrusted_data wrapper"
    assert "flag{fetch_url_smoke_test}" in fetch_result, "expected the flag header to appear in the result"
    assert "HTTP 200" in fetch_result, "expected the status line in the result"
finally:
    http_httpd.shutdown()
    http_httpd.server_close()

print("\n=== fetch_url: connection refused, expect a clean error string, not an exception ===")
refused = fetch_url.invoke({"url": "http://127.0.0.1:1/"})
print(refused)
assert "failed" in refused.lower(), f"expected a clean failure message, got: {refused}"

print(
    "\n=== fetch_url: HTTP verb tampering -- HEAD/PUT/PATCH/DELETE/OPTIONS all work, not just "
    "GET/POST -- regression test for picoCTF's 'Get aHead' challenge, where fetch_url's old "
    "GET/POST-only restriction blocked the actual intended solve: a flag-bearing response header "
    "that only appears on a HEAD request, never on GET ==="
)


class _VerbTamperingHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"plain GET body, no flag here")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("flag", "picoCTF{h34d_r3v34ls_m0r3_th4n_g3t}")
        self.end_headers()

    def do_PUT(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"put ok")

    def do_PATCH(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"patch ok")

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"delete ok")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, PUT, PATCH, DELETE, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


verb_httpd = socketserver.TCPServer(("127.0.0.1", 0), _VerbTamperingHTTPHandler)
verb_port = verb_httpd.server_address[1]
verb_thread = threading.Thread(target=verb_httpd.serve_forever, daemon=True)
verb_thread.start()
try:
    get_result = fetch_url.invoke({"url": f"http://127.0.0.1:{verb_port}/"})
    print(get_result)
    assert "flag{h34d_r3v34ls" not in get_result.lower(), (
        f"test setup assumption broken: GET should never see the flag header, got {get_result}"
    )

    head_result = fetch_url.invoke({"url": f"http://127.0.0.1:{verb_port}/", "method": "HEAD"})
    print(head_result)
    assert "picoCTF{h34d_r3v34ls_m0r3_th4n_g3t}" in head_result, (
        f"expected HEAD to reveal the flag header GET never sends, got {head_result}"
    )
    head_flag_state = observe({
        "messages": [ToolMessage(content=head_result, name="fetch_url", tool_call_id="1")]
    })
    assert head_flag_state == {"flag": "picoCTF{h34d_r3v34ls_m0r3_th4n_g3t}"}, (
        f"expected observe() to detect the flag from a HEAD response header, got {head_flag_state}"
    )

    for verb, expected in (
        ("PUT", "put ok"), ("PATCH", "patch ok"), ("DELETE", "delete ok"),
    ):
        verb_result = fetch_url.invoke({"url": f"http://127.0.0.1:{verb_port}/", "method": verb})
        print(verb_result)
        assert expected in verb_result, f"expected {verb} to reach the server, got {verb_result}"

    options_result = fetch_url.invoke({"url": f"http://127.0.0.1:{verb_port}/", "method": "OPTIONS"})
    print(options_result)
    assert "Allow: GET, HEAD, PUT, PATCH, DELETE, OPTIONS" in options_result, (
        f"expected OPTIONS to reach the server, got {options_result}"
    )

    print("\n=== fetch_url: a genuinely unsupported method is still rejected cleanly ===")
    trace_result = fetch_url.invoke({"url": f"http://127.0.0.1:{verb_port}/", "method": "TRACE"})
    print(trace_result)
    assert "Unsupported method" in trace_result, f"expected a clean rejection, got {trace_result}"
finally:
    verb_httpd.shutdown()
    verb_httpd.server_close()

print(
    "\n=== fetch_url: quoted header key (real observed model bug, e.g. \"'Content-Type'\") is "
    "sanitized before sending, not sent verbatim ==="
)


class _HeaderEchoHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.headers.get("Content-Type", "MISSING").encode())

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


header_echo_httpd = socketserver.TCPServer(("127.0.0.1", 0), _HeaderEchoHTTPHandler)
header_echo_port = header_echo_httpd.server_address[1]
header_echo_thread = threading.Thread(target=header_echo_httpd.serve_forever, daemon=True)
header_echo_thread.start()
try:
    quoted_header_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{header_echo_port}/",
        "method": "POST",
        "body": "a=1",
        "headers": {"'Content-Type'": "application/x-www-form-urlencoded"},
    })
    print(quoted_header_result)
    assert "application/x-www-form-urlencoded" in quoted_header_result, (
        f"expected the sanitized Content-Type header to reach the server, got {quoted_header_result}"
    )
    assert "MISSING" not in quoted_header_result, (
        f"expected the quoted key to still be recognized as Content-Type, got {quoted_header_result}"
    )

    print(
        "\n=== fetch_url: whole 'Header-Name: value' line stuffed into a header VALUE under a "
        "throwaway key (real observed model bug: {\"undefined\": \"Content-Type: application/json\"}) "
        "is re-split into a real key/value pair, not sent verbatim/dropped ==="
    )
    misplaced_header_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{header_echo_port}/",
        "method": "POST",
        "body": "a=1",
        "headers": {"undefined": "Content-Type: application/x-www-form-urlencoded"},
    })
    print(misplaced_header_result)
    assert "application/x-www-form-urlencoded" in misplaced_header_result, (
        f"expected the re-split Content-Type header to reach the server, got {misplaced_header_result}"
    )
    assert "MISSING" not in misplaced_header_result, (
        f"expected the misplaced header line to still be recognized as Content-Type, got {misplaced_header_result}"
    )
finally:
    header_echo_httpd.shutdown()
    header_echo_httpd.server_close()

print(
    "\n=== fetch_url: no-separator/camelCase header key (real observed model bug: "
    "\"contentType\" instead of \"Content-Type\") is canonicalized, not sent verbatim -- "
    "regression test for a run where this silently broke every POST across a whole picoCTF "
    "challenge (PHP's $_POST never populated, no error surfaced -- see practice_runs.md's "
    "'Local Authority' write-up). Uses its own local server rather than reusing "
    "header_echo_httpd above: piling many sequential requests onto one single-threaded "
    "socketserver.TCPServer has been flaky on Windows (WinError 10053, connection aborted) ==="
)


class _CamelCaseHeaderEchoHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.headers.get("Content-Type", "MISSING").encode())

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


camel_header_httpd = socketserver.TCPServer(("127.0.0.1", 0), _CamelCaseHeaderEchoHTTPHandler)
camel_header_port = camel_header_httpd.server_address[1]
camel_header_thread = threading.Thread(target=camel_header_httpd.serve_forever, daemon=True)
camel_header_thread.start()
try:
    camel_case_header_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{camel_header_port}/",
        "method": "POST",
        "body": "a=1",
        "headers": {"contentType": "application/x-www-form-urlencoded"},
    })
    print(camel_case_header_result)
    assert "application/x-www-form-urlencoded" in camel_case_header_result, (
        f"expected the canonicalized Content-Type header to reach the server, got {camel_case_header_result}"
    )
    assert "MISSING" not in camel_case_header_result, (
        f"expected the camelCase key to still be recognized as Content-Type, got {camel_case_header_result}"
    )

    print("\n=== fetch_url: a genuinely custom header key is left untouched, not guessed at ===")
    custom_header_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{camel_header_port}/",
        "method": "POST",
        "body": "a=1",
        "headers": {"X-My-Custom-Flag-Header": "application/x-www-form-urlencoded"},
    })
    print(custom_header_result)
    assert "MISSING" in custom_header_result, (
        f"expected a custom header (not Content-Type) to be left alone, not guessed into "
        f"Content-Type, got {custom_header_result}"
    )
finally:
    camel_header_httpd.shutdown()
    camel_header_httpd.server_close()

print(
    "\n=== fetch_url: search_pattern reaches a flag buried well past MAX_BODY_CHARS (8 KB) -- "
    "regression test for a real hallucination observed live: asked to read a flag out of an "
    "11 MB heap-dump response truncated to 8 KB, the model fabricated a plausible-looking flag "
    "from training-data memory of a public writeup instead of admitting it couldn't see far "
    "enough. search_pattern exists so it never has to guess ==="
)


class _LargeBodyHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        padding = "x" * (fetch_url_module.MAX_BODY_CHARS * 4)
        body = f"{padding}picoCTF{{buried_past_the_truncation_cutoff}}{padding}".encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


large_body_httpd = socketserver.TCPServer(("127.0.0.1", 0), _LargeBodyHTTPHandler)
large_body_port = large_body_httpd.server_address[1]
large_body_thread = threading.Thread(target=large_body_httpd.serve_forever, daemon=True)
large_body_thread.start()
try:
    default_result = fetch_url.invoke({"url": f"http://127.0.0.1:{large_body_port}/"})
    assert "buried_past_the_truncation_cutoff" not in default_result, (
        "test setup assumption broken: the flag should be past the default 8 KB cutoff"
    )
    assert "truncated" in default_result, "expected the default path to report truncation"

    search_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{large_body_port}/",
        "search_pattern": r"picoCTF\{[^}]{1,60}\}",
    })
    print(search_result)
    assert "picoCTF{buried_past_the_truncation_cutoff}" in search_result, (
        f"expected search_pattern to find the flag past the truncation cutoff, got {search_result}"
    )

    no_match_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{large_body_port}/",
        "search_pattern": r"htb\{[^}]{1,60}\}",
    })
    print(no_match_result)
    assert "No match" in no_match_result, f"expected a clean no-match message, got {no_match_result}"
finally:
    large_body_httpd.shutdown()
    large_body_httpd.server_close()


print(
    "\n=== fetch_and_decode_cipher: extracts a ciphertext from a live page and decodes it in one "
    "call, mirroring picoCTF's 'Bookmarklet' challenge shape (var encryptedFlag = \"...\";) ==="
)


class _BookmarkletHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            '<script>var encryptedFlag = "' + _keyed_cipher + '"; var key = "testkey";</script>'
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


bookmarklet_httpd = socketserver.TCPServer(("127.0.0.1", 0), _BookmarkletHTTPHandler)
bookmarklet_port = bookmarklet_httpd.server_address[1]
bookmarklet_thread = threading.Thread(target=bookmarklet_httpd.serve_forever, daemon=True)
bookmarklet_thread.start()
try:
    cipher_result = fetch_and_decode_cipher.invoke({
        "url": f"http://127.0.0.1:{bookmarklet_port}/",
        "key": "testkey",
        "pattern": r'encryptedFlag\s*=\s*"([^"]*)"',
        "mode": "subtract",
    })
    print(cipher_result)
    assert "<untrusted_data" in cipher_result, "expected untrusted_data wrapper"
    assert _keyed_plain in cipher_result, (
        f"expected the correctly decoded plaintext in the result, got {cipher_result}"
    )

    print("\n=== fetch_and_decode_cipher: pattern with no match is a clean message, not an exception ===")
    no_match_cipher_result = fetch_and_decode_cipher.invoke({
        "url": f"http://127.0.0.1:{bookmarklet_port}/",
        "key": "testkey",
        "pattern": r"notPresent=\"([^\"]*)\"",
        "mode": "subtract",
    })
    print(no_match_cipher_result)
    assert "did not match" in no_match_cipher_result, (
        f"expected a clean no-match message, got {no_match_cipher_result}"
    )
finally:
    bookmarklet_httpd.shutdown()
    bookmarklet_httpd.server_close()


print(
    "\n=== fetch_url: session_id persists cookies across calls (regression test for the "
    "IntroToBurp cookie-loss bug -- the agent's own run kept dropping the session cookie on "
    "plain GET calls, forcing an endless re-register loop instead of ever reaching an "
    "authenticated page) ==="
)


class _CookieSessionHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "sid=granted" in self.headers.get("Cookie", ""):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"authenticated")
        else:
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=granted; Path=/")
            self.end_headers()
            self.wfile.write(b"anonymous")

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


cookie_httpd = socketserver.TCPServer(("127.0.0.1", 0), _CookieSessionHTTPHandler)
cookie_port = cookie_httpd.server_address[1]
cookie_thread = threading.Thread(target=cookie_httpd.serve_forever, daemon=True)
cookie_thread.start()
try:
    first_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "test-session-a",
    })
    print(first_call)
    assert "anonymous" in first_call, f"expected the first call (no cookie yet) to be anonymous, got {first_call}"

    second_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "test-session-a",
    })
    print(second_call)
    assert "authenticated" in second_call, (
        f"expected the second call, same session_id, to automatically carry the cookie the "
        f"first response set, with no Cookie header supplied by hand, got {second_call}"
    )

    stateless_call = fetch_url.invoke({"url": f"http://127.0.0.1:{cookie_port}/"})
    print(stateless_call)
    assert "anonymous" in stateless_call, (
        f"expected a call with no session_id to stay fully stateless (no bleed-over from the "
        f"session_id path above), got {stateless_call}"
    )

    print("\n=== fetch_url: concurrent session cap is enforced ===")
    # test-session-a from above is still open and already counts toward the cap.
    for i in range(fetch_url_module.MAX_CONCURRENT_HTTP_SESSIONS - 1):
        sid = f"cap-session-{i}"
        cap_call = fetch_url.invoke({"url": f"http://127.0.0.1:{cookie_port}/", "session_id": sid})
        assert "Refused" not in cap_call, f"expected session {sid} to open, got {cap_call}"

    over_cap_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "one-too-many",
    })
    print(over_cap_call)
    assert "Refused" in over_cap_call, f"expected the session cap to be enforced, got {over_cap_call}"
    fetch_url_module.close_all_http_sessions()

    print(
        "\n=== fetch_url: expired session lifetime drops the cookie jar (falls back to a fresh "
        "session under the same id rather than reusing stale cookies) ==="
    )
    expiring_first = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "expiring-session",
    })
    assert "anonymous" in expiring_first
    fetch_url_module._http_sessions["expiring-session"]["created_at"] -= (
        fetch_url_module.HTTP_SESSION_LIFETIME_SECONDS + 1
    )
    expired_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "expiring-session",
    })
    print(expired_call)
    assert "anonymous" in expired_call, (
        f"expected the expired session's cookie jar to be dropped, not reused, got {expired_call}"
    )
finally:
    fetch_url_module.close_all_http_sessions()
    cookie_httpd.shutdown()
    cookie_httpd.server_close()


print("\n=== tcp_session: open/send/close against a local echo server ===")


class _EchoTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(b"echo: " + data)


tcp_httpd = socketserver.TCPServer(("127.0.0.1", 0), _EchoTCPHandler)
tcp_port = tcp_httpd.server_address[1]
tcp_thread = threading.Thread(target=tcp_httpd.serve_forever, daemon=True)
tcp_thread.start()
try:
    open_result = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
    print(open_result)
    assert "session_id=" in open_result, f"expected a session_id in open result, got {open_result}"
    session_id = open_result.split("session_id=")[1].split(" ")[0]

    send_result = tcp_send.invoke({"session_id": session_id, "data": "hello"})
    print(send_result)
    assert "echo: hello" in send_result, f"expected echoed data back, got {send_result}"
    assert "<untrusted_data" in send_result, "expected untrusted_data wrapper on tcp_send result"

    close_result = tcp_close.invoke({"session_id": session_id})
    print(close_result)
    assert "closed" in close_result.lower()

    print("\n=== tcp_session: sending on a closed/unknown session_id is a clean error, not an exception ===")
    stale_result = tcp_send.invoke({"session_id": session_id, "data": "hello again"})
    print(stale_result)
    assert "unknown" in stale_result.lower() or "expired" in stale_result.lower()

    print("\n=== tcp_session: concurrent session cap is enforced ===")
    opened_ids = []
    for _ in range(tcp_session.MAX_CONCURRENT_SESSIONS):
        cap_result = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
        assert "session_id=" in cap_result, f"expected session to open, got {cap_result}"
        opened_ids.append(cap_result.split("session_id=")[1].split(" ")[0])

    over_cap_result = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
    print(over_cap_result)
    assert "Refused" in over_cap_result, f"expected the session cap to be enforced, got {over_cap_result}"
    for sid in opened_ids:
        tcp_close.invoke({"session_id": sid})

    print("\n=== tcp_session: expired session lifetime is enforced ===")
    expiring_open = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
    expiring_id = expiring_open.split("session_id=")[1].split(" ")[0]
    tcp_session._sessions[expiring_id]["opened_at"] -= tcp_session.SESSION_LIFETIME_SECONDS + 1
    expired_result = tcp_send.invoke({"session_id": expiring_id, "data": "too late"})
    print(expired_result)
    assert "lifetime" in expired_result.lower() or "expired" in expired_result.lower()
finally:
    tcp_session.close_all_sessions()
    tcp_httpd.shutdown()
    tcp_httpd.server_close()


print("\n=== port_scan: open port with a banner, plus closed ports, against a local server ===")


class _BannerTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"BANNER-9000\n")


banner_httpd = socketserver.TCPServer(("127.0.0.1", 0), _BannerTCPHandler)
banner_port = banner_httpd.server_address[1]
banner_thread = threading.Thread(target=banner_httpd.serve_forever, daemon=True)
banner_thread.start()
try:
    scan_ports = f"{banner_port},{banner_port + 1},{banner_port + 2}"
    scan_result = port_scan.invoke({"host": "127.0.0.1", "ports": scan_ports})
    print(scan_result)
    assert "<untrusted_data" in scan_result, "expected untrusted_data wrapper"
    assert f"{banner_port}\topen\tBANNER-9000" in scan_result, (
        f"expected the open port's banner to be reported, got {scan_result}"
    )
    assert f"{banner_port + 1}\tclosed/filtered" in scan_result, (
        f"expected the unused adjacent port to be reported closed/filtered, got {scan_result}"
    )
finally:
    banner_httpd.shutdown()
    banner_httpd.server_close()

print("\n=== port_scan: default ports list is used when none is supplied ===")
default_scan = port_scan.invoke({"host": "127.0.0.1", "ports": ""})
print(default_scan[:200] + "...")
assert "<untrusted_data" in default_scan, "expected untrusted_data wrapper on default-ports scan"
assert default_scan.count("\n") >= 20, "expected roughly the default ~20-port list to be scanned"

print("\n=== port_scan: an oversized explicit ports list is capped, not run in full ===")
from agent.tools.port_scan import MAX_PORTS  # noqa: E402 - imported here to keep it near its one use

oversized_ports = ",".join(str(p) for p in range(20000, 20000 + MAX_PORTS + 25))
capped_scan = port_scan.invoke({"host": "127.0.0.1", "ports": oversized_ports})
port_rows = [
    line for line in capped_scan.split("\n")
    if "\t" in line and not line.startswith("port\t")
]
assert len(port_rows) == MAX_PORTS, f"expected exactly {MAX_PORTS} ports scanned, got {len(port_rows)}"


print("\n=== dir_enum: normal sweep, known hits reported and 404s omitted ===")


class _DirEnumHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/old-login":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


dir_enum_httpd = socketserver.TCPServer(("127.0.0.1", 0), _DirEnumHTTPHandler)
dir_enum_port = dir_enum_httpd.server_address[1]
dir_enum_thread = threading.Thread(target=dir_enum_httpd.serve_forever, daemon=True)
dir_enum_thread.start()
try:
    sweep_result = dir_enum.invoke({
        "base_url": f"http://127.0.0.1:{dir_enum_port}",
        "paths": "admin,old-login,definitely-not-real",
    })
    print(sweep_result)
    assert "<untrusted_data" in sweep_result, "expected untrusted_data wrapper"
    assert "admin\t200" in sweep_result, f"expected the 200 hit reported, got {sweep_result}"
    assert "old-login\t302" in sweep_result and "/login" in sweep_result, (
        f"expected the redirect and its Location reported, got {sweep_result}"
    )
    assert "definitely-not-real\t" not in sweep_result, (
        f"expected the 404 path omitted from the report, got {sweep_result}"
    )
finally:
    dir_enum_httpd.shutdown()
    dir_enum_httpd.server_close()

print("\n=== dir_enum: wildcard/catch-all target aborts instead of reporting false positives ===")


class _WildcardHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"catch-all page")

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


wildcard_httpd = socketserver.TCPServer(("127.0.0.1", 0), _WildcardHTTPHandler)
wildcard_port = wildcard_httpd.server_address[1]
wildcard_thread = threading.Thread(target=wildcard_httpd.serve_forever, daemon=True)
wildcard_thread.start()
try:
    wildcard_result = dir_enum.invoke({"base_url": f"http://127.0.0.1:{wildcard_port}"})
    print(wildcard_result)
    assert "aborted" in wildcard_result.lower(), f"expected an abort message, got {wildcard_result}"
    assert "wildcard" in wildcard_result.lower() or "catch-all" in wildcard_result.lower(), (
        f"expected the wildcard/catch-all finding named, got {wildcard_result}"
    )
    assert "path\tstatus" not in wildcard_result, (
        f"expected no per-path row table on an aborted sweep, got {wildcard_result}"
    )
finally:
    wildcard_httpd.shutdown()
    wildcard_httpd.server_close()

print("\n=== dir_enum: an oversized explicit paths list is capped, not run in full ===")
from agent.tools.dir_enum import MAX_PATHS  # noqa: E402 - imported here to keep it near its one use


class _DirEnumCapHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/cap-item-"):
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


dir_enum_cap_httpd = socketserver.TCPServer(("127.0.0.1", 0), _DirEnumCapHTTPHandler)
dir_enum_cap_port = dir_enum_cap_httpd.server_address[1]
dir_enum_cap_thread = threading.Thread(target=dir_enum_cap_httpd.serve_forever, daemon=True)
dir_enum_cap_thread.start()
try:
    oversized_paths = ",".join(f"cap-item-{i}" for i in range(MAX_PATHS + 25))
    capped_sweep = dir_enum.invoke({
        "base_url": f"http://127.0.0.1:{dir_enum_cap_port}",
        "paths": oversized_paths,
    })
    cap_rows = [line for line in capped_sweep.split("\n") if line.startswith("cap-item-")]
    assert len(cap_rows) == MAX_PATHS, f"expected exactly {MAX_PATHS} paths swept, got {len(cap_rows)}"
finally:
    dir_enum_cap_httpd.shutdown()
    dir_enum_cap_httpd.server_close()

print("\n=== dir_enum: unreachable target, expect a clean error string, not an exception ===")
dir_enum_refused = dir_enum.invoke({"base_url": "http://127.0.0.1:1"})
print(dir_enum_refused)
assert "failed" in dir_enum_refused.lower(), f"expected a clean failure message, got: {dir_enum_refused}"

print(
    "\n=== radare2_analyze: real end-to-end run against a real ELF (/bin/true, pulled live "
    "through WSL) -- not a mock, exercises the actual wsl.exe/rabin2/r2 bridge ==="
)
import subprocess as _subprocess


def _wsl_available() -> bool:
    """True only if the WSL bridge actually responds to a trivial command within a hard timeout.
    A machine without WSL -- or with wsl.exe present but no distro installed, which can block or
    prompt indefinitely -- otherwise makes this block HANG the entire smoke suite (a real,
    observed failure mode, see evals/practice_runs.md). Probing first lets the radare2 tests SKIP
    cleanly there instead, so the rest of the suite still runs to completion on any machine."""
    try:
        result = _subprocess.run(
            ["wsl.exe", "-e", "true"], capture_output=True, timeout=8
        )
        return result.returncode == 0
    except (OSError, _subprocess.SubprocessError):
        return False


if not _wsl_available():
    print(
        "SKIPPED: WSL unavailable (wsl.exe not found or unresponsive within 8s). radare2_analyze "
        "needs the WSL toolchain bridge; skipping its end-to-end tests rather than hanging the "
        "suite. Run these on the WSL-provisioned machine to exercise the disassembler path."
    )
else:
    import base64 as _b64  # local import: only this test block needs it

    _r2_test_bin = _subprocess.run(
        ["wsl.exe", "-e", "cat", "/bin/true"], capture_output=True, timeout=10
    ).stdout
    assert _r2_test_bin, "expected /bin/true to actually produce bytes via WSL -- is WSL installed?"
    _r2_b64 = _b64.b64encode(_r2_test_bin).decode()

    r2_info = radare2_analyze.invoke({"content_b64": _r2_b64, "mode": "info"})
    print(r2_info)
    assert "elf" in r2_info.lower(), f"expected ELF file info from rabin2 -I, got: {r2_info}"

    print("\n=== radare2_analyze: strings mode ===")
    r2_strings = radare2_analyze.invoke({"content_b64": _r2_b64, "mode": "strings"})
    print(r2_strings)
    assert "<untrusted_data" in r2_strings, "expected the result wrapped in <untrusted_data> tags"

    print("\n=== radare2_analyze: unknown mode is rejected with a clear error, not a crash ===")
    r2_bad_mode = radare2_analyze.invoke({"content_b64": _r2_b64, "mode": "delete_everything"})
    print(r2_bad_mode)
    assert "Unknown mode" in r2_bad_mode, f"expected an unknown-mode error, got: {r2_bad_mode}"

    print("\n=== radare2_analyze: invalid base64 is rejected with a clear error, not a crash ===")
    r2_bad_b64 = radare2_analyze.invoke({"content_b64": "not valid base64!!!", "mode": "info"})
    print(r2_bad_b64)
    assert "not valid base64" in r2_bad_b64, f"expected a base64 error, got: {r2_bad_b64}"

    print(
        "\n=== radare2_analyze: a symbol value shaped like a shell/r2-command injection attempt "
        "is rejected, not passed through to the -c command string ==="
    )
    r2_injection = radare2_analyze.invoke(
        {"content_b64": _r2_b64, "mode": "disasm", "symbol": "main; !rm -rf /"}
    )
    print(r2_injection)
    assert "Invalid symbol" in r2_injection, f"expected the injection attempt rejected, got: {r2_injection}"

print(
    "\n=== fetch_and_join_fragments: joins two comment-hidden fragments with no stray "
    "separator -- regression test for picoCTF's 'Includes' challenge, where the model correctly "
    "read both real fragments but introduced a space joining them by hand, on more than one "
    "attempt even after a prompt-only guardrail was added ==="
)


class _IncludesHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        if self.path == "/style.css":
            body = b"body { background-color: lightblue; }\n\n/*  picoCTF{1nclu51v17y_1of2_  */"
        elif self.path == "/script.js":
            body = b"function greetings() { alert('hi'); }\n\n//  f7w_2of2_df589022}"
        else:
            body = b""
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


includes_httpd = socketserver.TCPServer(("127.0.0.1", 0), _IncludesHTTPHandler)
includes_port = includes_httpd.server_address[1]
includes_thread = threading.Thread(target=includes_httpd.serve_forever, daemon=True)
includes_thread.start()
try:
    fragments_result = fetch_and_join_fragments.invoke({
        "base_url": f"http://127.0.0.1:{includes_port}",
        "paths": "style.css,script.js",
        "pattern": r"(?:/\*|//)\s*(.*?)\s*(?:\*/|$)",
    })
    print(fragments_result)
    assert "<untrusted_data" in fragments_result, "expected untrusted_data wrapper"
    assert "picoCTF{1nclu51v17y_1of2_f7w_2of2_df589022}" in fragments_result, (
        f"expected the two fragments joined with no separator, got {fragments_result}"
    )
    assert "1of2_ f7w" not in fragments_result, (
        f"expected no stray space between the two fragments, got {fragments_result}"
    )

    print("\n=== fetch_and_join_fragments: an unmatched pattern on a later path aborts cleanly ===")
    partial_result = fetch_and_join_fragments.invoke({
        "base_url": f"http://127.0.0.1:{includes_port}",
        "paths": "style.css,does-not-exist.js",
        "pattern": r"(?:/\*|//)\s*(.*?)\s*(?:\*/|$)",
    })
    print(partial_result)
    assert "did not match" in partial_result, f"expected a clean no-match message, got {partial_result}"
    assert "1 of 2" in partial_result, (
        f"expected the abort message to report how many fragments were found first, got {partial_result}"
    )

    print(
        "\n=== fetch_and_join_fragments + observe(): the correctly-joined flag is what gets "
        "detected, not a garbled span from the fragments debug listing -- regression test for a "
        "real bug: the first fragment of a split flag naturally starts with 'picoCTF{' (it's the "
        "first chunk of the real flag), and when the debug listing was printed before the "
        "'Joined:' line, FLAG_PATTERN's left-to-right regex search matched from that accidental "
        "'picoCTF{' all the way to the next stray '}' -- landing inside a LATER fragment's own "
        "repr -- producing a completely wrong 'flag' built out of debug text. Confirmed live "
        "against picoCTF's 'Scavenger Hunt' challenge (5 fragments); 'Joined: ...' now comes "
        "first in the payload specifically so the real answer wins the search ==="
    )
    scavenger_result = fetch_and_join_fragments.invoke({
        "base_url": f"http://127.0.0.1:{includes_port}",
        "paths": "style.css,script.js",
        "pattern": r"(?:/\*|//)\s*(.*?)\s*(?:\*/|$)",
    })
    scavenger_flag_state = observe({
        "messages": [
            ToolMessage(content=scavenger_result, name="fetch_and_join_fragments", tool_call_id="1")
        ]
    })
    print(scavenger_flag_state)
    assert scavenger_flag_state == {"flag": "picoCTF{1nclu51v17y_1of2_f7w_2of2_df589022}"}, (
        f"expected observe() to detect exactly the correctly-joined flag, not a garbled span "
        f"pulled from the debug listing, got {scavenger_flag_state}"
    )
finally:
    includes_httpd.shutdown()
    includes_httpd.server_close()

print(
    "\n=== fetch_and_join_fragments: per-path `patterns` handles genuinely different comment "
    "styles per file -- regression test for picoCTF's 'Scavenger Hunt' challenge (5 files: an "
    "HTML comment with no '}' in it at all, a CSS block comment, two '#' line comments, and a "
    "plain-text file with no comment delimiter). A single shared `pattern` relying on '}' as a "
    "stop condition ran past the HTML file's real fragment to the end of that file's entire "
    "body, since the next '}' was in a completely different file's response ==="
)


class _ScavengerHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        bodies = {
            "/index.html": (
                b"<html><body><p>stuff</p>\n"
                b"\t<!-- Here's the first part of the flag: picoCTF{t -->\n"
                b"      </div>\n\n    </div>\n\n  </body>\n</html>"
            ),
            "/mycss.css": b"body { color: red; }\n\n/* Here's part 2: h4ts_4_l0 */",
            "/robots.txt": b"User-agent: *\nDisallow: /\n# Part 3: t_0f_pl4c\n",
            "/.htaccess": b"# Part 4: 3s_2_lO0k\n",
            "/.DS_Store": b"Congrats! Part 5: _9588550}",
        }
        self.wfile.write(bodies.get(self.path, b""))

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


scavenger_httpd = socketserver.TCPServer(("127.0.0.1", 0), _ScavengerHTTPHandler)
scavenger_port = scavenger_httpd.server_address[1]
scavenger_thread = threading.Thread(target=scavenger_httpd.serve_forever, daemon=True)
scavenger_thread.start()
try:
    per_path_patterns = "\n".join([
        r"flag:\s*(\S+)\s*-->",
        r"part 2:\s*(\S+?)\s*\*/",
        r"# Part 3:\s*(\S+)",
        r"# Part 4:\s*(\S+)",
        r"Part 5:\s*(\S+)",
    ])
    scavenger_paths = "index.html,mycss.css,robots.txt,.htaccess,.DS_Store"
    scavenger_base = f"http://127.0.0.1:{scavenger_port}"

    multi_pattern_result = fetch_and_join_fragments.invoke({
        "base_url": scavenger_base, "paths": scavenger_paths,
        "patterns": per_path_patterns, "group": 1,
    })
    print(multi_pattern_result)
    assert "picoCTF{th4ts_4_l0t_0f_pl4c3s_2_lO0k_9588550}" in multi_pattern_result, (
        f"expected the correctly-joined flag using per-path patterns, got {multi_pattern_result}"
    )
    multi_pattern_flag_state = observe({
        "messages": [
            ToolMessage(content=multi_pattern_result, name="fetch_and_join_fragments", tool_call_id="1")
        ]
    })
    assert multi_pattern_flag_state == {"flag": "picoCTF{th4ts_4_l0t_0f_pl4c3s_2_lO0k_9588550}"}, (
        f"expected observe() to detect the correct 5-fragment flag, got {multi_pattern_flag_state}"
    )

    print(
        "\n=== fetch_and_join_fragments: a single shared pattern that isn't bounded per-file "
        "reproduces the real over-match bug (regression, confirming why patterns exists) ==="
    )
    single_pattern_result = fetch_and_join_fragments.invoke({
        "base_url": scavenger_base, "paths": scavenger_paths,
        "pattern": r"(picoCTF\{[^}]*|h4ts_4_l0|t_0f_pl4c|3s_2_lO0k|_9588550\})",
        "group": 1,
    })
    print(single_pattern_result)
    assert "</html>" in single_pattern_result, (
        "expected the known over-match failure to reproduce with an unbounded shared pattern "
        f"(sanity-checking the bug this feature fixes is real), got {single_pattern_result}"
    )

    print("\n=== fetch_and_join_fragments: patterns/pattern validation errors are clean, not exceptions ===")
    both_given = fetch_and_join_fragments.invoke({
        "base_url": scavenger_base, "paths": "a,b", "pattern": r"(.+)", "patterns": "(.+)\n(.+)",
    })
    print(both_given)
    assert "either pattern or patterns, not both" in both_given

    neither_given = fetch_and_join_fragments.invoke({"base_url": scavenger_base, "paths": "a,b"})
    print(neither_given)
    assert "Provide either pattern" in neither_given

    count_mismatch = fetch_and_join_fragments.invoke({
        "base_url": scavenger_base, "paths": "a,b,c", "patterns": "(.+)\n(.+)",
    })
    print(count_mismatch)
    assert "must match 1:1" in count_mismatch, f"expected a clean count-mismatch message, got {count_mismatch}"
finally:
    scavenger_httpd.shutdown()
    scavenger_httpd.server_close()

print(
    "\n=== fetch_and_join_fragments: repeating the SAME path extracts multiple fragments from "
    "ONE page (not separate files) -- regression test for picoCTF's 'dont-use-client-side' "
    "challenge, where a client-side JS verify() checks 8 separate substrings of one password "
    "field; the agent correctly identified every fragment but hand-typing all 8 out in its final "
    "answer introduced a spurious extra character partway through. Also confirms a repeated path "
    "is fetched once and reused, not re-requested per repetition ==="
)
_fetch_count = {"n": 0}


class _ClientSideHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        _fetch_count["n"] += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write((
            "function verify() {\n"
            "  if (checkpass.substring(0, split) == 'pico') {\n"
            "    if (checkpass.substring(split*6, split*7) == 'eb02') {\n"
            "      if (checkpass.substring(split, split*2) == 'CTF{') {\n"
            "        if (checkpass.substring(split*4, split*5) == 'ts_p') {\n"
            "          if (checkpass.substring(split*3, split*4) == 'lien') {\n"
            "            if (checkpass.substring(split*5, split*6) == 'lz_2') {\n"
            "              if (checkpass.substring(split*2, split*3) == 'no_c') {\n"
            "                if (checkpass.substring(split*7, split*8) == 'b45}') {}}}}}}}}}\n"
        ).encode())

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


clientside_httpd = socketserver.TCPServer(("127.0.0.1", 0), _ClientSideHTTPHandler)
clientside_port = clientside_httpd.server_address[1]
clientside_thread = threading.Thread(target=clientside_httpd.serve_forever, daemon=True)
clientside_thread.start()
try:
    ordered_patterns = "\n".join([
        r"substring\(0, split\) == '([^']*)'",
        r"substring\(split, split\*2\) == '([^']*)'",
        r"substring\(split\*2, split\*3\) == '([^']*)'",
        r"substring\(split\*3, split\*4\) == '([^']*)'",
        r"substring\(split\*4, split\*5\) == '([^']*)'",
        r"substring\(split\*5, split\*6\) == '([^']*)'",
        r"substring\(split\*6, split\*7\) == '([^']*)'",
        r"substring\(split\*7, split\*8\) == '([^']*)'",
    ])
    clientside_result = fetch_and_join_fragments.invoke({
        "base_url": f"http://127.0.0.1:{clientside_port}",
        "paths": ",".join(["index.html"] * 8),
        "patterns": ordered_patterns,
        "group": 1,
    })
    print(clientside_result)
    assert "picoCTF{no_clients_plz_2eb02b45}" in clientside_result, (
        f"expected the correctly-ordered 8-fragment flag from a single page, got {clientside_result}"
    )
    assert _fetch_count["n"] == 1, (
        f"expected the repeated path to be fetched exactly once and reused, got "
        f"{_fetch_count['n']} real HTTP requests"
    )
finally:
    clientside_httpd.shutdown()
    clientside_httpd.server_close()

print(
    "\n=== fetch_and_join_fragments: an empty entry in paths (e.g. ',mycss.css,myjs.js') means "
    "'fetch base_url itself', not 'skip this position' -- regression test for picoCTF's "
    "'Insp3ct0r' challenge: a model used exactly that leading-empty-entry convention expecting 3 "
    "paths (root + 2 files), but the old parser silently dropped the empty entry, shrinking the "
    "list to 2 with no signal that happened. patterns (correctly sized for 3) then failed the "
    "1:1 length check against the silently-shrunk list, and every retry only ever adjusted regex "
    "content, never the real cause, because nothing pointed at the dropped entry ==="
)


class _InspectorHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        if self.path == "/mycss.css":
            body = b"/* part 2/3 of the flag: t3ct1ve_0r_ju5t */"
        elif self.path == "/myjs.js":
            body = b"/* part 3/3 of the flag: _lucky_302945a7} */"
        else:
            body = b"<!-- 1/3 of the flag: picoCTF{tru3_d3 -->"
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


inspector_httpd = socketserver.TCPServer(("127.0.0.1", 0), _InspectorHTTPHandler)
inspector_port = inspector_httpd.server_address[1]
inspector_thread = threading.Thread(target=inspector_httpd.serve_forever, daemon=True)
inspector_thread.start()
try:
    inspector_patterns = "\n".join([
        r"flag:\s*(\S+)\s*-->",
        r"flag:\s*(\S+)\s*\*/",
        r"flag:\s*(\S+)\s*\*/",
    ])
    inspector_result = fetch_and_join_fragments.invoke({
        "base_url": f"http://127.0.0.1:{inspector_port}",
        "paths": ",mycss.css,myjs.js",
        "patterns": inspector_patterns,
        "group": 1,
    })
    print(inspector_result)
    assert "picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky_302945a7}" in inspector_result, (
        f"expected the empty leading path entry to fetch base_url itself as the first fragment, "
        f"got {inspector_result}"
    )
    assert "(base_url root)" in inspector_result, (
        f"expected the empty path entry to be labeled readably in the debug listing, got {inspector_result}"
    )
finally:
    inspector_httpd.shutdown()
    inspector_httpd.server_close()
