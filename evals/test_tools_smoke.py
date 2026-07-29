from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode
from agent.tools.search_vault import search_vault

print("=== find_flag_pattern: string containing a flag ===")
print(find_flag_pattern.invoke({"text": "the answer is flag{abc123}, don't lose it"}))

print("\n=== find_flag_pattern: string with no flag ===")
print(find_flag_pattern.invoke({"text": "just some ordinary sentence, nothing to see here"}))

print("\n=== identify_and_decode: known base64 (aGVsbG8gd29ybGQ= -> hello world) ===")
print(identify_and_decode.invoke({"text": "aGVsbG8gd29ybGQ="}))

print("\n=== identify_and_decode: known hex (68656c6c6f -> hello) ===")
print(identify_and_decode.invoke({"text": "68656c6c6f"}))

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
