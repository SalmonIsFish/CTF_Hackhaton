from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode

print("=== find_flag_pattern: string containing a flag ===")
print(find_flag_pattern.invoke({"text": "the answer is flag{abc123}, don't lose it"}))

print("\n=== find_flag_pattern: string with no flag ===")
print(find_flag_pattern.invoke({"text": "just some ordinary sentence, nothing to see here"}))

print("\n=== identify_and_decode: known base64 (aGVsbG8gd29ybGQ= -> hello world) ===")
print(identify_and_decode.invoke({"text": "aGVsbG8gd29ybGQ="}))

print("\n=== identify_and_decode: known hex (68656c6c6f -> hello) ===")
print(identify_and_decode.invoke({"text": "68656c6c6f"}))
