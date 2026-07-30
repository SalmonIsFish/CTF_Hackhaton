from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, ToolMessage

from agent.graph import MAX_CONTEXT_MESSAGES, trim_context
from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode
from agent.tools.search_skills import search_skills
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

print("\n=== search_skills: known term ('Wiener', present in ctf-crypto's RSA attack notes) ===")
skills_found = search_skills.invoke({"query": "Wiener"})
print(skills_found)
assert "ctf-crypto" in skills_found, "expected a ctf-crypto file in results"

print("\n=== search_skills: term not present anywhere in installed skills ===")
skills_not_found = search_skills.invoke({"query": "zzz_definitely_not_in_skills_zzz"})
print(skills_not_found)
assert "No matches" in skills_not_found, "expected clean no-match message"

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
