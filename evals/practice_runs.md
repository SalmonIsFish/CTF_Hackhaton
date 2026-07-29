# Practice Runs — Model Comparison

Results from running the 4 `agent/graph.py` test cases (echo, echo+early-exit-on-flag,
multi-step decode, vault lookup) against different providers/models, with the
`SYSTEM_PROMPT` (vault-search nudge) in place.

| Model | Provider | Case 1 (echo) | Case 2 (flag early exit) | Case 3 (multi-step decode) | Case 4 (vault lookup) | Free-tier quota | Notes |
|---|---|---|---|---|---|---|---|
| `gemini-3.5-flash-lite` | Google | PASS | PASS | PASS | PASS | 500 requests/day | **Recommended default.** Only model to pass all 4 cases cleanly, including multi-step tool chaining. Now the `model_router.py` default for `"google"`. |
| `openai/gpt-oss-120b` | Groq | PASS | PASS | FAIL | PASS | — | Weak multi-step chaining: after decoding base64 to hex, calls `echo` redundantly instead of calling `identify_and_decode` again, then states the final flag as prose instead of via a tool call — so `observe()` never sees it in a `ToolMessage` and the flag is never captured. |
| `llama-3.3-70b-versatile` | Groq | — | — | — | — | — | **Unusable.** Reliably emits malformed tool-call syntax (`<function=search_vault{"query": "..."}</function>` instead of a proper JSON tool call), which Groq rejects outright with `400 tool_use_failed`. Reproduced twice, not transient. |

## Models ruled out — don't retry these

- **`gemini-2.5-flash`** — retired for this API key. Returns `404 NOT_FOUND`
  ("no longer available to new users") at generation time, even though it still
  appears in `client.models.list()`.
- **`gemini-2.0-flash`** — `limit: 0` free-tier entitlement on this key. Not a quota
  *exhaustion*, a quota of zero — this key was never entitled to any free requests
  for this model, so waiting won't help.
- **`gemini-flash-latest`** (resolves to `gemini-3.6-flash`) — works, but only has a
  20/day free-tier quota, which this key exhausted mid-testing. Superseded by
  `gemini-3.5-flash-lite` as the default.

## How to check available models / quota for a key

```bash
python -c "
from dotenv import load_dotenv
load_dotenv()
import os
from google import genai
client = genai.Client(api_key=os.environ['GOOGLE_API_KEY'])
for m in client.models.list():
    if 'generateContent' in (m.supported_actions or []):
        print(m.name, '|', m.display_name)
"
```

Quota limits only show up when you actually hit them (in the `429` error body), not
from the listing call above.
