# Registration Examples

These examples show the first two identity setup paths:

| File | Purpose |
|---|---|
| `first_time_setup.py` | Fresh agent creation and registration-state checks. Defaults to mock mode; live mode is opt-in. |
| `reload_existing.py` | Encrypted local key persistence and reload with a passphrase. No backend required. |

Run from the repository root after installing the SDK:

```bash
python examples/registration/first_time_setup.py
python examples/registration/reload_existing.py
```

For live registration, set `AVP_REGISTRATION_LIVE=1`, `AVP_BASE_URL`, and
`AVP_AGENT_PASSPHRASE`. Live mode creates a real backend registration record
for a fresh DID.
