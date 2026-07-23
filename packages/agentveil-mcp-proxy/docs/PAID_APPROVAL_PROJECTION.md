# Paid Approval Center projection (public MCP Proxy)

Status: public consumption of private B2
`paid_approval_center_projection`. Boundary: MCP Proxy Runtime Gate client +
Approval Center rendering only. No private repo imports.

## Wire shape (trusted Runtime Gate payload)

Optional field inside the **verified / signed DecisionReceipt body**
(not an unsigned top-level HTTP response wrapper):

```json
{
  "schema_version": "paid_approval_center_projection/1",
  "projection_kind": "paid_active",
  "provider_status": "active",
  "plan_family": "builder",
  "private_provider_enabled": true,
  "core_fallback_active": false,
  "decision": "allow",
  "reason_code": "paid_provider_active",
  "selection_reason": "deterministic_precedence",
  "summary": "Bounded review summary",
  "capability_labels": ["Tools call routing"],
  "activation_source": "public_activation_install",
  "paid_policy_tightened": false
}
```

Public SDK normalizes this field before rendering. Unknown keys, bad tokens,
privacy markers, or inconsistent active/fallback flags are omitted.

## Approval Center behavior

| Projection | Card behavior |
|---|---|
| `paid_active` + `private_provider_enabled=true` | Show bounded “Paid policy review” section |
| `core_fallback` | No paid-active panel |
| missing / malformed | Ordinary card unchanged |
| Free/Core (no field) | Ordinary card unchanged |

Approve/Deny controls are unchanged. Terminal/expired pages do not invent paid
context.

## Privacy

The public card projection omits:

- license keys / entitlement or install tokens
- backend URLs / artifact IDs
- host paths / raw payloads / rule graphs / customer IDs

## Storage

When valid, the bounded projection is stored under
`action_gate_metadata.paid_approval_center_projection` for local and managed
Approval Center cards.
