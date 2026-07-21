# Azure control-plane detection rules (KQL)

**Domain: Azure/Entra control-plane telemetry** — `AuditLogs`, `AzureActivity`,
`AzureDiagnostics` (Key Vault), `MicrosoftGraphActivityLogs`. One of two rule
families in this repo (see [`../README.md`](../README.md)); the sibling
`endpoint/` family reads Defender `Device*` tables. The two share no join key
(endpoint `DeviceId` vs. an Entra/Azure **principal object-id**), so each keeps
its own `shared-functions.kql`.

These rules model the Sysdig TRT **"Azure permission takeover"** kill chain:
one leaked service-principal secret → Global Administrator → root User Access
Administrator → storage/Event Hub key harvest → Key Vault self-grant →
persistence on 26 app registrations. Full digest and attribution in
[`../references/2026-07-14-sysdig-azure-permission-takeover.md`](../references/2026-07-14-sysdig-azure-permission-takeover.md).

## The core idea — correlate by identity, not by plane

Azure's five permission planes never meet and don't share identifiers. A per-plane
single-event rule sees one slice; the value is **stitching every plane onto one
`Principal` timeline** so an escalation that hops planes reads as one chain. That
normalization is the whole job of `shared-functions.kql` here, and the reason
`t4-…-Block 3` (the cross-plane correlation) exists.

## Files

| File | Purpose | Automation action |
|------|---------|-------------------|
| `shared-functions.kql` | **Deploy first.** `FilteredAuditLogs` / `FilteredAzureActivity` / `FilteredKeyVaultDiag` / `FilteredGraphActivity` — each applies the shared service-principal allow-list **and** projects the normalized `Principal` (object-id) column every rule joins on. | None — infrastructure |
| `t4-azure-permission-bridges-isolate.kql` | **Staging.** The cross-plane **bridges** (isolate tier). Block 1 Entra bridges (`elevateAccess`, SP-granted privileged role); Block 2 bearer-key mints (`listKeys`) + Key Vault access-policy self-grant; Block 3 the identity-keyed **cross-plane chain**. MINIMAL header. | Isolate |
| `t3-azure-nhi-persistence-respond.kql` | **Staging.** NHI persistence + the Graph-plane grant that enables takeover. Block 1 tier-0 Graph permission / consent; Block 2 credential-add to app/SP; Block 3 credential-add **fan-out** (the 26-app signature); Block 4 Graph-activity view. GLOBAL header. | Respond |

## Conventions (shared with the endpoint family)

- **Shared exclusions + identity normalization via saved functions** — deploy
  `shared-functions.kql` first; set the `KnownAutomationPrincipals` allow-list in
  that one place.
- **GLOBAL vs MINIMAL** via the `excludeAdmin` boolean. The T4 bridges pass
  `false` (MINIMAL — keep every principal; these run elevated by design). The T3
  persistence rules pass `true` (GLOBAL — app-lifecycle automation is the benign
  source and belongs on the allow-list). **Never** allow-list a human-admin
  identity.
- **Always-false seed** (`(1 == 2)`) in the flat static blocks so every line
  starts with `or` and toggles freely.
- **One analytics rule per block** — files are delimited by `// ====` headers;
  deploy each block as its own Sentinel scheduled rule. Behavior blocks
  `summarize` away per-row ids; map the incident entity on `Principal`.
- **Tier prefix is the routing key** — `t3-` → respond, `t4-` → isolate. No
  `LOLBAS` segment (different tactic domain; see the endpoint README naming note).

## Before deploying

0. **Deploy `shared-functions.kql` first** and set `KnownAutomationPrincipals`
   (object-ids/appIds of vetted IaC/CI/CD/backup service principals — keep it
   short). Empty list = nothing excluded (safe default).
1. **Confirm the `elevateAccess` term** in `t4-…` Block 1 against your own
   telemetry — its exact `OperationName`/table varies by tenant routing (the
   report places it in `AuditLogs`, not `AzureActivity`). Block 3 catches it via
   the union regardless.
2. **Turn the logs on** — none of this is queryable/alertable by default:
   - Route Activity Log + Entra audit/sign-in logs to the workspace (sign-in
     needs Entra P1). This is where `elevateAccess`, role grants, and `listKeys`
     live.
   - Enable `MicrosoftGraphActivityLogs` (tenant diagnostic, P1, **off by
     default**) — required for `t3-…` Block 4. Blocks 1–3 (AuditLogs) are the
     durable fallback until it flows.
   - Enable data-plane diagnostics on Storage / Event Hubs / Key Vault to light up
     `FilteredKeyVaultDiag` and any future data-plane rule.
3. **Tune the behavior thresholds** — `t4-…` Block 3 window (2h) and the `t3-…`
   fan-out threshold (≥5 apps/1h) are staging starts. Exclude benign
   secret-rotation jobs by adding their SP to `KnownAutomationPrincipals`, not by
   widening the step/verb lists.

## Known gaps / backlog

- **`roleAssignments/write` on its own** is intentionally not a standalone isolate
  line (too common in IaC) — it earns severity only inside the Block 3 chain. Add
  a root-scope (`/`) T3 respond variant if the chain proves too tight.
- **Key Vault data-plane confirmation** (`SecretGet`/`KeyGet` after an
  access-policy self-grant) via `FilteredKeyVaultDiag` — wire into a Block-3
  variant once you've confirmed those logs actually flow.
- **Byte-volume exfil** of drained Event Hub / storage data is not expressible
  from control-plane logs — the `listKeys` mint is the tractable anchor. Complement
  with resource data-plane diagnostics where enabled.
