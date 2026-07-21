# Detection rules (KQL)

KQL detections, organized into families by **telemetry domain**. The two families
read entirely different tables and share no join key, so each is self-contained
with its own `shared-functions.kql`.

| Folder | Domain | Tables | Focus |
|--------|--------|--------|-------|
| [`endpoint/`](endpoint/) | Endpoint (Microsoft Defender) | `DeviceProcessEvents` + other `Device*` | Living-off-the-land binary/script (LOLBAS) abuse and later-stage tactics (collection / C2 / exfiltration / defence impairment), tiered T1–T4 and keyed on argument patterns + process lineage. Correlates by `DeviceId`. |
| [`azure-control-plane/`](azure-control-plane/) | Azure / Entra control plane | `AuditLogs`, `AzureActivity`, `AzureDiagnostics`, `MicrosoftGraphActivityLogs` | Cross-plane permission-takeover kill chain (directory-role grants, `elevateAccess`, bearer-key mints, Key Vault self-grants, NHI credential persistence, Graph app-permission grants). Correlates by **principal object-id**. |
| [`references/`](references/) | — | — | Source material the rules are built from (incident write-ups, threat research), with attribution. |

## Shared conventions across both families

- **`shared-functions.kql` first.** Each family's rules depend on its saved
  functions (exclusions, and — for Azure — identity normalization). Deploy that
  file into the workspace before the rules.
- **Tier prefix = automation routing key.** `t1-`→watch, `t2-`→review,
  `t3-`→respond, `t4-`→isolate.
- **GLOBAL vs MINIMAL** exclusion via an `excludeAdmin` boolean passed to the
  shared functions (`true` = drop known-noise identities; `false` = keep every
  identity, for techniques that run privileged by design).
- **Always-false seed** (`(1 == 2)`) in flat static rules so every detection line
  starts with `or` and toggles independently.
- **One analytics rule per block**; behavior blocks correlate multi-event and
  `summarize` away per-row ids (re-join per platform as noted in each family).

See each folder's `README.md` for the file-by-file breakdown and
before-you-deploy checklist.
