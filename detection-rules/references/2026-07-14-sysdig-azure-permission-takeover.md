# Reference: "No single pane of glass — Anatomy of an Azure permission takeover"

**Source:** Sysdig Threat Research Team (TRT) blog
**Author:** Lydia Graslie, Senior Threat Research Engineer, Sysdig
**Published:** July 14, 2026
**URL:** https://www.sysdig.com/blog/no-single-pane-of-glass-anatomy-of-an-azure-permission-takeover

> This is a structured **digest for engineering reference**, not a verbatim copy —
> it captures the facts the `azure-control-plane/` detection rules are built from,
> with attribution back to the original. Read the source article for the full
> narrative, screenshots, and Sysdig product context. All quotes are short and
> attributed; © Sysdig, Inc.

The `azure-control-plane/` rules in this repo model the kill chain below. Each
rule header points back here.

---

## The incident in one line

An attacker started from a **single leaked service-principal (NHI) client
secret** and, within about an hour of active effort over one morning, took
**dual-plane control** of the tenant: **Global Administrator** over the directory
**and** root-level (**User Access Administrator**) access over every resource,
plus persistence across dozens of identities and the keys to the telemetry
pipeline. No malware, no exploits, no zero-days — only legitimate Azure APIs.

The leaked secret was exposed ~2 weeks, replayed from rotating anonymization
infrastructure (commercial VPNs, Tor exits, small hosts across US, DE, SE, HK,
NL). Most consumers only did recon; one session escalated.

---

## Observed timeline (all UTC, every operation returned success)

### Phase 1 — Directory escalation (03:27–03:50)
- **03:27** — First valid sign-in as the service principal (NL hosting ASN).
- **03:28** — Add member to role (self).
- **03:29:57** — **Add member to role outside of PIM (permanent) → Global
  Administrator**, at directory root. ~2.5 min from first login to owning the
  directory. Possible because the SP already held a Graph permission
  (`RoleManagement.ReadWrite.Directory`) allowing exactly this.
- **03:29–03:50** — Attacker-controlled client secrets added to **26 application
  registrations** (persistence).

### Phase 2 — Resource-plane escalation + key harvest (04:32–04:37)
- **04:32:37** — `Microsoft.Authorization/elevateAccess/action` → **User Access
  Administrator at root** over Azure resources.
- **04:32:44** — `roleAssignments/write` at subscription scope (Owner-class, self).
- **04:33** — `storageAccounts/listKeys` on **four** storage accounts.
- **04:33:37–38** — `listKeys` on `rootmanagesharedaccesskey` for **both Event Hub
  namespaces** — the ones carrying the tenant's own audit telemetry.
- **04:34** — `Microsoft.KeyVault/vaults/accessPolicies/write` (self-add) on
  **three** Key Vaults, followed by `roleAssignments/write` on the same vaults;
  data-plane secret reads followed.

### Phase 3 — Persistence and return (through ~09:57)
- Continued access through the morning; one planted secret re-used from a
  different egress to confirm the backdoor, then went quiet.

---

## The five permission planes that never meet

| # | Plane | What it is | Log source |
|---|-------|-----------|-----------|
| 1 | **Entra directory roles** | GA, Privileged Role Admin, directory roles | Entra audit log (`AuditLogs`) |
| 2 | **Azure RBAC** | Owner/Contributor/User Access Admin on subs/RGs/resources | Azure activity log (`AzureActivity`) |
| 3 | **Key Vault** | Resource-local **access policies** (parallel to RBAC) | resource diagnostics (`AzureDiagnostics` / `AZKVAuditLogs`) |
| 4 | **Bearer keys / SAS** | Identity-less shared keys & SAS — "if you hold it, you're authorized" | mint is in `AzureActivity` (`listKeys`); *use* needs per-resource data-plane diagnostics (off by default) |
| 5 | **Graph API application permissions** | Admin-consented app permissions (`RoleManagement.ReadWrite.Directory`, etc.) | app config; `MicrosoftGraphActivityLogs`; consent/app-role events in `AuditLogs` |

The planes **do not share a join key** — an SP object-id, an RBAC scope path, a
Key Vault access-policy entry, and a storage key have almost nothing to correlate
on. Defenders rarely look at more than one at a time, so an attacker can hop
between them uncaught.

### The two cruelest details
- **`elevateAccess` is logged in the *opposite* plane from the one it affects.**
  A GA calling `Microsoft.Authorization/elevateAccess/action` instantly gets User
  Access Administrator at root `/` over every subscription — the cleanest
  directory→resource bridge. It is **not** a normal role assignment (won't show in
  the RBAC blade) and is **not** exported to `AzureActivity`; it lands in the
  **Entra audit log** under role-management. "A move that bridges two permission
  systems is visible in neither's normal view."
- **Bearer keys are a permanent blind spot.** `listKeys` mints an identity-less
  secret; every later use is anonymous, and data-plane use is unlogged unless
  per-resource diagnostics were on *before* exposure (off by default for storage,
  Event Hubs, most types). "Miss that one control-plane event and the access it
  created is both identity-less and invisible, permanently: a double blind spot."

### NHI sprawl
Each of the 26 backdoored app registrations is an independent NHI with its own
credential list. No single Azure view lists "every credential on every app
registration" — you enumerate `passwordCredentials` app by app, or reconstruct
from the audit log. Per Sysdig's 2026 report: NHIs are ~97% of managed identities,
hold the longest-lived secrets, and are the worst-instrumented part of the estate;
~38% of Azure service principals are "risky."

---

## Where to reconstruct "who/what has access" (the five queries)

- Entra directory roles → **`AuditLogs`**
- Azure RBAC + key harvest → **`AzureActivity`**
- Key Vault data-plane access → **`AzureDiagnostics`**
- NHI credential persistence → enumerate app registrations (or reconstruct from `AuditLogs`)
- Graph API application permissions → each app's API-permissions config (or the
  `Add app role assignment` / consent events back in `AuditLogs`)
- …and **`elevateAccess`** sits in the Entra table despite being a resource-plane grant.

---

## Recommendations (source "What to do about it")

1. **Inventory across all five planes as one estate** — Entra roles + RBAC alone
   miss resource-local policies, bearer keys, and Graph permissions.
2. **Treat NHIs as first-class identities, including their Graph permissions** —
   inventory every app's secrets/certs, alert on credential additions, age out
   long-lived secrets. Keep tier-0 Graph permissions
   (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`,
   `Application.ReadWrite.All`, …) on a **short, deliberately-maintained
   allow-list**; the admin-consent grant of one is itself high-signal.
3. **Watch the cross-plane bridges** (high-signal, low-noise): `elevateAccess`
   (alert on every occurrence); privileged directory-role grants (esp. to an SP);
   Key Vault `accessPolicies/write` + `roleAssignments/write`; `listKeys` / SAS
   issuance (your only chance to see the key).
4. **Starve the identity-less plane** — disable shared-key access on storage;
   prefer Entra/RBAC data-plane auth.
5. **Turn logging on before exposure** — route Activity Log + Entra audit/sign-in
   to a workspace; enable `MicrosoftGraphActivityLogs` (P1, off by default); enable
   data-plane diagnostics on Storage / Event Hubs / Key Vault.
6. **Unify telemetry, then correlate by IDENTITY, not by plane** — stitch
   `AuditLogs`, `AzureActivity`, resource diagnostics, and Graph activity into a
   single identity-centric timeline so the escalation reads as one story.

---

## Sysdig detections mapped to the kill chain

| Attacker move | Plane | Sysdig Falco rule |
|---|---|---|
| SP self-grants Global Administrator | Entra directory | Entra Add Member to Administrative Role |
| `elevateAccess` → root User Access Administrator | Entra↔RBAC bridge | Entra Elevate Access to User Access Administrator at Root † |
| `roleAssignments/write` at subscription scope | Azure RBAC | Azure Create/Update a Role Assignment |
| `storageAccounts/listKeys` ×4 | bearer-key mint | Azure Read the Access Keys for a Storage Account |
| Event Hub `listKeys` | bearer-key mint | Azure Read the Keys for an Event Hub Namespace † |
| Key Vault `accessPolicies/write` self-grant | resource-local policy | Azure Modify a Key Vault Access Policy † |
| Function App `host/listKeys` | bearer-key mint | Azure Read the Host Keys for a Function App † |

† Contributed by the TRT to Sysdig's open-source Falco rules in response to this
incident (the bridge, the resource-local self-grant, and the two bearer-key mints
that had no dedicated rule). The highest-value entry is `elevateAccess`: it hides
in the Entra plane while the key harvest lives in the Activity plane, so watching
both planes as one identity timeline collapses a two-plane attack into one
alertable chain.

---

## How this maps to the rules in `../azure-control-plane/`

| Source finding | Rule file / block |
|---|---|
| `elevateAccess` bridge; SP-granted privileged directory role | `t4-azure-permission-bridges-isolate.kql` Block 1 |
| `listKeys` bearer-key mints (storage / Event Hub / Function App / Service Bus); Key Vault `accessPolicies/write` | `t4-azure-permission-bridges-isolate.kql` Block 2 |
| Cross-plane chain, correlated by identity | `t4-azure-permission-bridges-isolate.kql` Block 3 |
| Tier-0 Graph application-permission grant / admin consent | `t3-azure-nhi-persistence-respond.kql` Block 1 |
| Credential added to app/SP; the 26-app credential fan-out | `t3-azure-nhi-persistence-respond.kql` Blocks 2–3 |
| Graph-plane app tampering (when `MicrosoftGraphActivityLogs` is on) | `t3-azure-nhi-persistence-respond.kql` Block 4 |
| Identity normalization across all planes | `../azure-control-plane/shared-functions.kql` |

**Lesson zero from the incident:** the investigation survived only because the
control-plane logs were captured to **immutable, off-tenant storage** the
attacker (who held the Event Hub root keys) couldn't reach. Evidence durability
must be independent of the plane the attacker controls.
