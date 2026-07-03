# LOLBAS detection rules

KQL detections for living-off-the-land binary/script (LOLBAS) abuse over
Microsoft Defender `DeviceProcessEvents`. Detections key on **argument patterns
and process lineage**, not binary names alone — the signed binaries here run
constantly and legitimately.

## Files

| File | Purpose | Automation action |
|------|---------|-------------------|
| `t1-lolbas-signals-watch.kql` | **Deploy.** Discovery/context + unusual tooling — lowest-confidence signals. | Watch (enrichment/ticketing) |
| `t2-lolbas-suspicious-review.kql` | **Deploy.** Dual-use techniques + light persistence; needs a second signal to escalate. | Review (analyst) |
| `t3-lolbas-malicious-respond.kql` | **Deploy.** Execution / evasion / initial-access chains; rare or no benign explanation. | Respond (aggressive) |
| `../t4-lolbas-sysinternals-privileged-context-isolate.kql` | **Staging.** Cross-family critical tier (cred-access / impact / lateral movement) spanning LOLBAS, Sysinternals, and DC tooling. Lives one level up. MINIMAL header (no admin exclusion). | Isolate (harshest) |
| `t3-lolbas-behavior-chains-respond.kql` | **Staging.** Behavior-based T3: confirmed download chain (process→network→file), discovery burst, contextual persistence escalation. GLOBAL header. | Respond (aggressive) |
| `../t4-defense-impairment-privileged-context-isolate.kql` | **Staging.** Cross-family defence-impairment tier (T1562) — **not LOLBAS** (see naming note): Defender disable via cmdline, kill/stop named security tooling, IFEO Debugger, IIS-log/WAF disable, WDigest downgrade. MINIMAL header. Lives one level up. | Isolate (harshest) |
| `../t4-lolbas-behavior-chains-privileged-context-isolate.kql` | **Staging.** Behavior-based T4: anti-recovery chain, tool-agnostic LSASS dump, lateral-movement fan-out, defence-impairment burst. MINIMAL header. Lives one level up. | Isolate (harshest) |
| `lolbin-hunting.kql` | Analyst-driven hunts (rarity/anomaly + network/file correlation, cmd→script, interpreter payloads). | None — human triage |
| `lolbin-severity-tiers.kql` | **Reference.** Fuller 4-tier, all-stages catalogue with per-line MITRE rationale. Includes later-stage detections (LSASS dump, hive save, `vssadmin delete shadows`, psexec). | None — reference/backlog |

## Naming convention

`T{n}-LOLBAS-{class}-{action}` — the `T{n}` prefix is the automation routing key
(T1→watch, T2→review, T3→respond, T4→isolate); `{class}` and `{action}` are for
humans. T4 additionally names its scope (`Sysinternals-privileged-context`)
because it spans beyond LOLBAS and drops the admin exclusion the others use.

**On the `LOLBAS` segment:** it is loose house-style, not a strict claim. The
T1-T3 tiers are genuinely LOLBAS (signed binaries abused for an *unintended*
purpose — proxy execution, download, app-control bypass). The T4 tier already
carries non-LOLBAS classes (Sysinternals, DC tooling). The defence-impairment
file drops the `LOLBAS` segment entirely (`t4-defense-impairment-...`) because
T1562 "Impair Defenses" is a *different tactic*: built-in admin tools used for
their *intended* function against security controls, not signed-binary abuse.
New non-LOLBAS classes should follow suit and omit the segment.

The T4 critical tier covers high-confidence malicious privileged activity across
sources (LOLBAS, Sysinternals-adjacent, DC tooling), so it lives one level up as
`../t4-lolbas-sysinternals-privileged-context-isolate.kql` (currently in staging).
It uses the separate **MINIMAL** exclusion header — same as GLOBAL minus the
account exclusion — because its detections run elevated by design. "Privileged
context" = does not *exclude* privileged accounts (still fires on any account);
it is not scoped admin-only.

## The three deployed rules

Scoped to the first few ATT&CK stages (recon / initial access / execution /
light persistence). Conventions shared across all three:

- **Identical global exclusion header**, marked `// === GLOBAL EXCLUSIONS v1 ===`.
  Bump the version number when you change it and keep all three in sync (or move
  the list to a Sentinel Watchlist to avoid duplication).
- **Always-false seed** (`(1 == 2)`) so every detection line starts with `or`
  and can be toggled/removed without breaking the OR chain.
- **No cross-tier overlap** — each command lives in exactly one rule (e.g.
  `wevtutil qe` → T1, `wevtutil cl` → T3).

### Before deploying
1. Set the `<svc_account_n>` account placeholders in the header (all three) and
   the interpreter FP list (`has_any ("x")`) in the T2 rule.
2. Confirm `wevtutil qe` matches your telemetry's term form.
3. Sanity-check the `FileName in~` matches for curl/wget and the interpreters
   against a sample window.

## Behavior-based rules (staging)

The static tiers key on what a single command line **looks like**; the two
behavior files key on what the activity **does** — multi-event correlation
(process→network→file), technique chaining in a time window, contextual
escalation, and fan-out. They are the productionized descendants of the
hunting queries.

Conventions specific to behavior rules:

- **Overlap is by design, ownership is not.** The "no cross-tier overlap"
  rule applies to single-command ownership; behavior rules deliberately reuse
  commands owned by other tiers because they fire on the *combination* (a
  discovery burst is made of T1-owned commands — that's the point). What must
  be decided before go-live is incident **attribution**: route the behavior
  rule as incident owner (it carries the most context), static hits as
  enrichment.
- **Multiple blocks per file, one analytics rule per block** when deploying.
- **Tumbling `bin()` windows** in the aggregation blocks — a chain straddling
  a boundary can split below threshold; validate with simulation and move to
  sliding windows if misses show up.
- Written for Sentinel scheduled rules; the summarize/join blocks drop the
  `Timestamp`/`ReportId`/`DeviceId` triple MDE custom detections require —
  re-join `arg_max(Timestamp, ReportId)` per group for MDE CDs.

## Later ATT&CK stages → T4 (staging)

The later-stage detections (credential access, destructive impact, lateral
movement) live in `../t4-lolbas-sysinternals-privileged-context-isolate.kql`,
which drops the admin/SYSTEM exclusion so it can see the elevated context these
run in. `lolbin-severity-tiers.kql` remains the fuller catalogue/reference.

Before graduating T4 from staging: dedupe against T3 — `wevtutil cl` appears in
both (they overlap only in user context today, since T3 excludes admin/SYSTEM;
both tiers auto-isolate, so it's a dedup/escalation-attribution concern, not an
action conflict). See the notes at the bottom of the T4 file.

### Defence impairment (T1562) — new T4 class

`../t4-defense-impairment-privileged-context-isolate.kql` adds a
defence-impairment class alongside the cred-access/impact/lateral T4 file:
Defender disable via command line (`Set-MpPreference`, WMIC exclusions), killing
or stopping named security/logging services (`taskkill`/`sc`/`net`/`wmic` scoped
to product binaries), IFEO `Debugger` hijack, IIS-log/WAF disable via `appcmd`,
and the WDigest `UseLogonCredential=1` downgrade. The behaviour file adds the
matching **defence-impairment burst** rule (3+ distinct impairment techniques in
30 min). Both use the MINIMAL header — these run elevated by design, so admin
exclusion would blind them.

Overlap to settle before go-live: the **registry-write** Defender tamper
(`DeviceRegistryEvents`, the `DisableAntiSpyware`/`DisableRealtimeMonitoring`
policy keys) stays with the existing Sigma-derived registry rule; the new lines
deliberately cover only the **process-command-line** angle that rule cannot see
(`Set-MpPreference` is a WMI call, not always a Defender policy-key write). Same
isolate action either way — route one as incident owner, the other as
enrichment.

**Folded-in hunts.** The standalone Bit9 **Parity** tamper hunt
(`sc`/`net`/`net1`/`powershell`/`cmd` + `stop|disable|delete|uninstall` against
the Parity agent) is absorbed into the service-control-tamper clause. That clause
is keyed on **`FileName`** (not `has "sc.exe"`) so it catches `sc stop parity`
written without the `.exe`, plus PowerShell `Stop-Service`/`Remove-Service`
wrappers — strictly stronger than the origin hunt — and generalises it across the
full product set. The confirmed agent binary is `parity.exe`; the service clause
matches the bare token `parity` (whole-token `has`, so it covers both the
`sc stop parity` service name and any `parity.exe` reference), while the
`taskkill` line matches the `parity.exe` image name. Retire the standalone hunt
(or keep it as the hunt-tier sibling) once this graduates.
