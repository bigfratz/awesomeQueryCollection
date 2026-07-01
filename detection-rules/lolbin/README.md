# LOLBin detection rules

KQL detections for living-off-the-land binary (LOLBin) abuse over Microsoft
Defender `DeviceProcessEvents`. Detections key on **argument patterns and
process lineage**, not binary names alone — the signed binaries here run
constantly and legitimately.

## Files

| File | Purpose | Wired to automation? |
|------|---------|----------------------|
| `earlystage/lolbin-earlystage-1-context-low.kql` | **Deploy.** Discovery/context + unusual tooling (merged Info+Low). | Enrichment/ticketing only |
| `earlystage/lolbin-earlystage-2-medium.kql` | **Deploy.** Dual-use techniques + light persistence; needs a second signal to escalate. | Review/medium automation |
| `earlystage/lolbin-earlystage-3-high.kql` | **Deploy.** Execution / evasion / initial-access chains; rare or no benign explanation. | Aggressive automation |
| `lolbin-hunting.kql` | Analyst-driven hunts (rarity/anomaly + network/file correlation, cmd→script, interpreter payloads). | No — human triage |
| `lolbin-severity-tiers.kql` | **Reference.** Fuller 4-tier, all-stages catalogue with per-line MITRE rationale. Includes later-stage detections (LSASS dump, hive save, `vssadmin delete shadows`, psexec) not yet in the early-stage set. | No — reference/backlog |

## The early-stage split (primary deployment)

Three rules scoped to the first few ATT&CK stages (recon / initial access /
execution / light persistence). Conventions shared across all three:

- **Identical global exclusion header**, marked `// === GLOBAL EXCLUSIONS v1 ===`.
  Company-specific values are redacted as `x` — restore before deploying. Bump
  the version number when you change it and keep all three in sync (or move the
  list to a Sentinel Watchlist to avoid duplication).
- **Always-false seed** (`(1 == 2)`) so every detection line starts with `or`
  and can be toggled/removed without breaking the OR chain.
- **No cross-tier overlap** — each command lives in exactly one rule (e.g.
  `wevtutil qe` → context-low, `wevtutil cl` → high).

### Before deploying
1. Restore the redacted `x` values in the header (all three) and the interpreter
   FP list (`has_any ("x")`) in the Medium rule.
2. Confirm `wevtutil qe` matches your telemetry's term form.
3. Sanity-check the `FileName in~` matches for curl/wget and the interpreters
   against a sample window.

## Backlog (later ATT&CK stages)

Deferred from the early-stage set, catalogued in `lolbin-severity-tiers.kql`:
credential access (`rundll32 comsvcs MiniDump`, `procdump -ma lsass`,
`reg save sam/security/system`), impact (`vssadmin delete shadows`), and lateral
movement (`psexec`/`paexec`). Revisit the admin/SYSTEM exclusion when folding
these in — they run elevated, so the current account exclusion would blind them.
