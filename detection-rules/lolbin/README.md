# LOLBin detection rules

KQL detections for living-off-the-land binary (LOLBin) abuse over Microsoft
Defender `DeviceProcessEvents`. Detections key on **argument patterns and
process lineage**, not binary names alone — the signed binaries here run
constantly and legitimately.

## Files

| File | Purpose | Automation action |
|------|---------|-------------------|
| `lolbin-t1-signals-watch.kql` | **Deploy.** Discovery/context + unusual tooling — lowest-confidence signals. | Watch (enrichment/ticketing) |
| `lolbin-t2-suspicious-review.kql` | **Deploy.** Dual-use techniques + light persistence; needs a second signal to escalate. | Review (analyst) |
| `lolbin-t3-malicious-respond.kql` | **Deploy.** Execution / evasion / initial-access chains; rare or no benign explanation. | Respond (aggressive) |
| `../t4-malicious-privileged-account-isolate.kql` | **Staging.** Cross-family critical tier (cred-access / impact / lateral movement) — no longer LOLBin-only, so it lives one level up. MINIMAL header (no admin exclusion). | Isolate (harshest) |
| `lolbin-hunting.kql` | Analyst-driven hunts (rarity/anomaly + network/file correlation, cmd→script, interpreter payloads). | None — human triage |
| `lolbin-severity-tiers.kql` | **Reference.** Fuller 4-tier, all-stages catalogue with per-line MITRE rationale. Includes later-stage detections (LSASS dump, hive save, `vssadmin delete shadows`, psexec) not yet in the deployed set. | None — reference/backlog |

## Naming convention

`LOLBin-T{n}-{class}-{action}` — the `T{n}` prefix is the automation routing
key (T1→watch, T2→review, T3→respond); `{class}` and `{action}` are for humans.
The T4 critical tier outgrew the LOLBin family — it now covers high-confidence
malicious privileged activity across sources (native, Sysinternals-adjacent, DC
tooling), so it lives one level up as `../t4-malicious-privileged-account-isolate.kql`
(currently in staging). It uses the separate **MINIMAL** exclusion header — same
as GLOBAL minus the account exclusion — because its detections run elevated by
design. "By privileged account" = does not *exclude* privileged accounts (still
fires on any account); it is not scoped admin-only.

## The three deployed rules

Scoped to the first few ATT&CK stages (recon / initial access / execution /
light persistence). Conventions shared across all three:

- **Identical global exclusion header**, marked `// === GLOBAL EXCLUSIONS v1 ===`.
  Company-specific values are anonymized as `x` / `<svc_account_n>` placeholders
  — restore before deploying. Bump the version number when you change it and keep
  all three in sync (or move the list to a Sentinel Watchlist to avoid duplication).
- **Always-false seed** (`(1 == 2)`) so every detection line starts with `or`
  and can be toggled/removed without breaking the OR chain.
- **No cross-tier overlap** — each command lives in exactly one rule (e.g.
  `wevtutil qe` → T1, `wevtutil cl` → T3).

### Before deploying
1. Restore the anonymized values in the header (all three) and the interpreter
   FP list (`has_any ("x")`) in the T2 rule.
2. Confirm `wevtutil qe` matches your telemetry's term form.
3. Sanity-check the `FileName in~` matches for curl/wget and the interpreters
   against a sample window.

## Later ATT&CK stages → T4 (staging)

The later-stage detections (credential access, destructive impact, lateral
movement) now live in `lolbin-t4-critical-privileged-isolate.kql`, which drops
the admin/SYSTEM exclusion so it can see the elevated context these run in.
`lolbin-severity-tiers.kql` remains the fuller catalogue/reference.

Before graduating T4 from staging: dedupe against T3 — `procdump -ma lsass` and
`wevtutil cl` appear in both (they only overlap in user context today, since T3
excludes admin/SYSTEM). See the note at the bottom of the T4 file.
