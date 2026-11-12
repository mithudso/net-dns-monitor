# Maintained-source optimization — 2026-11-12

This continues the retained full repository review without a file cap or a
reset of its five-iteration and two-blind-attempt limits. Round 1 reviewed
198 targets. Round 2 reviewed 104 changed hashes and reused 97 matching reports.
The current census has 207 targets, including six further regression modules.
Round 3 reviewed 49 changed/new targets and reused 158 matching reports.

## Per-iteration severity table

| Round | Critical | High | Medium | Low / Nit |
|---|---:|---|---|---|
| 1 | 0 corroborated | 1 owner-deferred incident-pipeline limitation | 113 accepted worker repair rows, plus separately documented repository guard/pin/documentation repairs | Retained below the fix bar |
| 2 | 0 corroborated | Same explicit owner deferral | 55 corroborated repair findings; parent verification also closed the state-save retry within the existing silence finding | Bounded-packet recursion claims remain retracted |
| 3 | 0 corroborated | 1 owner-deferred | 38 corroborated repair findings, including final root/collection follow-through | One Low console byte-count observation retained |

The first-round worker-row total is an accounting boundary, not a reconstructed
claim that every historical cross-file repair was a separate defect. Original
reports and their dispositions remain preserved.

## Findings and behavior

| Pass | Source | Severity | Finding and resulting behavior | Status |
|---|---|---|---|---|
| C1/C2/S3 | app, dns_query, config, domain_learner | Medium | Heartbeat fallback keeps its budget; readings retain completion age; IDNA separators encode correctly; invalid controls and hostname prefixes are refused. | Fixed with synthetic regressions |
| C1/S2/S3 | fleet_client, fleet_keys, fleet_store, fleet_server | Medium | Oversized events cannot block reporting. Failed registry reads cannot authorize mutation. Silence append/state failures retry. Refusal persistence is bounded. | Fixed with fake transports and scratch stores |
| S1/C3 | fleet_protocol | Medium in round 1 | Non-ASCII signatures and nonfinite timestamps are refused as data. | Fixed; bounded-packet recursion reports retracted after runtime probes |
| P2/C1 | failover, router | Medium | A stable state lock protects competing switches. Complete LAN subnets must fit private ranges. | Fixed with injected system calls |
| C1/S2/S5 | headless, forensic_log, settings_window, user_notify, system_log | Medium | Injection and startup cleanup work; episode names do not collide; malformed config and broken diagnostic streams stay safe; grouped entries keep error severity. | Fixed |
| P2/T1 | router_window, tests/conftest.py | Medium | Save UI uses the existing action slot while its synchronous bool API remains. Synthetic defaults precede collection and survive teardown. | Fixed; fresh-process sentinel regression |
| S1/C1/S2 | Service/start/install/router scripts | Medium | Reload failures cannot report stale jobs as success. Swap inputs survive rejection, rollback preserves activation, copies are staged, pending launches retain ownership. | Fixed with extracted, fully faked operations |
| C1/S1/S2/P2 | App Store and static/index development tools | Medium | Linkage/version checks, isolated artifacts, bounded probes, recording ownership, stable descriptors and ordered bounded watcher work preserve their existing contracts. | Fixed with synthetic clients/files |
| C1 | scripts/rotate_workflow_logs.py | Medium | Fenced version examples stay inside their journal entry. | Fixed; guarded journal suite |
| P2 | app incident pipeline | High | Incident work still runs synchronously on the GUI timer. Moving it requires preserving anti-flap ownership, report ordering and UI handoffs. | Owner-deferred; no redesign |
| T2 | Optional Chroma dependency | Exposure not established | Upstream advisories remain. Embedded use and an explicit embedding function do not prove safety. No semantic service or index was activated. | Unresolved upstream/exposure limitation |

## Verify gates

| Gate | Baseline | After repair | Verdict |
|---|---|---|---|
| Pinned Ruff lint/format | Passed before retained census changes | Full-tree lint/format passed after round 2 | Pass |
| Guarded pytest, exact 22 deselections | Historical 2792-node baseline: 2768 passed, seven failed, 17 deselected | Round 2: 3105 passed / 22 held; final: 3171 passed / 22 held, 3193 collected | Pass for exercised subset |
| Static paths/component/count check | Checkpoint CI failed stale census/counts | Refreshed census and exact totals checked locally | Pass |
| Fresh macOS CI | Checkpoint: 3033 passed, two graph cases skipped, then documentation failed | Source-equivalent 911bfc7: 3191 passed, two graph cases skipped; final PR-head checks gate delivery | Source pass |

The local process-tree guard denies outbound traffic, OS-management executables
and writes outside owned worktree/scratch paths. Synthetic factories precede
imports. The 22 held nodes remain 18 UDP integrations and four Foundation PNG
atomic writes. Fresh macOS CI must exercise or account for them. Deselection is
never passing. No real Keychain, repair, daemon, signing, model or semantic
operation is part of this maintenance claim.

### Residual and delivery boundaries

The original divergent checkout remains held. The separate privileged router timeout risk is unverified; fake process survival would assume the platform behavior being questioned. Notification denial remains final under the existing contract. The bounded-packet recursion claim remains retracted by baseline Python 3.13/3.14/3.15 probes. No enterprise registry, dashboard, license grant or SLA was invented.

Fresh source-equivalent [macOS CI](https://github.com/mithudso/net-dns-monitor/actions/runs/43284421759) passed on 911bfc77f3c39b0846f27be93e19c31692708de6: 3191 passed and two headless graph-rasterization cases skipped. Neither skip is in the 22 local-held nodes, so all 18 UDP and four Foundation nodes ran. The final checks and merge state are recorded on [PR41](https://github.com/mithudso/net-dns-monitor/pull/41); only the final passing head may merge. The [bootstrap audit](repo-bootstrap-audit-2026-11-12.md) records applicability and retained operating limits.

## Activated review domains

Python/runtime contracts; HMAC and untrusted UDP; subprocess/filesystem security;
macOS/AppKit callback ownership; CI/dependencies; test quality/concurrency;
architecture/configuration; logging and documentation. Per-file contexts receive
the injection gate and all applicable file passes. Repository M3, T2, T3, T4 and
cross-file M2 remain separate passes.

## Per-file changes

The [source coverage ledger](maintenance-source-coverage-2026-11-12.json) records
final path/hash/review accounting. All 207 maintained targets have complete diagnostics. 176 final hashes match those reports; 31 files contain subsequent corroborated repairs with owned diff review and regression validation. No independent final-hash cleanliness is claimed. The PR diff is the full patch; this report
groups behavior instead of repeating it. Source snapshots and substantive raw
JSONL reports remain in private maintenance evidence.

## Blind re-audit

No blind attempt has been consumed. The canonical contract gates only a CLEAN
exit. The explicit High incident-pipeline deferral and unresolved dependency
exposure prevent an unqualified cleanliness claim. The canonical checker ran separately on each changed file snapshot. The remaining High app limitation produced STABLE-REWRITE at edit ratio 0.0051, below 0.02. The resulting NO_CHANGE exit retains that limitation. No third gate or fabricated CLEAN is allowed.

## Recommendations

Not requested. No advisory feature or migration roadmap was implemented.

## Implemented features

Not requested. Changes repair corroborated behavior and verification defects.

## Summary

Iterations: 3 of 5 applied · 18 pass families with file/repository applicability · standard profile · Known final C/H/M: 0/1/0; Low observations retained · Verify: local subset PASS · Status: NO_CHANGE (canonical stable rewrite); remote delivery evidence is recorded below.

No held-out quality/benchmark set exists for champion–challenger promotion.
Regression tests are not a held-out eval. Empirical model, research and semantic
operations were not authorized or run.

## Snapshot and rollback

Snapshots remain under
~/.claude/skill-consolidation/backups/net-dns-monitor-20261112T104518Z/,
in iteration1-before and iteration2-before. A literal selected-file restore is:

    cp ~/.claude/skill-consolidation/backups/net-dns-monitor-20261112T104518Z/iteration2-before/netdnsmonitor/app.py netdnsmonitor/app.py

Restore only inspected task-owned paths. New regression modules have no previous
file. Remove only their exact owned paths when deliberately rolling back.
After delivery, rollback is a new reviewed change; never reset the default branch
or touch the divergent original checkout.

New regression files have no pre-write counterpart. Literal task-owned removal commands for a deliberate rollback are:

    rm tests/test_maintenance_app_regressions.py
    rm tests/test_maintenance_core_regressions.py
    rm tests/test_maintenance_tooling_regressions.py
    rm tests/test_maintenance_resume_core.py
    rm tests/test_maintenance_resume_fleet.py
    rm tests/test_maintenance_resume_tooling.py
    rm tests/test_maintenance_resume_shell.py
    rm tests/test_maintenance_resume_safety.py
    rm tests/test_maintenance_resume_journal.py

index: static census refreshed (shallow, partial); global prose index n/a outside corpus roots; optional semantic index unchanged (not authorized).
memory-central: current fleet architecture, retired-router safety and the
incident-pipeline deferral consulted; source-anchored regressions and continuation
recorded in shared project knowledge.
