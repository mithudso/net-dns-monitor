# macOS networking review and optimizer run — 2026-10-04

Version: 1. Delta: 1. Baseline: b8672f1. Branch: fix/macos-networking-audit. Tracking: TASK-379.

Completed the scoped code review, code-deep-optimizer v1.7.0 remediation and repo-bootstrapper v5.4.0 desktop pass. The first audit used five grouped reviewer bundles across the four-slot runtime, rather than a separate agent for each source file. This is a disclosed orchestration deviation from the repo-mode skill. All five groups were collected before code writes. The review prioritized networking, safety boundaries, AppKit workers and tooling. It is not a line-by-line review of every tracked file.

## Severity and convergence

| State | Critical | High | Medium | Low/Nit |
|---|---:|---:|---:|---|
| Initial audit | 0 | 3 | 25 | Not enumerated; subjective polish skipped |
| Iteration 1 / independent dissent | 0 | 0 | 6 | Same |
| Iteration 2 / final bounded state | 0 | 0 | 3 | Same |

Counts include the three existing architectural residuals below. The 25 initial actionable rows and three later runtime rows are deduplicated. The clean pinned environment exposed the Objective-C class defect; independent review also corroborated it and found two failback defects. Twenty-eight actionable findings were fixed. CONVERGED means the actionable set is closed; it does not mean the repository has no remaining Medium concerns.

## Findings and fixes

| Pass | Evidence path / symbol | Severity | Finding | Fix | Status |
|---|---|---|---|---|---|
| C1/C2/C3 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/dns_query.py:98 | Medium | F01: NOERROR without a usable answer was called resolved | Validate header, matching question, bounded compression and CNAME-to-A answers; truncation is unknown. | Fixed; focused or suite verification |
| C1/S4 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/repair_executor.py:215 | Medium | F02: Default-route evidence omitted IPv6 | Collect and label both route tables; preserve partial failures. | Fixed; focused or suite verification |
| C1/S4 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/interface_probe.py:52 | Medium | F03: Bound sockets guessed family from literal syntax | Try OS-returned numeric candidates with family-specific binding and one sliced deadline. | Fixed; focused or suite verification |
| C1/S3 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/router.py:93 | Medium | F04: DHCP pools could lease router/network/broadcast addresses | Reject reserved endpoints and pools containing the router address. | Fixed; focused or suite verification |
| C2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/peers.py:134 | Medium | F05: Fresh unknown observations retained old healthy booleans | Replace current unavailable health with None. | Fixed; focused or suite verification |
| S1 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/notifications.py:116 | High | F06: Rejected Slack bodies could echo webhook credentials | Discard untrusted body from errors; regression verifies redaction. | Fixed; focused or suite verification |
| S2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/prober.py:60 | High | F07: Worker encoding errors became apparent DNS failures | Carry unexpected worker exceptions back to the guarded caller. | Fixed; focused or suite verification |
| S4 | /Users/mitch/dev/net-dns-monitor/router/scripts/install_persistent_nat.sh:62 | High | F08: Forced install produced a daemon whose helper refused to run | Persist the explicit override in the daemon; default retirement refusal stays. | Fixed; focused or suite verification |
| S5 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/failover.py:289 | Medium | F09: Failed state persistence was silent | Log exception class and in-memory-only limitation, without state/error contents. | Fixed; focused or suite verification |
| P1/P2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/app.py:640 | Medium | F10: Heartbeat targets each received a full timeout | Share and slice one deadline; subprocess uses the exact fractional ceiling. | Fixed; focused or suite verification |
| P1/P2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/throughput.py:307 | Medium | F11: Lookup budget was additive and successful cache initialization raced | Deduct lookup/lock time; serialize first successful lookup; failed lookups retry later. | Fixed; focused or suite verification |
| P2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/throughput.py:344 | Medium | F12: TypeError retried identical measurement and could escape | Execute once and return unmeasured on errors. | Fixed; focused or suite verification |
| M2/C3 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/resolution_log.py:114 | Medium | F13: NaN could hide a measured stall during compaction | Normalize NaN before aggregation; preserve selector equivalence. | Fixed; focused or suite verification |
| S2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/console_window.py:139 | Medium | F14: Failed GUI queue handoff left the console busy forever | Propagate the handoff failure to the existing busy-flag guard. | Fixed; focused or suite verification |
| S2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/router_window.py:620 | Medium | F15: Router could start after a rejected save | Persist before updating live settings; refuse start if save fails. | Fixed; focused or suite verification |
| S3 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/peers.py:357 | Medium | F16: Infinity in a saved healthcheck counter stopped loading | Catch OverflowError and use the established zero fallback. | Fixed; focused or suite verification |
| M4 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/commands.py:99 | Medium | F17: dig and gateway checks asserted unsupported fault localization | Label native/direct checks and both route families; remove definite attribution. | Fixed; focused or suite verification |
| M4 | /Users/mitch/dev/net-dns-monitor/README.md:71 | Medium | F18: GUI shell console was described as a confirmed catalogue REPL | Document separate consoles and immediate arbitrary-shell execution. | Fixed; focused or suite verification |
| M4 | /Users/mitch/dev/net-dns-monitor/docs/APP_STORE_SUBMISSION.md:54 | Medium | F19: Current guidance contradicted dated release evidence | Reconcile all current guides with recorded 2026-09-27 release/submission; no approval inference. | Fixed; focused or suite verification |
| M4 | /Users/mitch/dev/net-dns-monitor/docs/logging.md:30 | Medium | F20: Guidance called implemented resolution compaction unimplemented | Document trigger, aggregates and remaining domain-cardinality bound. | Fixed; focused or suite verification |
| T1/S1 | /Users/mitch/dev/net-dns-monitor/tests/conftest.py:141 | Medium | F21: Inherited credentials could send synthetic test incidents | Clear Slack, Anthropic and SMTP credentials before each test. | Fixed; focused or suite verification |
| T3 | /Users/mitch/dev/net-dns-monitor/.pre-commit-config.yaml:19 | Medium | F22: Hook Ruff differed from the repo pin | Synchronize hook/runtime tooling, including green Dependabot Ruff 0.16.9 update. | Fixed; focused or suite verification |
| T2/T3 | /Users/mitch/dev/net-dns-monitor/constraints.txt:32 | Medium | F23: Dev-tool design and runtime dependency closure were inconsistent | Keep pre-commit external; pin verified httpx2/httpcore2/truststore closure. | Fixed; focused or suite verification |
| T4 | /Users/mitch/dev/net-dns-monitor/tests/test_throughput.py:186 | Medium | F24: Three tests abandoned 10/30-second workers | Use Events, release in finally and wait for completion; retain deadline assertions. | Fixed; focused or suite verification |
| M4/T3 | /Users/mitch/dev/net-dns-monitor/docs/MCP.md:18 | Medium | F25: Empty guides and missing retrieval entries; no drift gate | Fill actual MCP/caching docs, extend index, add static count/path guard and partial dossier. | Fixed; focused or suite verification |
| C1/S4 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/console_window.py:47 | Medium | F26: Second controller redeclared the Objective-C target class | Cache the lazy class; each instance keeps its own controller. | Fixed; focused or suite verification |
| C1/C2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/failover.py:968 | Medium | F27: Disabled preferred service could be called successful failback | Refuse before writing and keep the restore point. | Fixed; focused or suite verification |
| C1/C2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/failover.py:1016 | Medium | F28: Exact third-head restore falsely claimed preferred failback | Preserve exact restoration and name the actual restored head. | Fixed; focused or suite verification |

## Existing residuals

| Pass | Evidence | Severity | Status and constraint |
|---|---|---|
| P2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/app.py::_tick | Medium | BLOCKED (ambiguous intent): the synchronous incident pipeline can occupy the GUI timer thread. Moving it needs explicit ordering, anti-flap edge and UI-handoff design. |
| S2/P2 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/prober.py::resolve_all; resolution_prober.py | Medium | BLOCKED (ambiguous intent): libc resolver workers cannot be cancelled. Caller deadlines bound waiting, not a stuck OS call or total lifetime of repeated workers. |
| P1/M3 | /Users/mitch/dev/net-dns-monitor/netdnsmonitor/stall_log.py::select_stalled_domains | Medium | BLOCKED (ambiguous intent): fresh installs have no seed; fully abandoned batches can freeze rotation. Strict file retention also conflicts with permanent ever-stalled evidence. Existing task TASK-335 now records actual compaction and the remaining cardinality decision. |

Peer discovery remains unauthenticated and advisory. Chroma 1.5.9 has four known advisory families in the optional index dependency set. The affected HTTP/RBAC server endpoints are not exposed by this repository (PersistentClient plus stdio MCP); no remotely exploitable application path was demonstrated. Its transitive closure was not fully audited. No semantic service was started or upgraded.

## Verification

| Gate | Baseline | Final candidate | Verdict |
|---|---|---|---|
| Offline pytest | 2150 passed, 27.49s; existing Python 3.14.7 environment | 2203 passed, 26.56s; clean Python 3.13.12 and pinned dependencies | PASS; 53 added cases |
| Ruff lint / format | clean; local Ruff 0.16.1 | clean; pinned Ruff 0.16.9 | PASS |
| Dependency installation | old local environment differed from pins | clean runtime/dev/build install through constraints; missing closure pinned | PASS |
| Regression red gates | correctness 12 failures; performance 9; root safety 14 | green; later Objective-C 1 and failback 2 reproduced red then fixed | PASS |
| Static documentation/count gate | absent | check_docs.py --collect-tests passes | PASS |
| Shell syntax | not changed | bash -n install_persistent_nat.sh | PASS; installer never executed |
| CI and publication | baseline master | PR checks and merge receipt recorded in task/journal | Required before merge; task/PR holds receipt |

Full-suite timing is not a controlled performance benchmark. No latency/throughput gain is claimed from these two wall-clock samples. No live GUI launch, App Store acceptance, privileged write, real alert delivery or NAT64-only test was performed.

## Activated skills and pass coverage

Loaded code-deep-optimizer, repo-bootstrapper, deep-optimizer routing, lang-python, security-review, software-engineering-patterns and crawl-repo-to-llms. Python, untrusted inputs, network side effects and concurrency justified the reviewer skills. Crawl output is a partial static adapter, not completion of every deep-card/executable-inventory step.

| Pass | Coverage/result |
|---|---|
| C1 | Active: networking semantics, state freshness, route and failback contracts |
| C2 | Active: caller/result consistency, tri-state and persistence boundaries |
| C3 | Active: deterministic wire/edge/error counterexamples and red regressions |
| S1 | Active: notification secrecy, inherited test credentials, effect boundaries |
| S2 | Active: errors, persistence, worker and GUI-hop failures; resolver lifetime residual |
| S3 | Active: DHCP pools, numeric targets, stored counters and DNS wire bounds |
| S4 | Active: Darwin family binding, shell daemon environment, PyObjC lifetime |
| S5 | Partial: targeted persistence/error observability; no blanket external-call logging rewrite |
| P1 | Active: shared budgets and lookup reuse; no controlled live benchmark |
| P2 | Active: cache races and worker lifecycle; synchronous incident pipeline remains |
| M1 | Active: scoped source readability; no length-only refactors warranted |
| M2 | Active: aggregation consistency and duplicate measurement retry |
| M3 | Active: injected effect layering and desktop scope; no enterprise services added |
| M4 | Partial: current guides/comments/selected manual sections; not every prose line revalidated |
| T1 | Partial: static scan of 70 non-holdout Python files and detailed risky tests; no coverage percentage claim |
| T2 | Partial: 35 explicit pins plus three newly resolved transitives queried against OSV; index closure not fully scanned |
| T3 | Active: CI/hooks/pins and static doc drift checks |
| T4 | Partial: inspected test sleeps/worker isolation; no runner parallelism or real kernel-timeout faking |

All 18 passes were active with the stated partial coverage. The normal 50-file triage cap was expanded for related runtime corroboration and bootstrap metadata; grouping and overlap prevent a claim of uniform per-file 18-pass coverage. Group 4 records its exact 33-module deep-read set in the dossier manifest. Correctness deeply read 16 overlapping modules, safety 17 primary files plus router scripts; performance reviewed the relevant probe/meter/app paths. The filename census covers every tracked path plus declared additions, but every dossier card is shallow. Remaining deep-card work is explicitly enumerated by deferred_paths, ready for a later content crawl with indexing still paused.

## Bootstrap manifest

Existing editor/git metadata, Python pins, CI, issue/PR/security templates and core architecture/testing/install/runbooks were retained. The high-signal index grew from 89 to 106 paths. Empty MCP and caching guides now describe actual code. The static guard validates path safety/existence, dossier census/output parity and published total/per-file test counts. CI runs it. The partial dossier has 10 outputs and a separate review-scope inventory. CODEOWNERS, editor-specific files, server operations registries and administrative dashboards are optional or inapplicable for the solo desktop app. Prompt/work journals are below rotation thresholds.

## macOS research impact and sources

The earlier request loaded existing references and checked Apple guidance; it was not a completed original research program. This review verified the following implications against current code and primary material:

- Native IPv6 and NAT64-only reachability are different. A hard-coded IPv6 heartbeat cannot prove NAT64 acceptance. Apple documents address synthesis through getaddrinfo with its example flags; the code now uses returned families without promising flags=0 synthesis. Actual acceptance remains a separate live test.
https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/NetworkingOverview/UnderstandingandPreparingfortheIPv6Transition/UnderstandingandPreparingfortheIPv6Transition.html

- macOS dig bypasses native hostname/address resolution and DNS routing. The installed Apple manual man dig, macOS NOTICE, verifies this; man dscacheutil documents standard cache/live queries. The command catalogue and guide now distinguish these paths rather than locating a fault from differing replies.
Primary installed sources: /usr/share/man/man1/dig.1 and /usr/share/man/man1/dscacheutil.1. Python socket.create_connection is family-agnostic:
https://docs.python.org/3/library/socket.html#socket.create_connection

- Local Network permission failures need evidence from the affected process. Existing usage-description, sandbox gates and unknown-state rules were preserved; tests do not prove current prompt/grant behavior.
https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy

- OSV returned no matching advisories for queried runtime/dev/build pins, including the newly resolved Anthropic HTTP stack. This is database evidence, not proof of absence. Official metadata confirms the closure:
https://pypi.org/pypi/anthropic/1.8.0/json
https://pypi.org/pypi/httpx2/2.13.1/json
https://pypi.org/pypi/httpcore2/2.13.1/json
https://pypi.org/pypi/truststore/0.10.4/json

Qualified optional Chroma advisories:
https://github.com/advisories/GHSA-f4j7-r4q5-qw2c
https://github.com/advisories/GHSA-36p7-vc44-83pf
https://github.com/advisories/GHSA-2wm9-hf6c-p5cr
https://github.com/advisories/GHSA-xph7-9rjv-w5fr

## Independent and empirical gates

First fresh-context audit: three Medium findings (Objective-C duplicate class, disabled preferred failback, wrong-head restore wording). All were corroborated and fixed. Second fresh-context audit: no concrete Medium+ regression; 498 focused tests passed in 7.99s. Static path guard passed. Its source/diff scope included changed runtime modules, app wiring, scripts and matching tests; live acceptance remained outside the gate. No cross-model gate requested.

Empirical mode: exploratory dry-run only. Reserved tests/test_graphs.py remained unread by reviewers; it contains 26 cases, below the contract minimum of 30. Working-set regressions selected edits. Baseline and final full suites pass its 26 cases (100%); no margin-based promotion, independent confirmation set or quality/performance improvement is claimed. The structural fixes are regression-verified, not a champion-challenger quality gain.

## Capped diff preview

Each tracked changed file has a capped patch preview below. Added artifacts are listed separately. Full diffs are available in the published PR; these snippets omit context deliberately.

### /Users/mitch/dev/net-dns-monitor/.github/workflows/ci.yml

```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 98828ab..44f71bb 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -96,0 +97,5 @@ jobs:
+
+      # Static paths/counts only. Never open the semantic collection or contact
+      # Ollama in CI; a missing local index is not an application failure.
+      - name: Documentation paths and test counts
+        run: python scripts/check_docs.py --collect-tests
```
### /Users/mitch/dev/net-dns-monitor/.pre-commit-config.yaml

```diff
diff --git a/.pre-commit-config.yaml b/.pre-commit-config.yaml
index efd8c53..bb35600 100644
--- a/.pre-commit-config.yaml
+++ b/.pre-commit-config.yaml
@@ -19 +19 @@ repos:
-    rev: v0.16.1
+    rev: v0.16.9
```
### /Users/mitch/dev/net-dns-monitor/CLAUDE.md

```diff
diff --git a/CLAUDE.md b/CLAUDE.md
index 4ef3f07..d3109c0 100644
--- a/CLAUDE.md
+++ b/CLAUDE.md
@@ -80 +80 @@ report, because someone will act on it.
-ruff check . && ruff format --check . && python3 -m pytest -q   # 2150 tests, offline
+ruff check . && ruff format --check . && python3 -m pytest -q   # 2203 tests, offline
@@ -89,6 +89,11 @@ they test those functions and inject their own runners.
-There is **no `scripts/check_docs.py`** in this repo, despite what earlier revisions of
-this file claimed. Nothing machine-checks doc drift. Whenever tests are added, regenerate
-every test count by hand from `python3 -m pytest -q --collect-only | grep -c '::'`. The
-counts live in `docs/SCRIPTS.md` (the quick-start comment, the entry-point table, the
```
Truncated: 32 further patch lines.

### /Users/mitch/dev/net-dns-monitor/README.md

```diff
diff --git a/README.md b/README.md
index 2b13034..7306e83 100644
--- a/README.md
+++ b/README.md
@@ -73,13 +73,12 @@ the wrong fault.
-`netdns console` (or "Open console…" in the menu bar) is a REPL over the same
-catalogue: a usage guide, a numbered list of diagnostic commands, the live
-interface table, and service-order editing (`priority`, `promote <name>`).
-
-Anything that changes system state — a catalogue command marked `!`, switching
-networks, or promoting a service — shows you the exact command and waits for
-`yes`. Nothing that rewrites configuration happens on a single keypress. A
```
Truncated: 18 further patch lines.

### /Users/mitch/dev/net-dns-monitor/config.yaml

```diff
diff --git a/config.yaml b/config.yaml
index 0ceeaf1..aecb801 100644
--- a/config.yaml
+++ b/config.yaml
@@ -82,2 +82,2 @@ resolution_max_workers: 10
-# Pinged before ping_host; blank turns it off. IPv6 first because App Review
-# runs an IPv6-only NAT64 network, where an IPv4 ping has no route.
+# Pinged before ping_host; blank turns it off. Native IPv6 supports IPv6-only
+# links, but a NAT64-only test network may not route a native IPv6 literal.
@@ -87 +87,2 @@ ping_host: "8.8.8.8"
-# false positive "network failed" alerts from single-host ICMP rate limiting.
+# reducing alerts caused by single-host ICMP rate limiting. A reply proves
```
Truncated: 6 further patch lines.

### /Users/mitch/dev/net-dns-monitor/constraints.txt

```diff
diff --git a/constraints.txt b/constraints.txt
index 24ba146..281ff31 100644
--- a/constraints.txt
+++ b/constraints.txt
@@ -31,0 +32 @@ httpcore==1.0.9
+httpcore2==2.13.1
@@ -32,0 +34 @@ httpx==0.28.1
+httpx2==2.13.1
@@ -48 +50 @@ pyyaml==6.0.3
-ruff==0.16.8
+ruff==0.16.9
@@ -53,0 +56 @@ typing-inspection==0.4.4
```
Truncated: 1 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/APP_STORE_CHECKLIST.md

```diff
diff --git a/docs/APP_STORE_CHECKLIST.md b/docs/APP_STORE_CHECKLIST.md
index cb8e05c..830e55d 100644
--- a/docs/APP_STORE_CHECKLIST.md
+++ b/docs/APP_STORE_CHECKLIST.md
@@ -32,2 +32,5 @@ Not verified, because it cannot be from a script: the sandboxed GUI app was
-not launched, so the manual checks in step 5 are still open. Release signing
-has never run: this Mac has no distribution certificates (step 2).
+not launched in that measurement, so the manual checks in step 5 were still
+open. Release signing subsequently ran with real certificates on 2026-09-27
+(step 6). Build 1.0 (3) was submitted (step 7), then rejected for information
+on 2026-09-28; `APP_STORE_REVIEW_RESPONSE.md` records the later build-4 plan.
+Check App Store Connect for the current review state.
```
### /Users/mitch/dev/net-dns-monitor/docs/APP_STORE_SUBMISSION.md

```diff
diff --git a/docs/APP_STORE_SUBMISSION.md b/docs/APP_STORE_SUBMISSION.md
index 4bbd707..36f06d8 100644
--- a/docs/APP_STORE_SUBMISSION.md
+++ b/docs/APP_STORE_SUBMISSION.md
@@ -79 +79 @@ notarization (§10). Both can coexist.
-- **Release mode was never run.** This Mac has no Apple Distribution or Mac Installer Distribution certificate (checked again 2026-09-17: `security find-identity -v` lists one *Apple Development* identity, which cannot sign a store upload), so release signing, provisioning-profile embedding and `productbuild` signing have not been run. Ad-hoc mode was run end to end on 2026-09-14 and again on 2026-09-17.
+- **Current release and review state needs a live check.** Release signing first ran with real certificates on 2026-09-27, as recorded in `docs/APP_STORE_CHECKLIST.md` step 6. That checklist records processed/submitted build 1.0 (3) from `395c14e`; `docs/APP_STORE_REVIEW_RESPONSE.md` records its 2026-09-28 rejection and the subsequent build-4 plan. These are dated records, not a live check of certificates, App Store Connect, or the installed app.
@@ -82 +82,6 @@ notarization (§10). Both can coexist.
-- **Two helpers still shell out in the store build.** "Open forensic logs folder" runs `/usr/bin/open`, and the alert's notification fallback runs `osascript`. Neither has run sandboxed. Reports themselves now open through NSWorkspace. Click both once in the ad-hoc build.
+- **Store file opening and notification display need a manual check.** The app
+  opens HTTP(S) URLs through NSWorkspace. Files and folders still use
+  `/usr/bin/open`; that path is not verified in the sandbox. The alert
```
Truncated: 6 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/ARCHITECTURE.md

```diff
diff --git a/docs/ARCHITECTURE.md b/docs/ARCHITECTURE.md
index 763cfa9..59501d6 100644
--- a/docs/ARCHITECTURE.md
+++ b/docs/ARCHITECTURE.md
@@ -73,3 +73,5 @@ imports `interface_probe.py`.
-   `failure_threshold` consecutive non-healthy ticks. It clears the incident only
-   after `success_threshold` consecutive healthy ticks. An `unclassified` tick
-   counts as non-healthy.
+   `failure_threshold` consecutive failing ticks. It clears the incident only
+   after `success_threshold` consecutive healthy ticks. `StateMachine.tick()`
+   leaves the gate unchanged for an unclassified result when either reachability
+   or DNS is positively healthy. With no positive field, an unclassified result
```
Truncated: 1 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/COMPONENTS.md

```diff
diff --git a/docs/COMPONENTS.md b/docs/COMPONENTS.md
index 30c1fdd..6eef570 100644
--- a/docs/COMPONENTS.md
+++ b/docs/COMPONENTS.md
@@ -125 +125 @@ The ordered troubleshooting steps per classification (`NETWORK_LADDER`, `DNS_LAD
-`query_public_dns(domain)` sends one A query to a public resolver (default `1.1.1.1:53`) and validates the reply header. Returns `True`, `False`, or `None` when no reply arrived.
+`query_public_dns(domain)` sends one A query to a public resolver (default `1.1.1.1:53`). A matching, complete reply with a usable A answer, including a CNAME chain, returns `True`. A valid negative or NODATA reply returns `False`. A malformed, mismatched, truncated or missing reply returns `None`. Unsupported input names return `False`. This direct-server result does not establish native scoped resolver behavior.
@@ -192 +192 @@ The ordered troubleshooting steps per classification (`NETWORK_LADDER`, `DNS_LAD
-- **Side effects:** File append. No seam; tests pass a path.
+- **Side effects:** File append and, above 50,000 lines, per-domain compaction retaining maximum finite elapsed time and newest completed lookup. No seam; tests pass a path.
@@ -226 +226 @@ Reads the network parts of the unified log for the dashboard pane: `make_log_rea
-`make_query_log_reader` returns the raw DNS query lines from `log show`; `extract_top_domains` counts the most-queried names. Used by the dashboard's prewarm action.
```
Truncated: 3 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/DEVELOPMENT.md

```diff
diff --git a/docs/DEVELOPMENT.md b/docs/DEVELOPMENT.md
index c1991ad..60b0556 100644
--- a/docs/DEVELOPMENT.md
+++ b/docs/DEVELOPMENT.md
@@ -49,2 +49,4 @@ tests enforce that every key `load_config` reads appears in it with its real
-value, and that every key has a field in the settings window. There is no
-`config.example.yaml`; it was removed so the two could not drift apart.
+value, and that every key has a field in the settings window.
+`config.example.yaml` is a separate screenshot/demo fixture used by
+`scripts/appstore/shoot_screenshots.py`. It is not the source of runtime defaults;
+change `config.yaml` and `netdnsmonitor/config.py` together.
```
### /Users/mitch/dev/net-dns-monitor/docs/MCP.md

```diff
diff --git a/docs/MCP.md b/docs/MCP.md
index e69de29..851b9b2 100644
--- a/docs/MCP.md
+++ b/docs/MCP.md
@@ -0,0 +1,32 @@
+# Developer semantic search
+
+The optional developer index is separate from the menu bar app. It stores chunks
+in `<checkout>/.chroma_db`, in collection `codebase_index`. The indexer uses the
+local Ollama endpoint `http://localhost:11434/api/embeddings` with model
+`nomic-embed-text`. Installing the application does not install these tools.
+
```
Truncated: 25 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/SCRIPTS.md

```diff
diff --git a/docs/SCRIPTS.md b/docs/SCRIPTS.md
index 51e6d86..04e9561 100644
--- a/docs/SCRIPTS.md
+++ b/docs/SCRIPTS.md
@@ -36 +36 @@ One command is a gate rather than an experiment. Run it before trusting the rest
-python3 -m pytest -q          # 2150 tests; the whole decision surface
+python3 -m pytest -q          # 2203 tests; the whole decision surface
@@ -48 +48 @@ python3 -m pytest -q          # 2150 tests; the whole decision surface
-| `python3 -m pytest` | **gate:** the full decision surface, 2150 tests | no |
+| `python3 -m pytest` | **gate:** the full decision surface, 2203 tests | no |
@@ -485,3 +485,5 @@ name latches a permanent incident by a second route.
-**Purpose.** Hand-rolled UDP query against a chosen resolver. `getaddrinfo` cannot do
```
Truncated: 80 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/TESTING.md

```diff
diff --git a/docs/TESTING.md b/docs/TESTING.md
index 34a0e75..e18907e 100644
--- a/docs/TESTING.md
+++ b/docs/TESTING.md
@@ -3 +3 @@
-2150 tests, offline, in tens of seconds. `pytest.ini` sets
+2203 tests, offline, in tens of seconds. `pytest.ini` sets
@@ -29,0 +30 @@ on Python 3.13:
+| `test` | `macos-latest` | `python scripts/check_docs.py --collect-tests`: retrieval paths, dossier parity, and published test counts |
@@ -36 +37 @@ checks before a commit; it does not run the tests.
-The local verify loop is the same three commands:
+The local verify loop includes the static documentation check:
```
Truncated: 8 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/caching-and-optimization.md

```diff
diff --git a/docs/caching-and-optimization.md b/docs/caching-and-optimization.md
index e69de29..fdad788 100644
--- a/docs/caching-and-optimization.md
+++ b/docs/caching-and-optimization.md
@@ -0,0 +1,29 @@
+# Caching and bounded work
+
+The app has no shared server cache or administrative cache dashboard. Each
+process owns its monitor state, histories, worker queues and credential cache.
+`docs/ARCHITECTURE.md` describes the timers and data flow; the modules below own
+the bounds and persistence policy.
+
```
Truncated: 22 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/codebase-overview.md

```diff
diff --git a/docs/codebase-overview.md b/docs/codebase-overview.md
index a307142..9d84546 100644
--- a/docs/codebase-overview.md
+++ b/docs/codebase-overview.md
@@ -3 +3,3 @@
-A map of every tracked file, grouped by directory. Read it to find where
+A high-signal map, grouped by directory. The complete static source census is in
+`docs/llms/llms-filemap.txt`; every census card is explicitly shallow. Read this
+overview to find where
@@ -10,2 +12,3 @@ user; **high** means a change can break a feature or mislead a reader. Unmarked
-files are ordinary. The descriptions were re-checked against the working tree on
-2026-09-14 (commit `a6aab33`).
```
Truncated: 29 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/external-calls.md

```diff
diff --git a/docs/external-calls.md b/docs/external-calls.md
index 9b5015f..839a7c9 100644
--- a/docs/external-calls.md
+++ b/docs/external-calls.md
@@ -49 +49 @@ and to source runs only.
-| `netdnsmonitor/alert.py:109` | `/usr/bin/osascript -e 'display notification ...'`. Runs only when `rumps.notification` raised. | 10 s | Exception caught; traceback to stderr. | not gated. UNVERIFIED inside the sandbox. | `tests/test_alert.py` (`run_fn`) |
+| `netdnsmonitor/alert.py:119` | `/usr/bin/osascript -e 'display notification ...'`. Runs only when `rumps.notification` raised. | 3 s | Exception caught; traceback to stderr. | Skipped in the store build. | `tests/test_alert.py` (`run_fn`) |
@@ -73 +73 @@ and to source runs only.
-| `netdnsmonitor/query_log.py:44` | `/usr/bin/log show --style compact --last <log_lookback> --predicate <mDNSResponder, DNS>` (dashboard `prewarm_dns`). | 10 s | Data: `[]`; the action prints `No queried domains found in the log`. | Gated: `unified_log` (`GATED_DASHBOARD_ACTIONS`). | `tests/test_query_log.py` (`run_fn`) |
+| `netdnsmonitor/query_log.py:44` | `/usr/bin/log show --style compact --last <log_lookback> --predicate <mDNSResponder, DNS>` (dashboard `prewarm_dns`). | 10 s | Data: `None` on a failed read, `[]` on a successful empty read; the action distinguishes unavailable evidence from no queried domains. | Gated: `unified_log` (`GATED_DASHBOARD_ACTIONS`). | `tests/test_query_log.py` (`run_fn`) |
```
### /Users/mitch/dev/net-dns-monitor/docs/high_signal_file_index.json

```diff
diff --git a/docs/high_signal_file_index.json b/docs/high_signal_file_index.json
index 16f4eba..a4f249d 100644
--- a/docs/high_signal_file_index.json
+++ b/docs/high_signal_file_index.json
@@ -2 +2 @@
-  "generated_from": "a6aab33",
+  "generated_from": "b8672f1 dirty; static map refreshed 2026-10-04",
@@ -8 +8 @@
-      "purpose": "The CI gate: ruff check and ruff format --check on ubuntu-latest; pytest on macos-latest after pip install -r requirements-dev.txt -c constraints.txt; Python 3.13.",
+      "purpose": "CI: pinned Ruff on Ubuntu; offline pytest and static documentation checks on macOS; Python 3.13.",
@@ -1021,0 +1022,136 @@
+    },
```
Truncated: 135 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/integrations-and-assumptions.md

```diff
diff --git a/docs/integrations-and-assumptions.md b/docs/integrations-and-assumptions.md
index fbccd55..7231831 100644
--- a/docs/integrations-and-assumptions.md
+++ b/docs/integrations-and-assumptions.md
@@ -24 +24 @@ below are `config.DEFAULT_CONFIG` values; `tests/test_config.py` checks that
-| App Store Connect | `scripts/appstore/build_appstore.py` (release mode) | `xcrun altool --validate-app` and `--upload-package`. The script prints these commands and runs neither. | Manual. | App Store Connect API key (outside the repo) | Release mode has never run. See `docs/APP_STORE_SUBMISSION.md`. |
+| App Store Connect | `scripts/appstore/build_appstore.py` (release mode) | `xcrun altool --validate-app` and `--upload-package`. The script prints these commands and runs neither. | Manual. | App Store Connect API key (outside the repo) | Release signing ran on 2026-09-27; the checklist and review-response document record build 3 submission and later rejection. Current state needs a live check. |
```
### /Users/mitch/dev/net-dns-monitor/docs/known-issues.md

```diff
diff --git a/docs/known-issues.md b/docs/known-issues.md
index 4209d0d..3bc8cf8 100644
--- a/docs/known-issues.md
+++ b/docs/known-issues.md
@@ -88,6 +88,7 @@ and proves nothing about the world.
-- **The Mac App Store release path has never run with real certificates.** This
-  Mac has no Apple Distribution or Mac Installer Distribution certificate, so
-  `build_appstore.py release` (release signing, provisioning-profile embedding,
-  `productbuild` signing) has not run. `adhoc` mode ran end to end. The GUI app
-  has not been launched sandboxed; only `sandbox_probe` has. See
-  `docs/APP_STORE_SUBMISSION.md` §2.
+- **Current App Store review and live GUI behavior need verification.**
```
Truncated: 59 further patch lines.

### /Users/mitch/dev/net-dns-monitor/docs/logging.md

```diff
diff --git a/docs/logging.md b/docs/logging.md
index b0fca21..c3f2bec 100644
--- a/docs/logging.md
+++ b/docs/logging.md
@@ -30 +30 @@ every read.
-| Resolution log, `resolution_log_path` (`resolution-log.jsonl`) | `resolution_log.append_resolution_findings` | After each stalled-domain batch that produced findings (every `resolution_interval_seconds`, 300 s). One `checked_at` per batch. | None. See "Blocked on an owner decision" in `docs/known-issues.md`. `stall_log.select_stalled_domains` reads the whole file back each batch. |
+| Resolution log, `resolution_log_path` (`resolution-log.jsonl`) | `resolution_log.append_resolution_findings` | After each stalled-domain batch that produced findings (every `resolution_interval_seconds`, 300 s). One `checked_at` per batch. | Compacted after 50,000 lines to one completed record per domain: the slowest elapsed time with the newest completed `checked_at`. Abandoned records are dropped. The selector streams the file each batch; retained size scales with distinct historical domains, so 50,000 is a trigger, not a hard limit. |
```
### /Users/mitch/dev/net-dns-monitor/docs/runbooks/app-store-release.md

```diff
diff --git a/docs/runbooks/app-store-release.md b/docs/runbooks/app-store-release.md
index c19acec..e37bdbd 100644
--- a/docs/runbooks/app-store-release.md
+++ b/docs/runbooks/app-store-release.md
@@ -20,3 +20,4 @@ Every upload of a new build to App Store Connect.
-- **UNVERIFIED:** release mode has never run on this Mac, which has no Apple
-  Distribution or Mac Installer Distribution certificate
-  ([§2](../APP_STORE_SUBMISSION.md#2-what-is-already-done-in-this-repo)).
+- Release signing ran with real certificates on 2026-09-27; see
+  [the dated checklist](../APP_STORE_CHECKLIST.md#step-6-build-for-release).
+  Confirm the currently available identities/profile before a new release.
+  Historical build success does not verify today's certificate or review state.
```
### /Users/mitch/dev/net-dns-monitor/llms-facts.txt

```diff
diff --git a/llms-facts.txt b/llms-facts.txt
index d12846d..9aa8fb7 100644
--- a/llms-facts.txt
+++ b/llms-facts.txt
@@ -1,25 +1,9 @@
-<!-- generated: llms-suite 1.0, 2026-09-25; verified-as-of 2026-09-25; local paths rewritten to repo-relative -->
-
-# net-dns-monitor: Sourced Facts
-
-One declarative fact per line, each tagged with the repo-relative file it came from.
-
-## Facts
```
Truncated: 27 further patch lines.

### /Users/mitch/dev/net-dns-monitor/llms-full.txt

```diff
diff --git a/llms-full.txt b/llms-full.txt
index 9ea2636..9c58294 100644
--- a/llms-full.txt
+++ b/llms-full.txt
@@ -1,609 +1,14 @@
-<!-- generated: llms-suite 1.0, 2026-09-25; verified-as-of 2026-09-25; local paths rewritten to repo-relative -->
-
-# net-dns-monitor
-Source: https://github.com/mithudso/net-dns-monitor/blob/HEAD/README.md
-
-## net-dns-monitor
-
```
Truncated: 616 further patch lines.

### /Users/mitch/dev/net-dns-monitor/llms-small.txt

```diff
diff --git a/llms-small.txt b/llms-small.txt
index c0327e0..f4b2a30 100644
--- a/llms-small.txt
+++ b/llms-small.txt
@@ -1 +1,4 @@
-<!-- generated: llms-suite 1.0, 2026-09-25; verified-as-of 2026-09-25; local paths rewritten to repo-relative -->
+# net-dns-monitor — small retrieval guide
+> Source: /Users/mitch/dev/net-dns-monitor · remote URL omitted @ b8672f1 dirty
+> Generated: 2026-10-04 by crawl-repo-to-llms v1.2.0 (partial static adapter)
+> Census: 220 enumerated / 0 deep-read / 220 shallow · partial: census only; no deep cards or executable inventory
@@ -3 +6,9 @@
-# net-dns-monitor (small)
```
Truncated: 18 further patch lines.

### /Users/mitch/dev/net-dns-monitor/llms.txt

```diff
diff --git a/llms.txt b/llms.txt
index 83b9326..5fd364b 100644
--- a/llms.txt
+++ b/llms.txt
@@ -1,27 +1,16 @@
-<!-- generated: llms-suite 1.0, 2026-09-25; verified-as-of 2026-09-25; local paths rewritten to repo-relative -->
-
-# net-dns-monitor
-
-> macOS menu bar app that monitors network and DNS connectivity, auto-diagnoses with an offline troubleshooting ladder, escalates to Claude when the ladder cannot resolve it, and saves an IT-ready incident report.
-
-## Start here
```
Truncated: 36 further patch lines.

### /Users/mitch/dev/net-dns-monitor/memory.md

```diff
diff --git a/memory.md b/memory.md
index 124ab47..75d37ca 100644
--- a/memory.md
+++ b/memory.md
@@ -114,0 +115,8 @@ CI found a pre-existing console test race (tests/test_console.py:535, assert 1 =
+
+## v7 - 2026-10-04 - Networking review, code optimizer and repo bootstrapper
+
+Delta: 1
+
+Active task: TASK-379. Branch: fix/macos-networking-audit. Baseline: b8672f1. Loaded code-deep-optimizer v1.7.0, repo-bootstrapper v5.4.0 and their referenced contracts. Five audit groups will cover correctness, safety, concurrency, maintainability and tests/tooling, with the runtime concurrency cap respected. Networking topics include system versus direct DNS, IPv6/NAT64, scoped probes and permission uncertainty. KNOW-275 preserves the solo desktop scope. Do not modify live resolver symlinks, start indexing, embeddings or Ollama.
+
```
Truncated: 1 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/app.py

```diff
diff --git a/netdnsmonitor/app.py b/netdnsmonitor/app.py
index 92b99b6..cd445a4 100644
--- a/netdnsmonitor/app.py
+++ b/netdnsmonitor/app.py
@@ -640 +640,6 @@ def heartbeat_label(config: dict) -> str:
-def ping_heartbeat(config: dict, ping_fn: Optional[Callable[..., dict]] = None) -> dict:
+def ping_heartbeat(
+    config: dict,
+    ping_fn: Optional[Callable[..., dict]] = None,
+    *,
+    clock: Callable[[], float] = time.monotonic,
+) -> dict:
```
Truncated: 18 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/cli.py

```diff
diff --git a/netdnsmonitor/cli.py b/netdnsmonitor/cli.py
index 3989d05..7790dde 100644
--- a/netdnsmonitor/cli.py
+++ b/netdnsmonitor/cli.py
@@ -102,2 +102,2 @@ NET/DNS CONSOLE -- what to do when the network breaks
-     Nothing reachable            -> a network-layer fault. Go to 3.
-     Reachable but names fail     -> a DNS fault. Go to 2.
+     No reply                     -> inspect routes and filtering. Go to 3.
+     TCP works but names fail     -> compare resolver paths. Go to 2.
@@ -108,2 +108,4 @@ NET/DNS CONSOLE -- what to do when the network breaks
-     `dig` vs `dig-direct`  if direct works and the normal one does not,
-                   the local resolver is at fault, not the network.
```
Truncated: 11 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/commands.py

```diff
diff --git a/netdnsmonitor/commands.py b/netdnsmonitor/commands.py
index 9510b93..6caf80c 100644
--- a/netdnsmonitor/commands.py
+++ b/netdnsmonitor/commands.py
@@ -57 +57,6 @@ CATALOG: list[DiagnosticCommand] = [
-        "the routing table -- which interface the default route points at",
+        "the IPv4 routing table -- which interface the default route points at",
+    ),
+    DiagnosticCommand(
+        "routes6",
+        [NETSTAT, "-rn", "-f", "inet6"],
+        "the IPv6 routing table -- compare with the IPv4 routes",
```
Truncated: 19 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/config.py

```diff
diff --git a/netdnsmonitor/config.py b/netdnsmonitor/config.py
index ad7dae1..23dcf05 100644
--- a/netdnsmonitor/config.py
+++ b/netdnsmonitor/config.py
@@ -55 +55 @@ DEFAULT_CONFIG = {
-    # echo request to a single host every few seconds; it drives the menu bar
+    # echo requests to ordered targets every few seconds; it drives the menu bar
@@ -59,4 +59,3 @@ DEFAULT_CONFIG = {
-    # Pinged before ping_host; blank or null turns it off. IPv6 first because
-    # App Review runs an IPv6-only NAT64 network, where an IPv4 ping has no
-    # route and the heartbeat would report the network down. Same operator as
-    # 8.8.8.8, so a filtered ICMP path behaves alike on both.
```
Truncated: 6 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/console_window.py

```diff
diff --git a/netdnsmonitor/console_window.py b/netdnsmonitor/console_window.py
index 87d17a7..f5444c9 100644
--- a/netdnsmonitor/console_window.py
+++ b/netdnsmonitor/console_window.py
@@ -45,0 +46,3 @@ MAX_TRANSCRIPT_CHARS = 2_000_000
+# Objective-C class names are process-global, even across Python controllers.
+_CONSOLE_TARGET_CLASS = None
+
@@ -53,0 +57,4 @@ def _make_target(controller):
+    global _CONSOLE_TARGET_CLASS
+    if _CONSOLE_TARGET_CLASS is not None:
+        return _CONSOLE_TARGET_CLASS.alloc().initWithController_(controller)
```
Truncated: 7 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/dns_query.py

```diff
diff --git a/netdnsmonitor/dns_query.py b/netdnsmonitor/dns_query.py
index 285889a..e069e81 100644
--- a/netdnsmonitor/dns_query.py
+++ b/netdnsmonitor/dns_query.py
@@ -2,5 +2,3 @@
-resolver configuration. This is the ladder's "resolve against a known-good
-public resolver" check: it isolates "your configured resolver is broken"
-from "DNS is broken everywhere" (e.g. a captive portal intercepting all
-DNS), which `socket.getaddrinfo` can't do since it always goes through
-whatever resolver the OS is currently configured to use.
+resolver configuration. The ladder compares a public DNS-server answer with
+native resolution. Different results are evidence of different resolver paths,
```
Truncated: 141 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/failover.py

```diff
diff --git a/netdnsmonitor/failover.py b/netdnsmonitor/failover.py
index 71bcbce..33abf39 100644
--- a/netdnsmonitor/failover.py
+++ b/netdnsmonitor/failover.py
@@ -25,0 +26 @@ import json
+import logging
@@ -281 +282 @@ class FailoverStore:
-        except OSError:
+        except OSError as exc:
@@ -287 +288,4 @@ class FailoverStore:
-            pass
+            logging.getLogger(__name__).warning(
```
Truncated: 21 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/interface_probe.py

```diff
diff --git a/netdnsmonitor/interface_probe.py b/netdnsmonitor/interface_probe.py
index 947191a..a82ac91 100644
--- a/netdnsmonitor/interface_probe.py
+++ b/netdnsmonitor/interface_probe.py
@@ -17,0 +18 @@ import functools
+import ipaddress
@@ -61,11 +61,0 @@ def default_bound_connect(
-    # The bind option is family-specific. The ordinary prober uses
-    # socket.create_connection, which is family-agnostic, so an IPv6 external
-    # target is a perfectly valid thing to find in the config -- forcing every
-    # probe through AF_INET would report such a target as unreachable rather
-    # than unprobed, and a preferred link that had recovered over IPv6 would
```
Truncated: 54 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/notifications.py

```diff
diff --git a/netdnsmonitor/notifications.py b/netdnsmonitor/notifications.py
index c423ad0..6cd2912 100644
--- a/netdnsmonitor/notifications.py
+++ b/netdnsmonitor/notifications.py
@@ -115 +115,2 @@ def make_slack_notifier(
-            "error": f"Slack webhook returned status {status} body {body.strip()[:80]!r}",
+            # Response text is untrusted and can echo the webhook credential.
+            "error": f"Slack webhook rejected the message (status {status})",
```
### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/peers.py

```diff
diff --git a/netdnsmonitor/peers.py b/netdnsmonitor/peers.py
index 5522562..f3239f4 100644
--- a/netdnsmonitor/peers.py
+++ b/netdnsmonitor/peers.py
@@ -130,4 +130,3 @@ class PeerRegistry:
-            # Tri-state and only overwritten when the peer actually said
-            # something. A peer running an older build sends neither, and "didn't
-            # say" must stay distinguishable from "said no" -- localize.py treats
-            # them completely differently.
+            # Liveness and health have different meanings. A new message that
+            # omits health cannot refresh a prior healthy reading: that would
+            # make historical state look current to fault localization.
```
Truncated: 9 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/ping.py

```diff
diff --git a/netdnsmonitor/ping.py b/netdnsmonitor/ping.py
index 047b7ed..8075f58 100644
--- a/netdnsmonitor/ping.py
+++ b/netdnsmonitor/ping.py
@@ -36,3 +36,3 @@ Flags, and what each one is load-bearing for:
-           actually bounds the call -- measured 3.08s against an unroutable
-           address with `-t 3` -- which is what keeps a failed ping inside its
-           own 5s cadence.
+           bounds the binary itself -- measured 3.08s against an unroutable
+           address with `-t 3`. The subprocess timeout enforces the exact
+           fractional budget shared by the heartbeat's fallback targets.
@@ -136,3 +136,3 @@ def ping_once(
```
Truncated: 6 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/prober.py

```diff
diff --git a/netdnsmonitor/prober.py b/netdnsmonitor/prober.py
index ba604c7..4c4d799 100644
--- a/netdnsmonitor/prober.py
+++ b/netdnsmonitor/prober.py
@@ -59,0 +60,2 @@ def resolve_all(
+    errors: list[Exception] = []
+    lock = threading.Lock()
@@ -64 +66,8 @@ def resolve_all(
-            results[domain] = bool(resolve_fn(domain, timeout))
+            try:
+                result = bool(resolve_fn(domain, timeout))
+            except Exception as exc:  # noqa: BLE001 - propagate on the caller thread
```
Truncated: 13 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/repair_executor.py

```diff
diff --git a/netdnsmonitor/repair_executor.py b/netdnsmonitor/repair_executor.py
index e1c2068..47c44e6 100644
--- a/netdnsmonitor/repair_executor.py
+++ b/netdnsmonitor/repair_executor.py
@@ -216 +216,13 @@ def make_repair_executor(
-        return report_command([NETSTAT, "-rn", "-f", "inet"])
+        findings = [
+            (label, report_command([NETSTAT, "-rn", "-f", family]))
+            for label, family in (("IPv4", "inet"), ("IPv6", "inet6"))
+        ]
+        failures = sum(result.startswith("failed:") for _, result in findings)
+        prefix = (
```
Truncated: 13 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/resolution_log.py

```diff
diff --git a/netdnsmonitor/resolution_log.py b/netdnsmonitor/resolution_log.py
index 6b97d01..0adcb2b 100644
--- a/netdnsmonitor/resolution_log.py
+++ b/netdnsmonitor/resolution_log.py
@@ -24,0 +25 @@ import json
+import math
@@ -113 +114,2 @@ def _elapsed(record: dict) -> float:
-        return float(value)
+        elapsed = float(value)
+        return -1.0 if math.isnan(elapsed) else elapsed
```
### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/router.py

```diff
diff --git a/netdnsmonitor/router.py b/netdnsmonitor/router.py
index 115ef76..1f2b2d2 100644
--- a/netdnsmonitor/router.py
+++ b/netdnsmonitor/router.py
@@ -110,0 +111,3 @@ def validate(wan_if, lan_if, lan_ip, lan_netmask, dhcp_start, dhcp_end) -> Route
+    reserved = {network.network_address, network.broadcast_address}
+    if addresses["lan_ip"] in reserved:
+        raise ValueError("lan_ip is a network or broadcast address")
@@ -113,0 +117,2 @@ def validate(wan_if, lan_if, lan_ip, lan_netmask, dhcp_start, dhcp_end) -> Route
+        if addresses[field] in reserved:
+            raise ValueError(f"{field} is a network or broadcast address")
@@ -115,0 +121,2 @@ def validate(wan_if, lan_if, lan_ip, lan_netmask, dhcp_start, dhcp_end) -> Route
```
Truncated: 2 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/router_window.py

```diff
diff --git a/netdnsmonitor/router_window.py b/netdnsmonitor/router_window.py
index 6977f5f..f47cb9b 100644
--- a/netdnsmonitor/router_window.py
+++ b/netdnsmonitor/router_window.py
@@ -539,6 +538,0 @@ class RouterWindowController:
-        router = getattr(self.app, "router", None)
-        if router is not None:
-            for key, attr in _ROUTER_ATTRS.items():
-                if key in updates:
-                    setattr(router, attr, updates[key])
-
@@ -554,0 +549,6 @@ class RouterWindowController:
```
Truncated: 10 further patch lines.

### /Users/mitch/dev/net-dns-monitor/netdnsmonitor/throughput.py

```diff
diff --git a/netdnsmonitor/throughput.py b/netdnsmonitor/throughput.py
index fde47a3..b490daa 100644
--- a/netdnsmonitor/throughput.py
+++ b/netdnsmonitor/throughput.py
@@ -290,0 +291,2 @@ def make_throughput_meter(
+    *,
+    clock: Callable[[], float] = time.monotonic,
@@ -304,0 +307 @@ def make_throughput_meter(
+    lookup_lock = threading.Lock()
@@ -309,5 +312 @@ def make_throughput_meter(
-        if "address" not in cache:
-            cache["address"] = resolve_fn(host, timeout)
```
Truncated: 43 further patch lines.

### /Users/mitch/dev/net-dns-monitor/prompts.md

```diff
diff --git a/prompts.md b/prompts.md
index c7e838c..65c9b1a 100644
--- a/prompts.md
+++ b/prompts.md
@@ -51,0 +52,8 @@ Prompt:
+
+## v7 - 2026-10-04 - Networking review, code optimizer and repo bootstrapper
+
+Delta: 1
+
+Prompt:
+
```
Truncated: 1 further patch lines.

### /Users/mitch/dev/net-dns-monitor/requirements-dev.txt

```diff
diff --git a/requirements-dev.txt b/requirements-dev.txt
index 71bd822..86e6802 100644
--- a/requirements-dev.txt
+++ b/requirements-dev.txt
@@ -14,3 +14,3 @@ pytest==9.1.1
-ruff==0.16.8
-# Runs the same ruff via .pre-commit-config.yaml; `pre-commit install` once per clone.
-pre-commit==4.6.2
+ruff==0.16.9
+# Install pre-commit separately with pipx or uv tool, as documented in
+# .pre-commit-config.yaml; its environment is separate from the app's pins.
```
### /Users/mitch/dev/net-dns-monitor/router/scripts/install_persistent_nat.sh

```diff
diff --git a/router/scripts/install_persistent_nat.sh b/router/scripts/install_persistent_nat.sh
index 753cfa1..048355d 100755
--- a/router/scripts/install_persistent_nat.sh
+++ b/router/scripts/install_persistent_nat.sh
@@ -60,0 +61,6 @@ cat <<EOF > "$TMP_PLIST"
+    <!-- This installer only runs after the operator explicitly overrides retirement. -->
+    <key>EnvironmentVariables</key>
+    <dict>
+        <key>NDM_ROUTER_FORCE</key>
+        <string>1</string>
+    </dict>
```
### /Users/mitch/dev/net-dns-monitor/tests/conftest.py

```diff
diff --git a/tests/conftest.py b/tests/conftest.py
index 15d1ecf..380bf52 100644
--- a/tests/conftest.py
+++ b/tests/conftest.py
@@ -138,0 +139,4 @@ def no_real_keychain_or_distribution(monkeypatch):
+    # Synthetic incidents must never use credentials inherited from the shell.
+    # Credential tests set their own values after this fixture runs.
+    for name in ("SLACK_WEBHOOK_URL", "ANTHROPIC_API_KEY", "SMTP_PASSWORD"):
+        monkeypatch.delenv(name, raising=False)
```
### /Users/mitch/dev/net-dns-monitor/tests/test_app_ping_wiring.py

```diff
diff --git a/tests/test_app_ping_wiring.py b/tests/test_app_ping_wiring.py
index deb6c71..ffb5164 100644
--- a/tests/test_app_ping_wiring.py
+++ b/tests/test_app_ping_wiring.py
@@ -183,0 +184,2 @@ def test_the_ping_never_runs_on_the_run_loop(tmp_path):
+    release = threading.Event()
+
@@ -185 +187 @@ def test_the_ping_never_runs_on_the_run_loop(tmp_path):
-        time.sleep(10)
+        assert release.wait(timeout=5)
@@ -192,3 +194,4 @@ def test_the_ping_never_runs_on_the_run_loop(tmp_path):
-    started = time.monotonic()
```
Truncated: 72 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_app_status_wiring.py

```diff
diff --git a/tests/test_app_status_wiring.py b/tests/test_app_status_wiring.py
index 4de4860..3e46146 100644
--- a/tests/test_app_status_wiring.py
+++ b/tests/test_app_status_wiring.py
@@ -146,0 +147 @@ def test_resolution_tick_does_not_block_the_run_loop(tmp_path):
+    import threading
@@ -151,0 +153,2 @@ def test_resolution_tick_does_not_block_the_run_loop(tmp_path):
+    release = threading.Event()
+
@@ -153 +156 @@ def test_resolution_tick_does_not_block_the_run_loop(tmp_path):
-        time.sleep(10)
+        assert release.wait(timeout=5)
```
Truncated: 21 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_console_window.py

```diff
diff --git a/tests/test_console_window.py b/tests/test_console_window.py
index ac118d9..79d7303 100644
--- a/tests/test_console_window.py
+++ b/tests/test_console_window.py
@@ -198,0 +199,31 @@ def test_the_status_provider_is_passed_through(capsys):
+
+
+def test_actual_main_queue_failure_releases_busy_without_appkit_write(monkeypatch):
+    import sys
+    from types import SimpleNamespace
+
+    def unavailable():
```
Truncated: 24 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_dns_query.py

```diff
diff --git a/tests/test_dns_query.py b/tests/test_dns_query.py
index ca8e46e..51bfe5d 100644
--- a/tests/test_dns_query.py
+++ b/tests/test_dns_query.py
@@ -2,0 +3,2 @@ import struct
+import pytest
+
@@ -5,0 +8,124 @@ from netdnsmonitor.dns_query import PUBLIC_RESOLVERS, query_public_dns, query_pu
+def _wire_reply(packet, *, flags=0x8180, answers=b"", answer_count=0, question=None):
+    return (
+        struct.pack(">HHHHHH", int.from_bytes(packet[:2], "big"), flags, 1, answer_count, 0, 0)
+        + (packet[12:] if question is None else question)
```
Truncated: 140 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_failover.py

```diff
diff --git a/tests/test_failover.py b/tests/test_failover.py
index 6f3b64c..c62d4cf 100644
--- a/tests/test_failover.py
+++ b/tests/test_failover.py
@@ -1689,0 +1690,41 @@ def test_failover_refuses_to_be_built_without_a_store_or_a_prober():
+
+
+def test_failed_persistence_is_logged_without_error_contents(tmp_path, monkeypatch, caplog):
+    import logging
+
+    from netdnsmonitor import failover as module
+
```
Truncated: 34 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_interface_probe.py

```diff
diff --git a/tests/test_interface_probe.py b/tests/test_interface_probe.py
index a26fde6..f4257ad 100644
--- a/tests/test_interface_probe.py
+++ b/tests/test_interface_probe.py
@@ -286,0 +287,99 @@ def test_no_budget_at_all_is_none_not_false():
+
+
+def test_a_numeric_ipv4_target_uses_the_family_returned_by_the_os(monkeypatch):
+    import socket
+
+    from netdnsmonitor.interface_probe import default_bound_connect
+
```
Truncated: 92 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_notifications.py

```diff
diff --git a/tests/test_notifications.py b/tests/test_notifications.py
index e909704..2a03510 100644
--- a/tests/test_notifications.py
+++ b/tests/test_notifications.py
@@ -396,0 +397,9 @@ def test_email_notifier_closes_the_socket_when_quit_itself_fails():
+
+
+def test_slack_rejection_cannot_echo_webhook_credential():
+    secret = "https://hooks.example.test/services/private/token"
+    notify = make_slack_notifier(secret, post_fn=lambda *args: (200, "error " + secret))
+    result = notify("synthetic incident")
+    assert "error" in result
```
Truncated: 2 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_peers.py

```diff
diff --git a/tests/test_peers.py b/tests/test_peers.py
index 1dd59d9..b6c502f 100644
--- a/tests/test_peers.py
+++ b/tests/test_peers.py
@@ -645,0 +646,16 @@ def test_buckets_hand_out_copies_not_the_live_entries():
+
+
+def test_a_fresh_unknown_peer_reading_clears_historical_health():
+    registry = make_registry()
+    registry.observe("peer", address="192.168.1.2", external_reachable=True, dns_ok=True)
+    registry.observe("peer", address="192.168.1.2", external_reachable=None, dns_ok=None)
+    peer = registry.localization_view()[0]
```
Truncated: 9 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_ping.py

```diff
diff --git a/tests/test_ping.py b/tests/test_ping.py
index 13b44d8..7ed6e06 100644
--- a/tests/test_ping.py
+++ b/tests/test_ping.py
@@ -72,3 +72,2 @@ def test_sends_exactly_one_echo_request_and_bounds_the_run():
-    # The subprocess timeout is the last line of defence for a ping that
-    # ignores -t; it has to sit just above -t, not be unset.
-    assert kwargs["timeout"] == 5
+    # The subprocess also bounds fractional slices in the heartbeat's budget.
+    assert kwargs["timeout"] == 3.0
@@ -86 +85 @@ def test_sub_second_timeout_still_gets_at_least_one_second_of_t():
-    assert kwargs["timeout"] == 3
```
Truncated: 1 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_prober.py

```diff
diff --git a/tests/test_prober.py b/tests/test_prober.py
index 4f457be..83af91e 100644
--- a/tests/test_prober.py
+++ b/tests/test_prober.py
@@ -260,0 +261,10 @@ def test_a_connect_fn_that_raises_is_not_reported_as_unreachable():
+
+
+def test_resolution_worker_error_is_not_a_dns_failure():
+    from netdnsmonitor.prober import resolve_all
+
+    def bad_lookup(domain, timeout):
+        raise UnicodeError("invalid DNS label")
```
Truncated: 3 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_repair_executor.py

```diff
diff --git a/tests/test_repair_executor.py b/tests/test_repair_executor.py
index 0e4cecb..32f4378 100644
--- a/tests/test_repair_executor.py
+++ b/tests/test_repair_executor.py
@@ -403 +403 @@ def test_check_default_route_shells_out_to_netstat():
-    assert calls == [[NETSTAT, "-rn", "-f", "inet"]]
+    assert calls == [[NETSTAT, "-rn", "-f", "inet"], [NETSTAT, "-rn", "-f", "inet6"]]
@@ -504 +504 @@ def test_an_unreachable_public_resolver_is_not_reported_as_a_failed_name():
-    assert outcome.startswith("could not reach the public resolver")
+    assert outcome.startswith("could not obtain a usable public resolver result")
@@ -617,0 +618,31 @@ def test_a_failover_that_raises_is_reported_as_failed_not_raised():
+
```
Truncated: 30 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_resolution_log.py

```diff
diff --git a/tests/test_resolution_log.py b/tests/test_resolution_log.py
index 29a40c8..85b4d77 100644
--- a/tests/test_resolution_log.py
+++ b/tests/test_resolution_log.py
@@ -145,0 +146,14 @@ def test_one_checked_at_is_shared_by_every_record_in_a_batch(tmp_path):
+
+
+def test_compaction_preserves_stall_after_invalid_nan_record(tmp_path):
+    from netdnsmonitor.resolution_log import _compact
+
+    path = tmp_path / "resolution.jsonl"
+    findings = [
```
Truncated: 7 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_router.py

```diff
diff --git a/tests/test_router.py b/tests/test_router.py
index 6a151b5..6f118ed 100644
--- a/tests/test_router.py
+++ b/tests/test_router.py
@@ -375,0 +376,16 @@ def test_a_raising_runner_does_not_strand_the_lock():
+
+
+@pytest.mark.parametrize(
+    "updates",
+    [
+        {"lan_ip": "192.168.10.0"},
+        {"lan_ip": "192.168.10.255"},
```
Truncated: 9 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_router_scripts.py

```diff
diff --git a/tests/test_router_scripts.py b/tests/test_router_scripts.py
index 95d9459..cf3a683 100644
--- a/tests/test_router_scripts.py
+++ b/tests/test_router_scripts.py
@@ -224,0 +225,4 @@ def test_the_fresh_install_domains_warning_matches_the_shipped_config():
+
+
+def test_forced_install_preserves_override_for_scheduled_helper():
+    assert _daemon_plist()["EnvironmentVariables"]["NDM_ROUTER_FORCE"] == "1"
```
### /Users/mitch/dev/net-dns-monitor/tests/test_router_window.py

```diff
diff --git a/tests/test_router_window.py b/tests/test_router_window.py
index ddaea23..a8860ec 100644
--- a/tests/test_router_window.py
+++ b/tests/test_router_window.py
@@ -562,0 +563,22 @@ def test_the_legacy_config_keyword_still_constructs(tmp_path):
+
+
+def test_failed_save_leaves_live_router_unchanged_and_refuses_start(tmp_path):
+    router = FakeRouter()
+    router.lan_ip = "192.168.10.2"
+    ctrl, lines = controller(router=router)
+    ctrl.on_start(VALUES)
```
Truncated: 15 further patch lines.

### /Users/mitch/dev/net-dns-monitor/tests/test_throughput.py

```diff
diff --git a/tests/test_throughput.py b/tests/test_throughput.py
index b4d6e25..100215d 100644
--- a/tests/test_throughput.py
+++ b/tests/test_throughput.py
@@ -7,0 +8 @@ import socket
+import threading
@@ -126 +127,3 @@ def test_meter_resolves_once_and_shares_every_family_across_interfaces():
-    meter = make_throughput_meter(host="h", timeout=4.0, measure_fn=capture, resolve_fn=resolve)
+    meter = make_throughput_meter(
+        host="h", timeout=4.0, measure_fn=capture, resolve_fn=resolve, clock=FakeClock()
+    )
@@ -145,0 +149,92 @@ def test_a_failed_lookup_lets_the_measurement_retry_inside_its_own_budget():
```
Truncated: 115 further patch lines.


Added artifacts at report creation:

- /Users/mitch/dev/net-dns-monitor/docs/llms/filemap.json
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-facts.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-filemap.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-full.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-history.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-indexes.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-infra.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms-small.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/llms.txt
- /Users/mitch/dev/net-dns-monitor/docs/llms/manifest.json
- /Users/mitch/dev/net-dns-monitor/docs/repo-bootstrap-audit-2026-10-04.md
- /Users/mitch/dev/net-dns-monitor/scripts/check_docs.py
- /Users/mitch/dev/net-dns-monitor/scripts/generate_static_dossier.py
- /Users/mitch/dev/net-dns-monitor/tests/test_check_docs.py

## Deterministic convergence check

The shared convergence_check.py compared failover.py before/after the final remediation batch: STABLE-REWRITE, edit-distance ratio 0.0138, Medium+ 6 to 3, introduced 0 and closed 3. This is a file-specific edit ratio, not a repository-wide metric. The first whole-repository character comparison was stopped after 160 seconds without output because the helper uses a costly character-level SequenceMatcher; no result was inferred from it. Existing blocked rows prevent a CLEAN claim.

## Run summary

2 structural iterations · 18 active passes (partial coverage disclosed) · repo profile · final C/H/M: 0/0/3 · Verify PASS (remote CI required before merge) · Status CONVERGED with three existing intent constraints. Bootstrap desktop implementation verified; deep dossier coverage remains partial.

## Snapshot and rollback

Snapshot: /Users/mitch/.claude/skill-consolidation/backups/code-deep-optimizer-net-dns-monitor-20261004-165400. Iteration source copies and run-stub.jsonl preserve continuation. To restore one tracked file from the pre-run snapshot (does not delete newly added artifacts):

```bash
cp /Users/mitch/.claude/skill-consolidation/backups/code-deep-optimizer-net-dns-monitor-20261004-165400/netdnsmonitor/dns_query.py /Users/mitch/dev/net-dns-monitor/netdnsmonitor/dns_query.py
```
