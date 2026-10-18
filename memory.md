# Work Memory

Versioned operator log: active task, completed work, next steps. Newest last.
Record facts with evidence; correct earlier entries in a later version rather
than rewriting them.

## v1 - 2026-09-01 - Router NAT reboot recovery

Delta: 1

What was done:
- Inspected `router/scripts` and `router/docs/ROUTER.md`.
- Confirmed the router interface `en15` has `192.168.4.1`, upstream default route is `en13`, `net.inet.ip.forwarding` is enabled, and dnsmasq/Unbound are running.
- Reapplied NAT with `router/scripts/enable_nat.sh` using macOS administrator privileges.
- Verified PF reported `nat on en13 inet from 192.168.4.0/24 to any -> (en13)` and `Status: Enabled` during the repair run.
- Updated `router/scripts/install_persistent_nat.sh` so the LaunchDaemon re-runs every 60 seconds and writes stdout/stderr logs under `/var/log`.
- Reinstalled `/Library/LaunchDaemons/com.custom.router.nat.plist` from the updated installer.
- Verified launchd loaded the job with `StartInterval = 60`, last exit code `0`, and log paths configured.
- Verified local DNS with `dig @192.168.4.1 google.com +short +time=2 +tries=1`.

Remaining steps:
- Client systems may need DHCP renewal, reconnect, or reboot if they cached a bad lease while NAT was down.
- If routing breaks again, inspect `/var/log/com.custom.router.nat.err.log` and `/var/log/com.custom.router.nat.out.log`.

## v2 - 2026-09-14 - Deep code optimization, repo standard, Mac App Store preparation

Delta: 1

Correction to v1:
- The installer edit v1 describes never reached the repository. On 2026-09-14 neither the tracked `router/scripts/install_persistent_nat.sh` nor the main checkout's copy contained `StartInterval` or the `/var/log` paths. The installed daemon had them. Branch `feat/appstore-prep` restores both in the installer.

What was done (branch `feat/appstore-prep`, worktree `.claude/worktrees/appstore-prep`):
- **Deep code optimizer.** Three audit-and-fix iterations plus two blind re-audit gates. The suite went from 1098 to 1878 tests. The second blind gate still reported 1 High and 4 Medium; those were fixed afterwards but not re-audited by a third blind pass (cdo status BLIND-AUDIT-DISSENT). Owner decisions are recorded in `docs/known-issues.md`.
- **Security fixes:**
  - The router no longer runs a root script from `/tmp`.
  - The NAT LaunchDaemon installer now copies the script to a root-owned path.
  - SMTP STARTTLS now verifies certificates.
  - Redaction now covers dict keys.
  - Escalation errors no longer echo exception messages.
- **Mac App Store preparation:**
  - Added `distribution.py` (sandbox capability gating), `credentials.py` (Keychain) and `ai_consent.py` (Guideline 5.1.2(i)).
  - Added `scripts/appstore/` (build, icon, sandbox probe), `packaging/appstore/` entitlements, and `docs/APP_STORE_SUBMISSION.md` / `docs/PRIVACY_POLICY.md`.
- **Sandbox measurements** (ad-hoc build, macOS 26):
  - Work: ping, networksetup read, scutil, netstat, route, `IP_BOUND_IF`, UDP DNS, HTTPS, Keychain.
  - Refused: `log show` ("Cannot run while sandboxed").

Security action still needed on this machine (it cannot be fixed from the repo):
- The installed `/Library/LaunchDaemons/com.custom.router.nat.plist` runs `enable_nat.sh` as root from the user-owned checkout. Any process running as the user can edit that script and gain root. Re-run the fixed `router/scripts/install_persistent_nat.sh` with sudo, which installs a root-owned copy under `/Library/PrivilegedHelperTools/net-dns-monitor/`.

Remaining steps:
- Decide which router stack is canonical: `router.py` (bootpd) or `router/` (dnsmasq/unbound).
- Run the release build with real Apple certificates and submit (see `docs/APP_STORE_SUBMISSION.md`).
- Launch the sandboxed GUI build by hand once, and press Cmd-V in Credentials > Set Anthropic API key. Automation cannot do either.
- Merging this branch to master changes the live resolver: /opt/homebrew/etc/unbound/unbound.conf and dnsmasq.conf are symlinks into the main checkout, so the narrowed unbound access list and `username: "nobody"` apply at the next unbound restart.
- Inspect the older `/etc/sudoers.d/net-dns-monitor` (2026-08-19) with `sudo cat`; it predates the current grant code.

## v3 - 2026-09-14 - Owner decisions applied

Delta: 1

Owner answers to the seven open questions, and what was done:
- **Reinstall the NAT LaunchDaemon: yes.** It needs the owner's sudo password, so the owner runs `sudo router/scripts/install_persistent_nat.sh` from the merged master checkout.
- **Merge `feat/appstore-prep` into master: yes.** The background session is not allowed to merge. The owner fast-forwards master after moving 17 untracked stub files out of the way. The branch tracks newer versions of all of them.
- **Router stacks: keep both.** Recorded under "Decided" in `docs/known-issues.md`. The app's router still refuses to run while the `router/` LaunchDaemon is installed.
- **App Privacy label: conservative.** Diagnostics → Other Diagnostic Data and Other Data → Other Data Types, not linked, no tracking, App Functionality.
- **Export compliance: exempt.** The release command now always passes `--declare-exempt-encryption`.
- **Gateway failback: fixed.** A manual switch to a backup pauses automatic failback (persisted `failback_paused` in `failover.json`) until a manual switch back or the order returns to preferred. The misleading refusal reason is reworded.
- **Old sudoers file: inspect.** Also needs the owner's sudo password (`sudo cat /etc/sudoers.d/net-dns-monitor`).

Test count: 1878.

## v5 - 2026-10-04 - macOS networking expertise

Delta: 1

What was done:
- Loaded the macOS networking reference from `/Users/mitch/.claude/skills/devops-linux-admin/references/macos-networking.md` and the DNS reference from `/Users/mitch/.claude/skills/networking/references/dns-deep-dive.md`, after reading their migrated skill entrypoints.
- Read `/Users/mitch/dev/net-dns-monitor/CLAUDE.md` and focused Stele recall on macOS, DNS, mDNSResponder and interface-bound probing. Tracking task: TASK-374. Scope decision: KNOW-375.
- Checked Apple guidance on Local Network privacy and IPv6 DNS64/NAT64. Sources: https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy and https://developer.apple.com/support/ipv6/.
- Prepared to distinguish system DNS from direct DNS queries, configured state from observed connectivity, IPv4 from IPv6 failures, VPN routing from physical-link faults, and permission failures from network outages.
- Recorded the exact prompt. No runtime code or host network settings changed. Existing unrelated edits in the main checkout were preserved by using an isolated worktree.

Continuation:
- This was a learning request, not a live diagnosis. No particular network fault was supplied or reproduced.
- For a later diagnosis, collect evidence from the affected process and actual destination. Treat version-sensitive reference claims as leads to verify, not live measurements.
- Do not claim mastery or live validation from reading documentation. Existing project verification gaps remain as described in the project instructions.

Remaining requested steps: none after committing and publishing these records.

## v4 - 2026-09-17 - App Store readiness pass

Delta: 1

What was done (branch `feat/appstore-prep`):
- Merged `master` (c31d044) into the branch (`a78fa0f`): the semantic-index scripts, `config.example.yaml` and the doc stubs arrived; `AGENTS.md` stayed the pointer (master's copy was a stale CLAUDE.md duplicate); the file index kept this branch's entries plus master's three router files. The four indexer scripts were then brought under the ruff gate.
- `setup.py` now declares `NSLocalNetworkUsageDescription` for every build: macOS 15+ gates the peer broadcast and the gateway probe behind the Local Network permission (Apple TN3179). `build_appstore.py` refuses a bundle whose Info.plist lacks that key, the bundle id, either version string, the category or the minimum system version, and gained `--icon <designed.icns>` with an ICNS element check (ic09/ic10). Six tests added; 1884 total.
- Verified on this Mac (macOS 27.0, Xcode 27.0): 1884 tests pass in 22 s; ruff clean; ad-hoc sandboxed build succeeds (58 MB, arm64, minimum macOS 26.0, signature valid, three entitlements, no `itms-services`); the probe run inside the bundle matches the 2026-09-14 table exactly (`log show` and the real `~/.config` refused, everything else works).
- Facts re-checked against Apple: `altool` 27.0.5 still documents `--upload-package`; 5.1.2(i) names third-party AI; the privacy-manifest rule and the 2026-04-28 Xcode 26 SDK floor do not name macOS; quarantine attribute rule since 2025-02-18; age-rating questionnaire changed 2026-01-31; EU DSA trader status required.
- Team ID is `L9ELX85ZFD` (OU field of the Apple Development certificate; the Xcode template in the main checkout agrees). This Mac still has no Apple Distribution or Mac Installer Distribution certificate, so release mode remains unrun.
- Wrote `docs/APP_STORE_CHECKLIST.md`: verified state, owner-only steps in order with the release command filled in, manual GUI checks, metadata sections, open non-blocking items.

Remaining steps (owner):
- Steps 0 to 9 of `docs/APP_STORE_CHECKLIST.md`: bundle id, paid membership check, certificates and profile, hosting the privacy policy (repo is private, so not this repo's Pages), the manual sandboxed-GUI checks, the release build, upload, metadata, submit.
- Merge to `master` after approval, minding the resolver symlinks.

## v6 - 2026-10-04 - Reconcile and publish pending work

Delta: 1

Committed the nine pending ICMP fallback changes before merging remote master. Preserved IPv6-first heartbeat behavior and integrated the additional fallback target into the shared heartbeat path. Kept all failed-target reasons in diagnostics. Blank or null disables the fallback. Preserved the newer App Store response and remote changes. Tracking: TASK-376; scope decision: KNOW-377.

Validation: lint and format checks passed; all 2150 offline tests passed. Updated test counts. Publication and final CI status are recorded in TASK-376. Use a merge commit to retain both histories and allow master to fast-forward. No further product changes are required. No live GUI or network behavior has been verified in this session.

CI found a pre-existing console test race (tests/test_console.py:535, assert 1 == 3). Track newly created thread identities instead of requiring a global count to stay equal. This keeps the no-leaked-reader check while allowing unrelated threads to finish.

## v7 - 2026-10-04 - Networking review, code optimizer and repo bootstrapper

Delta: 2

Completed the five audit groups, 18 active passes with disclosed partial coverage, two remediation iterations, desktop bootstrap implementation and two fresh-context reviews. Tracking: TASK-379; substeps TASK-389 through TASK-393. Baseline b8672f1, branch fix/macos-networking-audit. The report docs/macos-networking-audit.md records 28 fixed findings, scopes, primary sources, capped diffs, regression red gates and three existing architectural residuals. docs/repo-bootstrap-audit-2026-10-04.md records the desktop manifest pass.

Fixed DNS answer validation and both-family route evidence, bound address-family selection, fresh peer unknown state, DHCP reserved ranges, Slack response secrecy, resolver worker exceptions, daemon override persistence, save observability, GUI queue/class lifetime, router save/start ordering, compaction NaN semantics, probe budgets/cache races and failback honesty. Isolated inherited test credentials and released orphan test workers. Corrected native/direct DNS, NAT64, console and dated-release guidance. Added static path/census/output/count checks in CI, 106 high-signal paths and a 221-path shallow dossier with 10 outputs. Deep content cards remain partial; no semantic index/Ollama activity occurred.

Verification: baseline2150pass; final2203pass in26.56s using a clean Python3.13.12 environment and constrained runtime/dev/build packages. Ruff0.16.9 lint/format, bash syntax, git diff --check and check_docs --collect-tests pass. Second independent review:498focusedtests pass and no new Medium+ regression. Existing .venv was left intact (Python3.14.7 / Ruff0.16.1 differed from repo pins). The clean environment exposed missing httpx2/httpcore2/truststore constraints and the Objective-C class bug; both were fixed. Deterministic final failover comparison reported STABLE-REWRITE (ratio0.0138); final optimizer status CONVERGED with3blockedintentrows, not CLEAN.

Publication: green Dependabot Ruff PR29 merged as9a74be7; red Dependabot PR28 is excluded by the green-bot sweep limit and its independent pydantic-core pin conflicts with the paired pydantic constraint. Commit/push/CI/merge/sync completion is recorded in TASK-393 and the resulting PR receipt. No force push or host network mutation is authorized by these changes.

Remaining follow-up choices: redesign GUI incident ordering, cancellable/bounded resolver workers, stalled-domain seeding/rotation and retention policy. TASK-335 now records implemented compaction and its remaining domain-cardinality bound. Actual GUI, NAT64-only, permission, privileged and alert-delivery acceptance remain unverified. The optional local Chroma dependency has reachability-qualified HTTP-server advisories; its transitive closure was not completely audited. Holdout graphs26cases is below empirical minimum30; no quality/benchmark gain or auto-promotion claimed.

Snapshot and isolated verification env: /Users/mitch/.claude/skill-consolidation/backups/code-deep-optimizer-net-dns-monitor-20261004-165400. Source snapshots, .iter1/.iter2 and run-stub.jsonl preserve continuation. Requested code/doc work is complete; task/PR records hold final publication state.

## v8 - 2026-10-04 - Repo bootstrapper convergence pass

Delta: 1

Active task: TASK-405. Re-audit after the v7 pass (PR #33, 1313b89) against the
repo-bootstrapper checklist. Baseline gate green: ruff clean, 2203 tests pass,
`check_docs.py --collect-tests` passes.

Gaps found: `.github/copilot-instructions.md` lacks the checklist's commands,
architecture and conventions sections and the no-invention and workflow-log
rules; `CLAUDE.md` lacks `Repository shape` and `Commands`; no workflow-log
rotation tool exists. Out of scope (KNOW-275, KNOW-380): operations registry,
tool inventory, CODEOWNERS, editor workspace files, `.mcp.json`,
CODE_OF_CONDUCT. No code-deep-optimizer or crawl rerun: v7 converged today and
no source changed since.

Remaining steps: add the sections, add `scripts/rotate_workflow_logs.py` with
tests, update the ledger and test counts, run the gate, commit and push.

Completed (v8): added the copilot-instructions and CLAUDE.md sections, the
rotation script with six tests, test counts (2209), index/overview/SCRIPTS rows,
a regenerated static dossier (223 cards) and the ledger re-audit section.
Verification: Ruff lint/format clean, 2209 tests pass, `check_docs.py
--collect-tests` passes, `git diff --check` clean. Remaining: commit and push.

## v9 - 2026-10-04 - MCP self-test and Dependabot PR #28

Delta: 1

Owner answers to v8 questions: add the MCP `--self-test` flag; resolve PR #28's
conflicts and merge it (this replaced the earlier "close it" answer).
`scripts/mcp_server.py --self-test` lists tools through FastMCP `list_tools()`
(present in both the local 3.2.4 and the pinned 4.0.10) without serving; three
offline tests use a fake FastMCP. Tests: 2212.

Follow-up (v9): owner chose to close PR #28 and ignore `pydantic-core` in
`.github/dependabot.yml`; it moves by hand with `pydantic` (KNOW-407).

## v10 - 2026-10-05 - Code deep optimizer, second run

Delta: 1

Active task: TASK-408. Second code-deep-optimizer run. The v7 run grouped files
into five bundles and deep-read 33 modules; this run fans out per file over a
50-file triage set led by the files v7 did not deep-read. Three BLOCKED
residuals (`_tick` pipeline, uncancellable resolver workers, stall_log
seeding) stay out of scope. Snapshot of HEAD 6b1280c: /Users/mitch/.claude/skill-consolidation/backups/code-deep-optimizer-net-dns-monitor-20261005-000312.
Verify gate: `ruff check .`, `ruff format --check .`, `pytest -q`,
`scripts/check_docs.py --collect-tests`. Empirical mode off (no reserved
held-out eval set). Remaining: collect findings, verify, fix, gate, report, ship.

Completed (v10): 35 diagnostic units over 52 files, 10 fix agents over disjoint
file sets, then a fresh review of the fix diff (round 2: 7 Medium, all fixed).
Iteration 1 raised 8 High and 133 Medium rows (about 8 duplicates); all fixed or
retracted except 6 BLOCKED owner decisions listed in
`docs/code-deep-optimizer-2026-10-05.md`. Also fixed: the test suite posted real
"network failed" notifications (conftest now stubs `rumps.notification`, KNOW-409).
Verification: ruff clean, 2521 tests pass, check_docs passes, bash -n clean,
notification leak recorder 0. Status CONVERGED (not CLEAN: BLOCKED rows remain).
Remaining: commit, push, CI.

## v11 - 2026-10-05 - Owner decisions on the optimizer's open questions

Delta: 1

Active task: TASK-416. Strip credentials from console children; `netdns ladder`
partial exit code; app router start uses `launchctl load -F` so bootpd is never
persistently enabled (DHCP opt-in); Settings restart note compares normalized
values (screenshot showed 62 false "restart" keys) and fits its label. Decision 1
(connection refused = reachable) awaits an explanation to the owner. Live boot-time
DHCP services (homebrew.mxcl.dnsmasq, com.apple.bootpd overrides enabled) need sudo;
commands go to the owner.

Completed (v11): console strips credentials; `netdns ladder` exits 3 for
partial/unknown/NOT_AUTOMATED (1 still wins for a hard failure); router start uses
`launchctl load -F`; Settings note names 4 keys plus a count, bigger label,
tooltip. The 62-key report was the Sep 17 `dist/` build (predates the
changed-keys comparison); current code finds 0 changes against the real config.
Verification: ruff clean, 2529 tests pass. Remaining: commit, push, CI; owner
runs the sudo commands to disable boot-time dnsmasq/bootpd/NAT daemons.

## v12 - 2026-10-05 - Connection refused counts as reachable

Delta: 1

`prober.default_connect` and `interface_probe.default_bound_connect` return True
on ConnectionRefusedError (an RST is the target answering). Verified read-only:
`launchctl print-disabled system` shows homebrew.mxcl.dnsmasq, com.apple.bootpd
and com.custom.router.nat disabled; no dnsmasq/bootpd process. 2532 tests pass.

## v13 - 2026-10-17 - Apple rejection audit (TASK-417)

Delta: 1

Active task: TASK-417 (claimed by the parent session). Agent: apple-review-rejection-auditor.
Constraints: no upload, submit, altool, Transporter, App Store Connect or message to
Apple; no GUI launch; CLAUDE.md non-negotiables 1-10 bind every fix; never obfuscate
code to pass a scan (2.5.19); commit to master and push, never force-push.
Plan: walk catalog 3A/3B/3C against a fresh store bundle build, then an adversarial
pass; fix repo-owned FAILs with the smallest change; run the CI gate and
`scripts/check_docs.py --collect-tests`; commit only this session's files.
Starting state: HEAD abc9cd2, clean tree.

Completed (v13, commit 1): built the store bundle (`build_appstore.py adhoc`, 97 MB) and walked
catalog 3A/3B/3C against it. Fixed: the bundle shipped the shell console, router and `netns`
CLI modules (2.5.19/2.4.5(v)); `prune_store_bundle` now deletes them and a bundle-interpreter
import check proves the rest still imports (app.py imports became function-level); a
valid `PrivacyInfo.xcprivacy` (the build applies the TN3181 invalid cases; an EMPTY
required-reason array is invalid); `NSLocalNetworkUsageDescription` names what triggers the
prompt; consent text v2 names interface names, IP addresses, router/DNS addresses and search
domains (the step outcomes are raw `scutil`/`netstat` output); heartbeat ends with
`ping_host_name` (`dns.google`) over ping6 for IPv6-only NAT64 networks (2.5.5); setup.py
excludes 28 unused third-party/stdlib packages (97 MB to 64 MB, funding strings gone);
review Notes, reply, policy and submission docs rewritten to match. Found, not fixed: the
hosted privacy policy is stale and its site nav carries a funding link (other repo);
`NSUserNotificationCenter` is still deprecated tech; `privileges.py`/`repair_executor.py`/
`failover.py` still ship dormant (disclosed in Notes); LSMinimumSystemVersion is now 27.0
(Homebrew Python is built for macOS 27; GA 2026-09-14). Another session (TASK-418) is editing
repair_executor, app.py and the build script for editable remediation scripts: its store
gating must keep `remediation_editor` off and the scripts directory out of reach
(Guideline 2.5.2). Verification: isolated worktree at HEAD plus these hunks, ruff clean,
2559 passed, check_docs passes.

Commit 2 (docs): the live listing's description bullet "bound to each network interface"
describes a feature the store edition lacks (interface probing serves only failover and the
CLI), so the owner edits it in App Store Connect; Notes wording for "Refresh network
status" fixed; the Support page's Local Network paragraph is stale and its site navigation
links /donate/ (both in the llms-explorer repo, owner action). Gate-1 checks that need no
credentials passed: entitlements per Mach-O (sandbox, plus inherit on the helper), no
`._*`, no private symbols, `codesign --verify --strict`, profile decoded offline (team,
app id and Apple Distribution certificate match, expires 2027-09-27). Open: NAT64 run,
`altool --validate-app`, GUI launch, Local Network prompt, notification banner, macOS 26 floor.


## v14 - 2026-10-17 - Editable remediation scripts and in-app IDE (TASK-418)

Delta: 1

Active task: TASK-418 (Stele). Decision: KNOW-419.
Constraints: CLAUDE.md non-negotiables 1-10; no GUI launch (window is a thin shell,
logic lives in an offline-testable module); App Store build runs bundled built-ins
only (no overrides, custom scripts or editor, Guideline 2.5.2); another session has
uncommitted edits in app.py, setup.py, scripts/appstore/build_appstore.py and three
test files, so stage only this task's hunks.
Plan: (1) `builtin_remediations/*.py`, one documented script per ladder step, run with
an injected `ctx`; (2) `remediation_scripts.py` store/loader/runner; (3)
`make_repair_executor` dispatches through it with identical outcome strings; (4)
custom steps join `ladder_for`; (5) `remediation_editor.py` logic + `remediation_window.py`
shell, menu and dashboard entry; (6) store bundle prune + package data; (7)
`docs/REMEDIATION_SCRIPTS.md`, tests, counts.
Done: all seven plan items. Gate (clean tree of this task alone): ruff check and format
clean, 2617 tests pass, `check_docs.py --collect-tests` passes. Headless AppKit smoke
run of the editor window built it, checked, saved, and ran a script (it caught a real
bug: a helper method on the NSObject subclass was read as a selector).
Store bundle check (2026-10-17, `build_appstore.py adhoc`, exit 0, ad-hoc signed): the editor
and window modules were pruned, `remediation_scripts.py` and all nine `remediations/*.py` are in
the bundle, and the pruned bundle imports. The editor window has not been used by hand in the
menu-bar app (cannot be automated); the owner runs that click-through.
The store bundle's `exec(compile(...))` in `remediation_scripts.execute` runs bundled,
signed built-ins only; a 2.5.2 reviewer scanning for `exec` may ask.

## v15 - 2026-10-17 - Liquid Glass UI, dropdowns, tooltips, full settings (TASK-422)

Delta: 1

Active task: TASK-422 (Stele). Constraints: CLAUDE.md non-negotiables; AppKit windows stay
thin shells, decisions live in offline-testable modules; no launch of the menu-bar app; the
store build keeps hiding gated actions; NSGlassEffectView exists here (macOS 27.2, PyObjC
12.2.2) but falls back to NSVisualEffectView; master may move under another session, so land
with `git update-ref` and the old value.
Done: click-through steps saved as `docs/runbooks/remediation-editor-click-through.md`.
Plan: (1) read dashboard/settings/mini/router/editor windows and config keys; (2) shared
`glass.py` helper (material, fallback, tooltips contract); (3) group dashboard actions into
pull-down menus by category, keeping gating; (4) tooltips everywhere + test that walks every
control; (5) settings fields for every config key + test; (6) docs, counts, gates.
Done: all six plan items. `ui_catalog.py` (tips, dashboard groups, app-options row spec),
`ui_style.py` (glass with vibrancy fallback, `tip`, tooltip walker), dashboard actions in
five pull-down menus (Checks, Repairs, Tools, Reports, Permissions) with two buttons,
tooltips on every control of every window, Settings row for non-config options, three new
config keys (`remediation_scripts_dir`, `custom_remediation_scripts_enabled`,
`remediation_script_timeout_seconds`), `docs/USER_INTERFACE.md`. Gate: ruff clean, 2678
tests pass, check_docs passes. Headless screenshots of the dashboard and Settings checked
(windows were not key, so button text looks dim there).
Open: nobody has looked at the glass in the running app or used the menus by hand; the
dashboard graph area was empty in the screenshots (no history fed), so graph appearance on
glass is unchecked; the console and mini windows are checked only by a smoke script.

## v16 - 2026-10-17 - Alerts move to UserNotifications (TASK-424)

Delta: 1

Active task: TASK-424 (Stele). Constraints: CLAUDE.md non-negotiables 3-5; `requirements.txt` stays at four packages (no `pyobjc-framework-UserNotifications`, verified absent from the venv, so the framework loads through `objc.loadBundle`); the menu-bar app is not launched; real banner delivery is not claimed.
Done: new `netdnsmonitor/user_notify.py` (`post` returns `queued`, `denied`, `no-bundle`, `unavailable` or `failed:<Class>`; authorization is asked once per launch, the first banner is held until the answer; `backend_fn` and `bundle_fn` are injected). `alert.notify` calls it through an injectable `post_fn`, falls back to `osascript` only for `no-bundle`, `unavailable`, `failed:*` and never for `denied` or in the store build. Every `rumps.notification` call in `app.py` now goes through `alert.notify`/`App._notify`. `tests/conftest.py` stubs `user_notify.post`, the loader and the bundle probe for all tests except `test_user_notify`. Docs updated (known-issues, review response, submission, COMPONENTS, external-calls, counts).
Measured: under Homebrew framework `python3`, `NSBundle.mainBundle()` reports `org.python.python` at `.../Python.app`, so identifier plus `.app` is not enough; `has_app_bundle` rejects the interpreter's bundle. `objc.loadBundle` of the system framework works and content/request objects build; the center itself was deliberately not called outside a bundle.
Gate: ruff clean, 2700 tests pass, check_docs passes.
Open (UNVERIFIED): the `requestAuthorizationWithOptions:` and `addNotificationRequest:withCompletionHandler:` block metadata registered by hand in `load_backend` has never run against the real center; authorization prompt, banner, and denied path need the signed app. Owner check: build the app, click **Test network alert**, expect the permission prompt, then a banner after Allow; after Don't Allow expect no banner and `notification authorization denied` in `~/Library/Logs/net-dns-monitor.launchd.log`.

## v17 - 2026-10-17 - Support macOS 26 in the store build (TASK-423)

Delta: 1

Active task: TASK-423 (Stele). Constraints: CLAUDE.md non-negotiables; install nothing
system-wide (temp venv only); no upload, no App Store Connect, no GUI launch; never claim a
minos that was not read with `vtool`; plist floor, productbuild and every Mach-O minos must
agree (ITMS-90264); avoid `netdnsmonitor/alert.py` (another session).
Plan: (1) measure minos of Homebrew Python vs uv python-build-standalone 3.14.7; (2) build the
bundle from a temp venv on the standalone interpreter; (3) survey every Mach-O; (4) adapt
`build_appstore.py` (non-framework layout, floor 26.0, gate) and `setup.py`; (5) docs, tests,
gates, commit, push.
Finding so far: uv's standalone 3.14.7 reports `minos 11.0`; py2app 0.28.10 bundles it as a
non-framework `libpython3.14.dylib` but crashes on `zlib.__file__` (zlib is built in).
Done: option (a) worked. uv python-build-standalone 3.14.7 (minos 11.0) in a temp venv; py2app
0.28.10 bundles it as `Frameworks/libpython3.14.dylib`. `setup.py` shims py2app's
`zlib.__file__` copy; `build_appstore.py` finds libpython, writes `SUPPORTED_MACOS` 26.0 as
the plist floor and refuses any Mach-O above it (`minimum_system_version`, 2 new tests).
Ad-hoc bundle: 15 Mach-O, highest minos 26.0 (two rebuilt launchers), interpreter/libpython
11.0, extensions 10.15/11.0; plist 26.0; codesign strict deep valid; `productbuild
--synthesize` gives `os-version min="26.0"`; probe not run. Gate: ruff clean, 2680 tests,
check_docs passes. Docs updated (SUBMISSION s4/4.3, CHECKLIST, REVIEW_RESPONSE, SCRIPTS,
INSTALLATION). `.venv-store/` gitignored.
Open (owner only): launch on a real macOS 26 Mac; `altool --validate-app` on a package built
from `.venv-store`; the app uses NSGlassEffectView (macOS 26) with a vibrancy fallback, not
exercised on 26.
