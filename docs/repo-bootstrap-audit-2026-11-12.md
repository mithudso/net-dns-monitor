# Repository bootstrap audit — 2026-11-12

This maintenance resumes the retained audit and repair branch. The review covers
all maintained Python, shell, tests, CI and declarative configuration. It includes
the implemented headless monitor, signed-UDP fleet receiver and editable
remediation scripts. The October desktop-only scope predates those features.
The separate router stack remains retired. Maintenance does not activate it.

The run applies `repo-bootstrapper` and `code-deep-optimizer`. Their generic
server scaffolding is interpreted against the existing application architecture.
The Python package is the reusable library boundary. This run does not invent a
Node server, operations database, dashboard, license grant or response-time SLA.
Semantic queries, embeddings, model inference, live network probes, installers,
privilege changes, signing and service activation remain outside this run.

| Area | Result |
|---|---|
| Workflow instructions | `AGENTS.md` and `GEMINI.md` share `CLAUDE.md`; the Copilot file supplies commands, architecture and conventions. Versioned journals preserve continuation and use a cooperative lock. |
| Configuration and tooling | Runtime dependencies remain four exact pins. Ruff hook and development pins match. The source-census guard checks current nonignored source, component coverage and test totals. |
| Architecture and APIs | The component map includes all current package modules. Fleet, headless, remediation and distribution boundaries have dedicated contracts and wiki navigation. |
| Operations | `docs/external-calls.md` retains dated call-site anchors and adds current source symbols, timeout/retry, failure, deduplication and observation contracts. |
| Testing | Synthetic checks preserve fake side effects and scratch user state. Eighteen UDP and four Foundation cases are held under the strict local guard; fresh macOS CI must account for them. |
| Retrieval | The maintained dossier is a static census with shallow cards. Its manifest explicitly remains partial. Source review does not produce deep retrieval cards or semantic embeddings. |
| Security | Malformed inputs and failure reporting are audited against the actual source. Existing signed fleet, secret redaction, capability gates and network-order readback remain load-bearing contracts. |
| Ownership and runtime | Work stays in an isolated branch. The divergent original checkout and protected resolver configuration remain unchanged; no live service is restarted. |

## Applicability of the five generic operations standards

| Standard | Existing implementation and audit boundary |
|---|---|
| CLI/MCP trigger | The supported `netdns` catalogue, fleet/headless commands and operator scripts expose existing operations. GUI and privileged operations remain deliberate UI/manual actions. A universal new registry would change the product. |
| Central error logging | Structured local results, forensic/event logs and bounded status fields are the implemented observations. This run documents their limits; it does not claim every call writes a universal error sink. |
| Automatic remediation | The existing troubleshooting ladder preserves each step's verbatim result. Credential, privilege and validation failures require the established user action. A successful recovery never proves which repair caused it. |
| Dashboard card | Existing dashboard actions retain capability gates and unknown-state reporting. No new server dashboard or one-card-per-call product redesign is authorized. |
| Persisted-data verification | Fleet acknowledgement, event append and state-save boundaries are documented separately. This run does not claim crash-atomic exactly-once persistence. Nonpersisting probes have no datastore guarantee. |

The generic five-standard server ideal is therefore **scope-qualified**, not an
assertion that this desktop application implements that entire product. Prior
solo-maintainer omissions such as CODEOWNERS/editor workspace scaffolding remain
intentional. The optional MCP service is documented but is not auto-registered
or started. This audit does not change the license or promise response times.

## Coverage and verification

The initial diagnostic round reviewed 198 targets without a file cap. The current
census added three regression modules. The retained changed-source round has
104 targets and reuses 97 exact-hash reports. The dated optimizer report and
source-coverage artifact record the final counts, dispositions and checks.
At the checkpoint, fresh CI exercised the full suite: 3033 passed and two were
skipped; the job then failed because documentation totals and census were stale.
That result is historical evidence, not a final delivery gate.

Final local verification passes: pinned Ruff lint/format, 3171 pytest passes with 22 explicit local holds, and the exact 3193-node static documentation gate. The maintained-source optimizer exits NO_CHANGE with an explicit owner-deferred High limitation. Final remote delivery follows passing checks on the pushed head. The existing synchronous GUI incident pipeline remains an
explicit owner-deferred architecture limitation. Live App Store approval,
privileged network changes, notification delivery and between-Mac fleet
operation remain unverified by this synthetic maintenance.
