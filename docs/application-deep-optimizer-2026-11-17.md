# Net DNS Monitor application review, 2026-11-17

Net DNS Monitor detects connectivity and DNS incidents on macOS, runs an offline
diagnostic ladder, and leaves a report the owner can hand to IT. An optional
headless workflow reports incidents and recovery to a separate fleet receiver.
The review covered eleven journeys across the direct and App Store editions,
the CLI, the fleet roles, the router boundary, and source delivery. The plan
selected 211 of the application optimizer's 240 methods.

| Finding | Severity | Change and acceptance |
|---|---|---|
| Fresh public test setup fetched a private Git dependency. | High | The default development environment uses public pinned dependencies. The optional LaunchAgent parity comparison is collected consistently and skips when its comparison library is absent. The baseline public test job failed before running pytest. |
| Failover displays called the first enabled service active, even when its probe showed it was unreachable. | Medium | The menu and CLI describe priority order explicitly, including the case with no enabled service. The reachability rows remain separate, and the App Store menu still shows its read-only state. |
| Moving from Start at Login to the supervised installer could leave two desktop jobs. | Medium | The service installer refuses an existing or loaded standalone login agent before it replaces the bundle. The menu and installer use the same reservation to coordinate agent creation. The installation guide describes the migration. |
| The fleet guide and security model denied sending probe results, even though incident messages carry reachability and DNS health summaries. | Medium | Both documents now describe the transmitted summaries and identify the detailed probe fields that stay local. |
| A first inconclusive headless probe could send a healthy heartbeat and close an existing fleet incident. | Medium | Heartbeats stay unknown until a probe scores at the flap gate. A receiver fixture keeps the prior incident open and then observes inferred recovery on healthy evidence. |
| Malformed config blocked removal of the headless KeepAlive job. | Medium | The CLI reaches uninstall using the fixed job label. It preserves the return code for confirmed removal or unload failure. |
| Headless install equated successful bootstrap with a running monitor. | Medium | The installer checks the job for a PID within a bounded interval. It reports an unconfirmed start separately from successful launch. |
| Start at Login stayed checked after stopping supervision. | Medium | The menu uses the supervision flag and explains how to re-enable the existing job without creating a second agent. |
| A disabled preferred service at the front of the raw order could be reported as already active. | Medium | No-op decisions use the first enabled service and report a refusal when no service is enabled or a third service leads. |
| Restoring the saved order could leave a backup first among enabled services when a disabled entry led the list. | Medium | Failback promotes the preferred service if the saved order would still prioritize an enabled backup. |

An injected regression run against the original source reproduced the two
behavior defects. The same nine cases passed after the changes. The tests use
synthetic LaunchAgent data and stubbed launchd queries. The optimizer retains
the before/after receipts and source bindings in its local run record.
An independent review of the first candidate found five further journey
defects. A second review found the saved-order failback defect and caught a
regression that cleared a manual pause when the first-priority backup was
temporarily disabled. Ten additional cases reproduced these findings against
the corresponding candidates and passed on the repaired source.

The synchronous menu-bar incident pipeline remains a High finding under the
existing owner deferral. The ladder, unified log and escalation can still delay
the menu during an incident. Changing that order needs an explicit decision on
reporting, failover and UI handoffs. Other pending behavior decisions are
listed in [known issues](known-issues.md).

The public privacy notice describes App Store consent while also referring to
the direct edition. Direct desktop and headless use a configured API key as
opt-in to incident diagnosis. The notice and its source need a coordinated
update in the site and application repositories.

The evidence supports the source repairs. Installed GUI behavior, a live login
agent migration, privileged repair and failover, signed App Store behavior,
outbound notifications and a two-Mac fleet run remain unverified. The review
does not establish field latency, accessibility, adoption, or retention.
The optimizer's convergence result remains blocked by the deferred High
finding and incomplete live evidence.

Rollback is a reviewed revert of the application optimizer change. The change
does not migrate existing configuration, reports, or stored failover state.
