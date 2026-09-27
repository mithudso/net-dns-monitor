# Requirements

## Functional

1. **Monitor.**
   - Check TCP reachability to configured IP targets.
   - Check DNS resolution of configured domains and a control domain.
   - Send an ICMP heartbeat.
   - Track per-interface reachability.
2. **Classify.** Label each tick healthy, network, dns or unclassified. A value that was not probed (`None`) produces unclassified, never a guess.
3. **Declare incidents** only on the healthy-to-incident edge after the anti-flap threshold. One outage gives one report and one alert.
4. **Troubleshoot** with an offline ladder. Each step records exactly what it did; repairs that did not run say so.
5. **Fail over** to a backup network service, only after reading the service order back (direct build only).
6. **Escalate** to Claude when the ladder cannot resolve an incident. This needs the user's API key, plus explicit in-app permission in the App Store build.
7. **Report.** Write an IT-ready report and forensic episode on disk. Optionally alert Slack or email with redacted text.
8. **Localize** the fault (this machine, local network, DNS, upstream) using peers on the same subnet.

## Non-functional

- **Honesty.** No output may claim a repair, switch or measurement that did not happen (CLAUDE.md 1, 2).
- **Offline testability.** Every side effect is injected. The suite opens no sockets beyond loopback.
- **Responsiveness.** Nothing raises into the rumps timer. Domain lookups in a tick share one deadline.
- **Secrets.** Credentials come from the environment or the Keychain. They never appear in reports, logs, errors or notifications.
- **Dependencies.**
  - Four runtime packages (`requirements.txt`), pinned exactly, with transitive versions frozen in `constraints.txt`.
  - Python 3.13.
- **Distribution.**
  - The direct py2app bundle, supervised by a LaunchAgent.
  - The Mac App Store build, sandboxed with no temporary exceptions (APP_STORE_SUBMISSION.md).

## Runtime dependencies

| Package | Why |
|---|---|
| `rumps` | Menu bar app and timers |
| `pyobjc-framework-Cocoa` | AppKit windows, the Dock tile, and Keychain access through the PyObjC bundle loader |
| `PyYAML` | `config.yaml` |
| `anthropic` | Claude escalation |

Development only (`requirements-dev.txt`): `pytest`, `ruff`. The store build also needs `py2app` and Xcode.
