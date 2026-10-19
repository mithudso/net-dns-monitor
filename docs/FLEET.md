# Fleet monitoring: headless mode and the central report server

For an administrator who installs the monitor on teammates' Macs and wants one
place that shows **which machines have problems, what the problems are, and
what was done about them**.

Two roles, one codebase:

| Role | Command | What it does |
|---|---|---|
| Reporting machine | `netdns headless` | Runs the monitor with no windows. Reports each incident, the steps it ran, and the recovery. |
| Central server | `netdns server` | Listens for reports on UDP, logs them, keeps the current picture of every machine. |
| Reader | `netdns fleet` | Prints that picture and the recent events. Works whether or not the server is running. |

`netdns` is `python3 -m netdnsmonitor.cli` (see `docs/SCRIPTS.md`).

## Set up the server (once)

1. Pick a Mac that stays on. Give it a fixed address (a DHCP reservation is enough).
2. Start the server:
   ```bash
   python3 -m netdnsmonitor.cli server
   ```
   Expect `[fleet] listening on UDP 45738`, and a warning that no machines are
   enrolled yet. To keep it running without a terminal, set `fleet_server_enabled: true`
   in that Mac's config and run `headless --install` there: the headless process then
   hosts the server too.
3. Enroll each teammate's Mac (next section). The server picks up an enrollment or a
   revocation within a second; no restart.

The server writes two files (paths are `fleet_server_log_path` and
`fleet_server_state_path`):

- `fleet/events.jsonl` — every accepted event, one JSON object per line, append-only.
  Rotated to `events.jsonl.1` at 10 MB.
- `fleet/state.json` — the current picture, one entry per machine.
- `fleet/keys.json` — the enrolled machines and their keys (`fleet_keys_path`), mode 0600.

## Put it on a teammate's Mac

Each Mac has **its own key**, and that key is its login. A report is accepted only if
it is signed with the key enrolled for the machine name it claims.

1. **On the server, enroll the Mac** under a name you will recognise:
   ```bash
   python3 -m netdnsmonitor.cli fleet enroll desk-7
   ```
   It prints the key once, with the commands to run on that Mac. It is not printed
   again; if it is lost, `fleet revoke desk-7` and enroll again.
2. **On the teammate's Mac,** install the project and copy `config.yaml` to
   `~/.config/net-dns-monitor/config.yaml`, then set:
   ```yaml
   fleet_reporting_enabled: true
   fleet_machine_name: "desk-7"           # must equal the enrolled name
   fleet_server_address: ""               # empty = broadcast to this subnet
   ```
   While the Macs share one network, leave `fleet_server_address` empty. Set it to
   the server's IP address for a machine on another network: a broadcast never
   crosses a router, so a Mac elsewhere would otherwise look silent. An IP beats a
   name, because during an outage the name may not resolve.
3. **Install the agent,** with the key from step 1:
   ```bash
   export FLEET_MACHINE_KEY="<the key>"
   python3 -m netdnsmonitor.cli headless --install
   ```
   This stores the key in that Mac's Keychain (the agent has no shell environment, so
   an exported variable alone would never reach it), writes
   `~/Library/LaunchAgents/com.netdnsmonitor.headless.plist` (`KeepAlive`, so it
   restarts if it stops) and loads it. Remove it with `headless --uninstall`.
4. Check: the log is `~/Library/Logs/net-dns-monitor-headless.log`, and on the
   server `netdns fleet` should list the machine within one heartbeat
   (`fleet_heartbeat_seconds`, default 300).

`netdns headless` with no flag runs in the foreground, which is how to try it first.

## What is reported

| Event | When | Contains |
|---|---|---|
| `hello` | every `fleet_heartbeat_seconds` | machine name, status (`healthy`, `flaky`, `incident`, `unknown`), version |
| `incident` | the anti-flap gate declares an incident | classification, whether the network and DNS probes answered, **every ladder step with its outcome**, whether the recheck passed, whether Claude was consulted |
| `resolved` | the gate clears the incident | how long it lasted, the steps that had run |

The server adds `online` (first heard, or heard again after silence), `silent`
(not heard for `fleet_stale_seconds`) and a `resolved` marked `inferred`.

**What the log does and does not claim.**

- A `resolved` event says the network recovered and lists the steps that ran with
  their outcomes verbatim (`partial: ...`, `NEEDS_PRIVILEGE: ...`). It does **not**
  say a step fixed it. The gate clears an incident on consecutive healthy probes;
  a transient fault clears the same way.
- If a `resolved` is lost, the next `healthy` heartbeat closes the incident and the
  log marks it `inferred from heartbeat`. The report says "closed from a heartbeat,
  not reported".
- A machine that goes quiet is `silent`, never `healthy`. A machine that went quiet
  during an incident shows as `incident (silent)`: it may be the one whose network is
  down, which is the only case where it cannot say so.
- `unknown` means the first probe has not finished. It is reported as unknown.

**Delivery.** Each incident and resolution waits in an in-memory outbox (100 events)
and is re-sent, oldest first, until the server acknowledges it, so an incident
declared while the network is down is delivered when it returns. The outbox is
lost if the process restarts before then. Heartbeats are not queued.

## Reading the log

```bash
python3 -m netdnsmonitor.cli fleet                 # every machine, problems first by name
python3 -m netdnsmonitor.cli fleet --events 50     # plus the last 50 events
python3 -m netdnsmonitor.cli fleet --json          # state, events and enrolled names
python3 -m netdnsmonitor.cli fleet keys            # enrolled names (never the keys)
python3 -m netdnsmonitor.cli fleet revoke desk-7   # refuse that machine from now on
```

Example:

```
2 machine(s) known; 1 not healthy.

desk-7 (192.168.1.31)  [incident]  last heard 2026-10-17 10:02:11 UTC
    PROBLEM since 2026-10-17 10:01:40 UTC: dns
    steps run: flush_dns_cache: partial: HUP refused; renew_dhcp_lease: NEEDS_PRIVILEGE: no grant
    the recheck after those steps still failed
```

## Settings

All in the **Fleet reporting** group of Settings, or `config.yaml`. They need a
restart of the headless process.

| Key | Default | Meaning |
|---|---|---|
| `fleet_reporting_enabled` | false | Send reports. Nothing is sent while false. |
| `fleet_server_address` | "" | Server IP. Empty broadcasts to the subnet. |
| `fleet_port` | 45738 | UDP port, same on both sides. |
| `fleet_heartbeat_seconds` | 300 | Heartbeat interval. |
| `fleet_machine_name` | "" | Name in the log. Empty uses the host name. Keep it stable: the server keys machines by it. |
| `fleet_allow_unsigned` | false | Server: accept unsigned reports (trial only). |
| `fleet_server_enabled` | false | Run the server inside the headless process. |
| `fleet_server_log_path` | `.../fleet/events.jsonl` | Server event log. |
| `fleet_server_state_path` | `.../fleet/state.json` | Server state file. |
| `fleet_keys_path` | `.../fleet/keys.json` | Server: enrolled machines and their keys. |
| `fleet_stale_seconds` | 900 | Server: silent after this long. |

A machine's key is the credential `FLEET_MACHINE_KEY` (environment, then Keychain), set
from the Credentials menu or by `headless --install`. It is never in the config file.

## Security model

- **A key per machine.** Every message carries an HMAC-SHA256 over its canonical JSON,
  keyed by the key enrolled for the name the message claims. A machine cannot speak for
  another, a name that was never enrolled (or was revoked) is refused, and a leaked key
  exposes one machine, not the fleet. Refusals are counted by reason (`bad_signature`,
  `unknown_machine`, `unsigned`, `clock_skew`) and shown by `netdns fleet`; a refused
  datagram gets no reply, so a scanner learns nothing.
- **Symmetric keys, not an SSL/TLS key pair.** Public-key signatures are not in the
  Python standard library, and the project's runtime dependencies are fixed at four.
  The server therefore holds every machine's key: `keys.json` is as sensitive as the
  keys, is written mode 0600, and should live on a Mac only you can use. A compromised
  *server* exposes all keys. If you need keys the server cannot reveal, that is a
  change to the dependency policy, not a setting.
- **Replay window.** The signed time is the *send* time; the server refuses messages
  more than 10 minutes off its own clock, so a machine with a wrong clock shows up as
  `clock_skew` refusals rather than disappearing silently. A replay inside the window
  is caught by the per-machine event-id memory.
- **Not encrypted.** The payload is a host name, a classification and step outcomes.
  The signature stops forgery, not eavesdropping on the local network.
- **Redacted.** Step text is redacted with `sensitive_strings` before it leaves the
  machine. Probe results, log excerpts, report paths and credentials are never sent.
- **Rate-limited.** One machine name may log 30 events a minute; the server holds at
  most 1000 machines.
- **Unsigned mode** (`fleet_allow_unsigned`) lets any host on the network claim any
  machine name, and the keys then protect nothing. Use it for a first trial, then turn
  it off.

## What is not verified

- No second machine has reported to a real server yet. The suite and a loopback
  smoke run exercise the real sockets; real subnet **broadcast** between two Macs,
  and macOS's Local Network prompt for the headless process, have not been observed.
- The LaunchAgent has been written and parsed in tests, not loaded by `launchctl`
  in this repository's checks.
- Headless mode runs the incident detector and ladder only: no peer discovery, ping
  heartbeat, dashboard, log viewer or forensic episodes. The saved report in
  `reports_dir` and the server log are the records.
- The menu-bar app does not report to the server.
- The Mac App Store edition has none of this: `distribution.Capabilities.fleet_reporting`
  is false there, the modules are pruned from the bundle, and the Settings group is hidden.

## Files

| File | Role |
|---|---|
| `netdnsmonitor/fleet_protocol.py` | message format, signing, validation (no sockets) |
| `netdnsmonitor/fleet_client.py` | reporter: outbox, retry, acknowledgement |
| `netdnsmonitor/fleet_keys.py` | the enrolled machines and their keys (no sockets) |
| `netdnsmonitor/fleet_store.py` | server log and state, silence and inference, text report (no sockets) |
| `netdnsmonitor/fleet_server.py` | UDP listener |
| `netdnsmonitor/headless.py` | windowless monitor loop, LaunchAgent install |
| `tests/test_fleet.py` | the suite for all of the above |
