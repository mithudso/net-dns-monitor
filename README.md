# net-dns-monitor

macOS menu bar app that monitors network + DNS connectivity, auto-diagnoses
via an offline troubleshooting ladder, escalates to Claude when the ladder
can't resolve it, and saves an IT-ready incident report -- no user action
required to detect, diagnose, or report an issue.

## Honest scope

This app can genuinely fix a small set of local problems and diagnose a
great many more -- but even that small set is partial. `dscacheutil
-flushcache` runs fine unprivileged; the `killall -HUP mDNSResponder` half
of a full DNS cache flush does not, since mDNSResponder runs as a different
user and a signal to a process you don't own is rejected regardless of the
command's own permissions (confirmed empirically, not assumed). The app
reports that case as `partial` rather than claiming success. It cannot fix an ISP outage, a
misconfigured upstream DNS server, or a captive portal -- those need a
human. The diagnostic report is the primary deliverable for most real
incidents, not a fallback.

Repairs that need root are no longer unconditionally stubbed. **Grant elevated
permissions** in the window installs a narrow `/etc/sudoers.d` rule -- two exact
commands, no wildcards, no shell -- after which the DNS cache flush completes and
`renew_dhcp_lease` runs. Without the grant both still report why they cannot.
See [Permissions](#permissions) for what that grant costs, and
`netdnsmonitor/privileges.py` for the reasoning.

Toggling a network interface stays unautomated on purpose, not for want of
permission: down-then-up cannot be one command, and two risks leaving the machine
offline with no network to fix it over.

The one exception is the optional network-failover step, which is genuinely
attempted rather than stubbed — reordering network services can succeed for an
administrator account without a helper. It is still tagged as needing
privilege, and when the write is refused it reports `NEEDS_PRIVILEGE` and
changes nothing. See "Automatic network failover" below.

## Command line

One entry point for everything the app does without a menu bar:

```bash
python3 -m netdnsmonitor.cli interfaces      # every service, live
python3 -m netdnsmonitor.cli bench           # + measured throughput
python3 -m netdnsmonitor.cli status          # classification + failover state
python3 -m netdnsmonitor.cli failover backup # switch to the fastest backup
python3 -m netdnsmonitor.cli console         # interactive
python3 -m netdnsmonitor.cli guide           # what to do when it breaks
```

`interfaces` is the one to start with — it shows every service with its device,
whether the service is enabled, whether it can actually reach anything, and
(with `bench`) how fast:

```
 #  SERVICE                    DEVICE   SVC  REACHABLE     Mbps
 1  AX88179B                   en6      on   not probed       -
 3  USB 10/100/1G/2.5G LAN     en9      OFF  unreachable      -
 4  M3100                      en12     OFF  unreachable      -
 6  Wi-Fi                      en0      on   reachable      3.5
```

`SVC = OFF` is the trap worth knowing: **a disabled service is skipped by macOS
no matter where it sits in the priority order.** Failing over to one requires
enabling it as well as promoting it, which the app does.

`not probed` is not `unreachable` — an unplugged adapter disappears from the
interface list entirely, and calling that "unreachable" sends you looking for
the wrong fault.

### Console

`netdns console` (or "Open console…" in the menu bar) is a REPL over the same
catalogue: a usage guide, a numbered list of diagnostic commands, the live
interface table, and service-order editing (`priority`, `promote <name>`).

Anything that changes system state — a catalogue command marked `!`, switching
networks, or promoting a service — shows you the exact command and waits for
`yes`. Nothing that rewrites configuration happens on a single keypress. A
command with a placeholder (`ifconfig {device}`) asks for the value rather than
shelling out with a literal `{device}` in it.

In the terminal console a number **runs** the command (after confirming, if it
mutates); in the menu bar window the dropdown **inserts** it into the input box
so you can read it first.

## Automatic network failover

Optional, **off by default**. When the preferred network dies, the app can move
the machine onto a backup network by rewriting the macOS network service order,
and move it back when the preferred one recovers.

```yaml
failover_enabled: true
failover_preferred_service: "AX88179B"   # the wired link
failover_backup_service: "Wi-Fi"         # the hotspot
```

Names must match `networksetup -listnetworkserviceorder` exactly; a name that
doesn't match is reported as a failure listing the names that do exist, and
nothing is reordered.

**Menu bar controls.** Three indicator rows show which service is carrying
traffic (`●`) and which is not (`○`), each with its device and whether it can
actually reach anything right now:

```
Active: Wi-Fi — failover is automatic
○ Preferred: AX88179B (en6) — unreachable
● Backup: Wi-Fi (en0) — reachable
Switch to backup now
Switch back to preferred now
Refresh network status
```

The switch buttons skip the policy — a person clicking a button has already
supplied the judgement the rate brakes exist to substitute for — but not the
execution safety: the permutation guard and the read-back verification still
apply, and the result is reported in a notification.

**Three modes**, set by which keys you fill in:

| `failover_enabled` | Both names set | Behaviour |
|---|---|---|
| `false` | no | Off entirely |
| `false` | yes | **Manual only** — buttons work, nothing moves on its own |
| `true` | yes | Automatic, buttons still available |

Manual-only is the way to try this before trusting it unattended.

**The one failure this addresses.** A link that is *up but not carrying
traffic* — it has a cable and an address, so macOS keeps it primary and keeps
routing into a hole. When a cable is simply unplugged the interface disappears
and macOS fails over on its own; this feature correctly does nothing there.

**It verifies the backup before moving.** Reachability is tested *through* the
backup interface specifically, using the `IP_BOUND_IF` socket option, so a
switch only happens when the other side is known to carry traffic. Binding the
source address instead would not work: on Darwin the route lookup follows the
destination, so a socket bound to the Wi-Fi address still leaves via whichever
interface owns the route.

**Several backups, fastest wins.** Give `failover_backup_services` a list and
every candidate that is independently confirmed reachable gets benchmarked —
a real bounded download forced out of that interface — with the fastest chosen
outright. Reachability stays a gate rather than a factor: a fast-looking but
unverified path never beats a slow proven one. A link whose speed could not be
measured reports `None`, not `0.0`, so it ranks after measured links rather
than below dead ones. Only reachable candidates are benchmarked, since there is
nothing to measure on a path that carries no traffic and it costs seconds each.

**It enables a disabled service.** macOS skips a disabled service wherever it
sits in the order, so promoting one on its own is a change that looks like a
success and routes nothing. The enable is verified by reading the listing back,
exactly like the reorder.

**It is built to be reluctant.** Four brakes must all release before anything
moves: the incident must be a configured trigger (network-layer only by
default), the backup must be independently verified, the cooldown must have
expired, and the hourly switch budget must not be spent. Failback is
asymmetric — it waits for the preferred link to pass several consecutive checks
— so a flapping link cannot drag the machine back and forth. Every refusal
records *why*, and that reason appears in the incident report.

**It restores your exact order.** The service order in place before the first
failover is recorded and restored verbatim, rather than leaving the backup
permanently in second place. The record survives a restart, so an app
relaunched mid-outage can still put you back.

**Privilege, honestly.** Reordering network services needs an administrator
right. Whether that succeeds without a password prompt depends on your account
and on the "Require an administrator password to access system-wide
preferences" setting. If it is refused, the step reports `NEEDS_PRIVILEGE` and
nothing changes. And because `networksetup` can exit 0 without doing anything,
the order is read back and compared after every attempt — a switch is only
reported as `ok` once the new order has been confirmed on disk.

**Not yet verified live.** The decision logic, the parser, the rate brakes and
the persistence are covered by offline tests, and the `IP_BOUND_IF` probing was
confirmed by hand against real interfaces. The privileged
`networksetup -ordernetworkservices` write itself has **not** been executed on a
real machine. Clicking "Switch to backup now" is the way to find out: it runs
the same guarded path the automatic switch does and reports exactly what
happened. Evidence suggests it will work without a password prompt — `scselect
-n` wrote to root-owned `preferences.plist` from a non-root admin account
silently, using the same authorization right — but that is a prior, not proof.

## Setup

Requires Python 3.9+ (the code uses bare `list[...]`/`tuple[...]` generic
type hints).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

mkdir -p ~/.config/net-dns-monitor
cp config.yaml ~/.config/net-dns-monitor/config.yaml
# edit ~/.config/net-dns-monitor/config.yaml: add the domains you actually
# care about, any internal targets, and (optionally) sensitive_strings to
# redact before LLM escalation
```

To enable the Claude escalation step (used only when the offline ladder +
repair attempt still leave an incident unresolved):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Without that variable set, escalation is skipped and the report still gets
written -- it just won't have an LLM analysis section.

To enable notifications (both channels are optional and independent):

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...   # Slack
export SMTP_PASSWORD=...                                        # email, if the relay authenticates
```

Neither secret belongs in `config.yaml` -- for a Slack incoming webhook the
URL *is* the credential, so it stays in the environment and is never echoed
back in an error message. Email also needs `email_recipients` in
`config.yaml`; with an empty recipient list that channel stays inactive.

## Notifications

When an incident is declared and its report is written, a redacted one-block
summary goes to every configured channel: classification, start time,
duration, whether local repair resolved it, the repair outcome, the Claude
analysis if there was one, and the path to the local report. Raw probe results
and log excerpts are deliberately *not* sent -- those are unredacted by design
because the report stays on the machine. Anything in `sensitive_strings` is
stripped on the way out, the same rule that governs LLM escalation.

Honest limits, same shape as the escalation caveat above:

- These channels need working connectivity, so they cannot fire during a
  genuine full outage -- only during partial degradation. The on-disk report
  is written either way.
- Notifications fire on incident *onset* only. Recovery produces no report
  (see `status.py`), so there is no "back to normal" message; the menu bar
  icon is the recovery signal.
- Send timeouts are short (`notify_timeout_seconds`, default 5s) because this
  runs on the UI thread at the moment the network is known to be broken.
- A delivery failure is recorded and swallowed, never raised: a Slack outage
  must not stop the report from being saved.

## Auto-learned domains

`domains` in the config is a floor, not the whole list. Every
`domain_learn_interval_seconds` (default 300) the app scans the unified log for
*failed DNS resolutions* and adds those hostnames to the probe list --
evidence already on the machine that someone tried to reach a name and could
not. That avoids the browser-history route, which would mean reading another
app's data.

**On a stock macOS install this finds nothing, and that is not a bug in the parser.**
macOS masks hostnames in the unified log by default: mDNSResponder's resolver lines
carry `<mask.hash: '...'>` or an opaque token (`BBUpzafn IN A?`) where the queried name
would be, so there is no name to extract. Measured on one machine: 758 error-like
lines, 198 of them explicitly masked, 0 learnable domains. Unmasking
(`sudo log config --mode "private_data:on"`) is a **system-wide privacy change** and is
not recommended lightly. Treat `domains` as the real probe list and this feature as
opportunistic. `docs/SCRIPTS.md` shows how to check what your own log yields.

Two guards keep this from making the monitor worse:

- `dns_ok` is an all()-across-domains signal, so one dead name scraped out of a
  log line would otherwise pin the app in a permanent false incident. A learned
  domain that fails *while the control domain still resolves* is a dead name
  rather than a broken resolver, and is evicted. With the control domain also
  failing, nothing is pruned -- that is the real outage this app exists to
  report. Hand-configured domains and the control domain are never evicted.

  The control domain (`control_domain`, default `api.anthropic.com` -- the host
  LLM escalation already depends on, so a failing control means escalation was
  going to fail too) is what makes that test possible. Learned names are by definition names that *failed*, so
  on the default `domains: []` every probed name is a learned failure and
  "something else resolved" is false by construction; a name known to resolve
  is the anchor that breaks the tie. Setting `control_domain: null` with no
  configured domains disables pruning's anchor.
- Scraped hostnames are validated before use (no IP literals, no
  `in-addr.arpa`/`ip6.arpa` reverse zones, no bare labels, length-capped), and
  the store is capped at `max_learned_domains` so a log flood cannot grow the
  probe list without bound.

- All domain lookups in a tick share **one** deadline
  (`probe_timeout_seconds`, default 2s), resolved on worker threads. Serial
  lookups would make the block additive -- with 20 learned names plus the
  control domain, a resolver outage would freeze the menu bar for ~42s.
- `domain_learn_interval_seconds` is clamped to at least twice
  `poll_interval_seconds`. Scanning every tick re-adds a dead name as fast as
  pruning drops it, so the flap gate's success counter never resets and one
  dead name latches a permanent incident.

Learned domains live in `learned_domains_path` and stay local; only the
redacted summary described above ever leaves the machine. Set
`learn_domains_from_logs: false` to probe exactly the configured list. Setting
`control_domain: null` *and* leaving `domains` empty removes the anchor: with
nothing known-good to compare against, a dead learned name can no longer be
identified as dead and will hold the app in an incident.

## Run

```bash
./scripts/start.sh
```

Checks the install and launches the app as a proper `.app` bundle (so the
Dock/Force-Quit/Cmd-Tab name correctly reads "Net-DNS-Monitor" instead of
"Python") -- output goes to `net-dns-monitor.log`, and the terminal
detaches once it's running; quit via the menu bar's Quit item. For direct
foreground debugging instead (Ctrl-C works, but the Dock/Force-Quit name
falls back to "Python"):

```bash
source .venv/bin/activate
python -m netdnsmonitor.app
```

Either way, the menu bar shows the current network statistics followed by a
status dot (🟢 healthy / 🟡 flaky -- a probe just started failing but hasn't
crossed the incident threshold yet / 🔴 incident):

```
61ms 1.2M↓0.3M↑ 🟢 Net/DNS: healthy
```

Round-trip time to `ping_host`, recent packet loss (shown only when nonzero),
and current throughput in bits per second. The Dock tile carries the same
round-trip time in the same status colour. Click the menu bar item and choose
"Open last report" for the most recent incident report, or "Test network
alert" to check that alerts actually reach you. See `HOWTO.md`'s Menu bar
reference section for the full status-icon and resolution-monitor-badge
behavior.

## Dashboard window

Four ways to open it, because the status item in the top-right is easy to miss on
a crowded or notched menu bar:

1. **Automatically shortly after launch** (`open_dashboard_at_launch: true`),
   ordered front without stealing focus.
2. **Click the Dock icon.**
3. **"Net-DNS-Monitor" -> Open Dashboard** in the menu bar top-*left*, which
   appears when the app is active.
4. **Open dashboard** in the status-item dropdown, top-right.

What it shows:

- **Network right now** -- ping target, round-trip time, packet loss, current
  download and upload rates.
- **Monitor** -- live status, consecutive probe failures, the last incident and
  its report path, the last resolution batch, and whether a forensic episode is
  open.
- **Other monitors on this network** -- peers discovered on the LAN, grouped
  into current / recent / other.
- **Settings in force** -- every cadence and threshold actually in effect, so
  the app's behaviour is explicable without opening the config file.
- **Permissions** -- what the app may do as root, what each right unlocks, and
  what stays impossible either way. See [Permissions](#permissions).
- **A button per troubleshooting step** -- ping now, check interface state,
  check the default route, check the configured DNS servers, check
  `/etc/resolver` overrides, resolve via a public resolver, flush the DNS cache,
  or run the full ladder for the current classification. Results appear in the
  pane at the bottom, each with the reason the step exists. Steps that mutate
  system state say so on the button.
- **A system log pane down the right-hand side** -- see
  [System log viewer](#system-log-viewer).

Steps run on a worker thread, never on the run loop: `repair_executor` allows 5s
per step and a full ladder is four of them, so running one inline would freeze
the window and every timer for up to half a minute.

The window is two columns wide rather than taller because it was already 950px
high and the display it opens on is 1080 logical pixels: there was nowhere to
stack a log pane underneath. Log lines need the width anyway.

## Console

Two ways in, because the point of it is to be there when you need it: **"Open
console"** in the status-item dropdown, and **"Open console (arbitrary shell)"**
in the dashboard's button grid. Both open the same console -- one working
directory, one history -- rather than two that silently disagree about where you
are. Closing it with `q` leaves the monitor running; that is the whole reason it
closes rather than quits.

It runs **arbitrary shell**, deliberately. During an outage the useful next
command is whatever the person watching thinks of, not whatever a catalogue
anticipated. It runs as your user in your environment -- the same reach as
Terminal.app, no more and no less. There is no blocklist, because a pattern
match over arbitrary shell is theater: it would miss the dangerous command
spelled slightly differently and refuse the safe one that happens to contain
`rm`.

The guards are the ones that hold regardless of what gets typed:

- **20s timeout, then the whole process group is killed.** A bare `ping
  google.com` never exits on its own. Killing the group rather than the process
  is what stops `shell=True` from leaving the `ping` orphaned under a dead
  `/bin/sh`.
- **stdin is `/dev/null`.** Anything that would prompt -- `sudo`, `ssh` -- fails
  with a readable error instead of hanging until the timeout.
- **Output is capped at 64 KB**, drained and discarded past the cap so that
  `yes` costs flat memory instead of gigabytes in a menu bar app.

Built-ins: `:help`, `:status` (the monitor's own view of itself -- gate state,
classification, live stats, resolution failures, last report), `:history`,
`:pwd`, `:clear`, `cd` (a real built-in, since a subprocess cannot change its
parent's directory), and `q` to close.

Every command runs on a worker thread, not just the slow ones. A console with a
fixed command set can pick what to push off the main thread because it knows in
advance which entries are slow; an arbitrary-command console cannot, and a
blocking wait would freeze the window, the menu bar *and* the monitoring timers
during the outage you opened it to investigate.

`:status` routes through `status_state`, the same function behind the menu bar
title, the Dock tile and the alert -- so it cannot drift into telling you the
network is healthy under a red menu bar icon.

## System log viewer

The right-hand column shows what macOS itself says about the network -- the
error and fault entries from `mDNSResponder`, `configd`, the Wi-Fi stack, and
anything logging through `com.apple.network`. Nothing has to be clicked: it
backfills 15 minutes at launch, then re-reads the last minute every 30 seconds.

**New network errors are reported automatically.** They are echoed into the
results pane on the left (capped at `log_view_announce_limit` per poll), counted
in the Monitor section, and -- while an outage episode is open -- written into
that episode, so the forensic record carries what the OS said at the time and
not only what this app measured.

**Search** ANDs its terms and treats a leading `-` as an exclusion:

```
dns -crowdstrike      DNS lines that are not from CrowdStrike
[C134.1.1:3]          substring, not a regex, so a connection id pastes straight in
```

Four controls sit above the pane: **Refresh now**, **Errors only / All levels**
(the label states the filter in force, not the action), **Clear search**, and
**Empty buffer**. The status line under them separates the four different reasons
a pane can be empty -- the read failed, nothing was captured, everything captured
was filtered out, or your search excluded it all -- because otherwise they all look
like a quiet network, and only some of them are.

Four measurements shaped the defaults, all `log show` on a real machine:

| Query | Time | Lines |
|---|---|---|
| network errors/faults, last 1m | 1.4s | 44 |
| network errors/faults, last 15m | 4.2s | 919 |
| network errors/faults, last 60m | **16.9s** | 16,354 |
| *all levels*, same subsystems, last 30m | -- | **192,901** |

Hence: a small window polled often rather than a large one re-read; errors-only
by default; a 45-second timeout instead of the 10s used elsewhere for `log show`;
and identical repeated messages coalesced into one row with an `(xN)` count.

That last one is load-bearing rather than cosmetic. On this machine hundreds of
those "errors" were a single repeated CrowdStrike line, and coalescing is what
made the one entry that mattered -- `Socket SO_ERROR [51: Network is
unreachable]` -- visible at all. `log_view_noise_patterns` drops entries not
worth a row in the first place.

One thing the viewer cannot fix: macOS redacts private data, so DNS queries
arrive as `qname: <mask.hash: '...'>` rather than as a hostname. That needs a
logging configuration profile, and no amount of privilege changes it.

## Graphs, the mini window, settings, and prewarming

- **Three graphs** in the dashboard -- ping latency, download, upload -- over the
  last `history_max_samples` samples (default 720 = one hour at a 5s cadence).
  Outages are drawn as *gaps* with a faint marker, never as a line interpolated
  across them.
- **A floating mini window.** "Collapse to floating mini window" (or `Cmd-M`)
  gives a small always-on-top panel showing just the status dot, round-trip time
  and loss. Draggable, stays above other windows, remembers where you left it,
  and does not vanish when you switch apps. Toggle it back from the same places.
- **A settings window** (`Cmd-,`) with a field for **every** one of the 34
  config keys, grouped by area, and marked where a restart is needed. Saving
  rewrites `config.yaml` and **does not keep its comments** -- the previous file
  is backed up as `config.yaml.bak-<timestamp>` first, and a new timestamp each
  save so repeated saves cannot eat the only commented copy.
- **Prewarm DNS** resolves the 50 most-queried names from the unified log so
  their answers are already cached.

## Working out *where* an outage is, using a peer

One machine cannot tell these apart -- "I can't reach the internet" looks the
same whether the Wi-Fi card wedged, the router died, the ISP is out, or only DNS
is broken. A second machine running the monitor is the missing reference.

When an outage starts, peers are probed immediately and their own
`external_reachable` / `dns_ok` are compared with ours:

| What we see | What the peer sees | Verdict |
| --- | --- | --- |
| no internet | *no peer answers at all* | **this machine** -- our own link |
| no internet | peer is fine | **this machine** -- route, firewall, VPN or interface |
| no internet | peer also has none | **upstream** -- router, modem or ISP |
| DNS only | peer resolves fine | **DNS on this machine** -- resolver, cache, `/etc/resolver` |
| DNS only | peer cannot resolve either | **DNS for the whole network** -- the shared resolver |

The verdict, its confidence, the sentence explaining it, and the evidence all go
to the top of the dashboard and into the forensic episode. With no peer available
it says the question cannot be answered rather than guessing, and peers that
disagree with each other are treated as an unusable signal rather than a vote.

## Forensic log

Every network down/up episode is written up automatically: what was detected,
every step taken, **why** each step was taken, and what it returned.

An episode spans both detectors. It opens on the first "down" signal from either
the 5-second ping heartbeat or the 30-second anti-flap gate, and closes only
when both agree the network is back. That split matters -- the heartbeat notices
an outage in seconds but takes no action, and the gate takes all the action but
only after debounce, so either one alone produces a useless record.

Two artifacts:

- `forensic-log.jsonl` -- appended to *as each event happens*, so an app killed
  or a machine powered off mid-outage still leaves the evidence behind.
- `episodes/<timestamp>-episode.md` and `.json` -- the per-episode write-up,
  produced when the network comes back. The Markdown has a chronological
  timeline and a "Steps taken" table of step / kind / why it was run / result.

An outage that cleared before the ladder ever started says so explicitly rather
than showing an empty table.

## Peer discovery on the LAN

At startup (on the first sweep, never blocking launch) the app announces itself
on the local network over UDP and looks for other copies of the monitor. Every
`peer_announce_seconds` (default 300) it re-announces, then heartbeats every host
it knows about with a probe/pong exchange.

Peers are filed by how recently they were last heard from, so a machine that is
switched off needs nothing to notice it left:

| Bucket | Meaning |
| --- | --- |
| `current` | heard from within `peer_current_seconds` (default 600 = two announce intervals, so one dropped broadcast is not a demotion) |
| `recent` | heard from within `peer_recent_seconds` (default a day) -- was here, isn't answering now |
| `other` | known, but longer ago than that -- kept as history |

All three are written to `peer_record_path` (default `peers.json`) and shown in
the dashboard. That file is read back at startup, which is what lets a fresh
process probe the hosts it knew about last run rather than waiting for one of
them to announce.

**What this discloses:** any host on the same LAN can learn this machine's
hostname and whether its network is currently healthy. That is the feature, but
it is a disclosure, so `peer_discovery_enabled: false` opens no socket and
broadcasts nothing. Incoming datagrams are size-capped, JSON-only,
protocol-tagged, and every string is truncated and stripped of control
characters; nothing from a packet is ever used as a path, a command, or an
argument. There is no leader, no shared state, and no remote commands -- a peer
can learn another peer's hostname and status and nothing else.

## Ping heartbeat and network-failed alert

Separately from incident detection, the app sends one ICMP echo request to
`ping_host` (default `8.8.8.8`) every `ping_interval_seconds` (default 5).
When a ping fails it **bounces the Dock icon and posts a "network failed"
notification** naming the host and the error.

The alert is edge-triggered: it fires when the network goes down and then
stays quiet, rather than bouncing twelve times a minute for the length of an
outage. Recovery re-arms it and cancels the bounce.

Two knobs if the default is too noisy or too quiet:

- `ping_failure_threshold` (default 2) -- consecutive failed pings before
  alerting. 1 is literal: a single dropped echo request alerts. On Wi-Fi that
  will occasionally be one lost packet rather than a real outage; set it to 2
  to ignore those and still alert within 10 seconds of a real outage.
- `ping_alert_repeat_seconds` (default 0 = one alert per outage) -- set to
  e.g. 300 to be re-alerted every 5 minutes while the network stays down.

This heartbeat only drives the display and the alert. It never runs the repair
ladder, escalates to Claude, or writes a report -- that stays with the
debounced 30-second incident poll, because acting on a false positive there
costs flushed caches and API calls. It also uses ICMP where the incident
prober deliberately uses TCP-connect; see `netdnsmonitor/ping.py` for why.

## Permissions

Reading system logs (`log show`) may require the "Full Disk Access" or
log-access permission the first time it runs, depending on macOS version --
macOS will prompt if so.

Two repair steps need root, and until now the app could only report that it did
not have it. The dashboard has a **Grant elevated permissions** button, and a
**Revoke** button beside it. The window prints exactly what the grant permits
before macOS raises its authentication dialog, so it can still be cancelled after
reading.

**What the grant installs.** One file, `/etc/sudoers.d/net-dns-monitor`, owned by
`root:wheel`, mode 0440, listing your account and these complete commands:

```
/usr/bin/killall -HUP mDNSResponder        restart the system DNS responder
/usr/sbin/ipconfig set <interface> DHCP     re-request a DHCP lease
```

**What that means.** This is a real, persistent widening of what the Mac will do
without authenticating. Once the file exists, any process running as you -- not
only this app, including software you did not install deliberately -- can run
those specific commands as root with no prompt. Weigh that before clicking.

What limits the exposure: both entries are complete command lines, and sudo
matches the arguments, so the grant does not extend to `killall` or `ipconfig` in
general. There is no wildcard in the file and no shell entry (either would be
equivalent to granting unrestricted root), which is why the interfaces are
enumerated at grant time and validated before being written. Neither command
takes a file path, reads or writes your data, or can be made to run another
program; the worst either can do is briefly interrupt this machine's own network.
sudo logs every use. Revoke deletes the file.

Before installing anything, the grant checks that `/etc/sudoers` actually
includes `/etc/sudoers.d` (otherwise the file would be ignored and the button
would be lying) and validates the file with `visudo -cf` -- an invalid file in
`sudoers.d` breaks `sudo` for the whole machine. It never edits `/etc/sudoers`
itself; if the include line is missing it says so and stops.

The Permissions section reads the grant out of `sudo -n -k -l`, matching the rule
itself rather than trusting sudo's exit status. That distinction is not academic:
`sudo -l <command>` exits 0 whenever a command is permitted *by policy*, and macOS
ships `%admin ALL=(ALL) ALL`, so an exit-status check reports "granted" for any
admin account that merely holds a cached credential — or, per `sudoers(5)`, that
has *any* unrelated NOPASSWD rule. The section also lists the interfaces the
installed file covers rather than the ones the machine currently has, and says so
when the default route has moved onto an interface the grant does not include.

**What it changes.** With the grant, "Flush DNS cache" also restarts
mDNSResponder instead of reporting a partial result, and `renew_dhcp_lease` runs
on the default-route interface instead of returning `NEEDS_PRIVILEGE`.

**What is deliberately still not automated.** `toggle_network_service`. Taking an
interface down and back up cannot be done in one command, and the only way to
make it one is to allow a shell to run as root -- unrestricted root, in effect.
Two commands is worse than the problem: if anything interrupts the second one,
the machine is offline with no network to fix it over. The step reports that
rather than pretending a permission is missing. Toggle Wi-Fi or the cable by hand
if the other steps have not helped.

## Reports

Every incident produces a timestamped `.json` (machine-readable) and `.md`
(human-readable) file under `reports_dir` (default:
`~/Library/Application Support/net-dns-monitor/reports/`). Each report is
self-contained: classification, probe results, log excerpts, every ladder
step attempted and its outcome, the repair outcome, the recheck result, and
the Claude escalation response if one occurred. Hand the `.md` file to IT.

## Resolution monitor

Independent of incident detection, every `resolution_interval_seconds`
(default 300 = 5 minutes) the app re-resolves **every domain that has ever
stalled on this machine**, in parallel, and appends the outcome to
`resolution_log_path` (default:
`~/Library/Application Support/net-dns-monitor/resolution-log.jsonl`) as one
JSON object per line: `domain`, `resolved`, `error`, `elapsed_seconds`,
`outcome`, `checked_at`. The stall list is read back out of that same log, so
the feature builds its own watch list over time.

"Stalled" means the lookup *took* at least `resolution_stall_seconds`
(default 1.0) -- not that it failed. An instant `NXDOMAIN` is a fast,
definitive answer and is not a stall. This distinction matters more than it
sounds: the query-log mining this replaced swept up non-domains (bundle IDs
like `com.apple.mDNSResponder`, truncated tokens like `com.code42.agen`), and
14,845 of 16,282 observed records were those failing instantly. Keying on
elapsed time excludes them without needing a "is this a real domain" guess.

Because the list only grows, each cycle is bounded by
`resolution_batch_deadline_seconds` (default 240, which must stay under the
interval). Domains still outstanding at the deadline are logged with
`outcome: "abandoned"`, and abandoned records are deliberately **not** treated
as stall evidence -- otherwise a slow batch would enlarge the list, which
would make batches slower still. The batch runs on a worker thread so it can
never delay the 30-second incident poll.

Note that `resolution_timeout_seconds` is not enforceable per lookup:
`socket.setdefaulttimeout()` does not bound `socket.getaddrinfo()`, which is a
blocking call into the system resolver. Measured on macOS, a missing `.local`
name took 5.01s against a 2.0 setting. The batch deadline is the real ceiling.

## Tests

```bash
source .venv/bin/activate
python -m pytest -v
```

`docs/SCRIPTS.md` is the operator's manual for every entry point — including the
one-shot module invocations that exercise the prober, the ladder, the log watcher, the
domain learner and the notification text without starting a menu bar.

All decision logic (classification, anti-flap gating, the troubleshooting
ladder, escalation redaction/gating, the report builder, and the full
state-machine orchestration) is unit tested with injected fakes for every
external effect (network, subprocess, LLM, SMTP, webhook). The `app.py`
menu-bar shell is thin wiring over those tested modules; its `tick()` and
builder functions are covered with fakes, but the rumps run loop itself is
not, since that needs a real macOS event loop.

## Project layout

- `classifier.py` -- network-vs-DNS-vs-healthy-vs-unclassified split
- `flap_gate.py` -- anti-flap consecutive-count debounce
- `ladder.py` -- the offline troubleshooting ladder definition
- `repair_executor.py` -- dispatches ladder steps to real macOS commands
- `dns_query.py` -- raw UDP query against a specific public resolver
- `prober.py` -- TCP-connect reachability + DNS resolution aggregation
- `ping.py` -- one-shot ICMP ping with round-trip-time parsing
- `ping_monitor.py` -- loss window + the edge-triggered alert decision
- `net_stats.py` -- interface byte counters and throughput derivation
- `alert.py` -- Dock bounce + network-failed notification
- `forensic_log.py` -- down/up episode journal and per-episode write-up
- `peers.py` -- peer registry, recency buckets, and the file record
- `peer_net.py` -- UDP announce/probe/pong and the listener thread
- `dashboard.py` -- the window: contents as pure data plus the AppKit view
- `history.py` -- bounded rolling sample history behind the graphs
- `graphs.py` -- renders each series to an NSImage (pixel-testable)
- `localize.py` -- the decision matrix that turns an outage into a place to look
- `mini_window.py` -- the floating always-on-top panel
- `settings_window.py` -- a field per config key, and the safe save
- `log_watcher.py` -- `log show` tailing/filtering for DNS/network errors
- `stall_log.py` -- selects every ever-stalled domain from the resolution log
- `query_log.py` -- `log show` reading + top-queried-domain extraction; no longer wired into the resolution monitor (kept and still unit-tested)
- `resolution_prober.py` -- parallel, deadline-bounded DNS resolution of a domain batch
- `resolution_log.py` -- JSONL append for resolution-monitor findings
- `escalation.py` -- redaction + the escalate-or-not gate
- `service_order.py` -- parses/reorders the macOS network service list
- `interface_probe.py` -- reachability forced out of a named interface
- `failover_policy.py` -- the pure switch/don't-switch decision + rate brakes
- `failover.py` -- executes the reorder, verifies it, persists the old order
- `domain_learner.py` -- learns/validates/prunes domains from failed log lookups
- `notifications.py` -- redacted Slack webhook + SMTP email incident alerts
- `anthropic_escalator.py` -- the Claude API call itself
- `report.py` / `report_storage.py` -- incident report schema + persistence
- `status.py` -- menu bar title/stats-segment logic + the console's `:status` text
- `console.py` -- the console's decisions: built-ins, `cd`, the guarded runner
- `console_window.py` -- AppKit shell for the console; holds no decisions
- `dock_icon.py` -- draws the Dock tile as the current reading
- `state_machine.py` -- orchestrates all of the above
- `config.py` -- YAML config loading with defaults
- `app.py` -- the rumps menu bar shell
