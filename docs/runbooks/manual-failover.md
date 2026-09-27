# Runbook: manual network failover

A manual switch moves a configured backup network service to the head of the
macOS service order, or restores the order that was in place before the switch.
The implementation is `netdnsmonitor/failover.py`. The write guard is
`service_order.is_order_intact`.

**UNVERIFIED:** the `networksetup -ordernetworkservices` write has never run
against a real machine. Only tests with fakes cover it. See
[known-issues.md](../known-issues.md), "Unproven".

## When to use

- The preferred link is down and you want traffic on a backup now.
- The preferred link is back and you want the original order restored.
- You are trying failover for the first time. Use manual-only mode
  (`failover_enabled: false`) so nothing switches on its own.

## Preconditions

- The direct build. The Mac App Store build does not allow the write
  (`distribution.detect` sets `network_order_write` to false).
- `~/.config/net-dns-monitor/config.yaml` names both sides. Names must match
  `networksetup -listnetworkserviceorder` exactly:

  ```yaml
  failover_enabled: false                 # false = manual only; true adds automatic switching
  failover_preferred_service: "USB 10/100/1G/2.5G LAN"
  failover_backup_services: ["Wi-Fi"]     # or failover_backup_service: "Wi-Fi"
  ```

- The CLI runs from a source checkout with the project dependencies installed
  (see [DEVELOPMENT.md](../DEVELOPMENT.md)). The program calls itself `netdns`; the
  command is `python3 -m netdnsmonitor.cli`.
- For a first try, unplug the wired adapters. With only Wi-Fi up, a reorder
  changes the stored order but not the active route.

## 1. Check the current state (read-only)

```bash
networksetup -listnetworkserviceorder
python3 -m netdnsmonitor.cli failover status
```

`failover status` prints:

```
Active service : <head of the order> (on the backup | on the preferred link | on neither the preferred link nor a backup)
Automatic      : yes | yes (failback paused after a manual switch; `netdns failover preferred` ends it) | no (manual only)
<table: SERVICE, DEVICE, SVC, REACHABLE, Mbps for the preferred service and each backup>
```

The `paused` form appears only with automatic switching on and a backup at the
head of the order. See [Automatic failback after a manual switch](#automatic-failback-after-a-manual-switch).

`REACHABLE` is `reachable`, `unreachable`, or `not probed`. `not probed` means
the interface is absent or has no device. It does not mean the link is dead.

"Active service" is the head of the service order, not the live default route.
An unplugged adapter at the head still shows as active.

In the menu bar, the three rows at the top show the same state:

```
Active: <service> — failover is automatic | automatic, failback paused after a manual switch | manual only
● Preferred: <name> (<device>) — reachable | unreachable | not probed
○ Backup: <name> (<device>) — ...
```

A filled marker (`●`) marks the service at the head of the order. **Refresh network
status** repaints the rows and posts a notification with the last attempt in this
app session.

## 2. Switch

### From the terminal

```bash
python3 -m netdnsmonitor.cli failover backup                    # the best-ranked backup
python3 -m netdnsmonitor.cli failover backup --service "Wi-Fi"  # a specific configured backup
python3 -m netdnsmonitor.cli failover preferred                 # back to the recorded order
```

`--config PATH` selects another config file, before or after the subcommand.

| Exit code | Meaning |
|---|---|
| 0 | `status` printed, or the outcome starts with `ok:` or `no switch: already on`. `status` also exits 0 when it prints `Failover: could not read the network service order`. |
| 1 | The outcome starts with `failed:` or `NEEDS_PRIVILEGE:`, or it is any other `no switch:`: a third service is at the head of the order, or another switch attempt is already in progress. |
| 2 | Failover is not configured (`Failover: not configured ...`), the config file could not be loaded (`config error: ...` on stderr), or argparse rejected the command line. |
| 130 | Interrupted with Ctrl-C. |

### From the menu bar

- **Switch to backup now** switches to the best-ranked backup. It takes no service
  name. Like `failover backup`, it pauses automatic failback (see below).
- **Switch back to preferred now** restores the recorded order.

Both run on the menu bar's run loop. The menu does not respond until the switch
finishes. The outcome arrives as a notification with the subtitle "Switch to
backup" or "Switch to preferred". If failover is not configured, the notification
says
`Not configured — set failover_preferred_service and failover_backup_service in config.yaml.`

The switch lock is per process. Do not switch from the terminal and the menu at
the same time.

### Automatic failback after a manual switch

A manual switch to a backup, from the menu or with `failover backup`, pauses
automatic failback. The machine stays on the backup until you switch back, even
when the preferred link's probes answer again.

Why: if `failover_probe_targets` point at each link's gateway, a preferred probe
that answers proves only that the local network is up. The ISP link behind the
gateway can still be dead, and an automatic failback would move traffic back onto
it.

- The app records the pause as `"failback_paused": true` in `failover.json` before
  it writes the new order. The running app, the CLI and a restarted app all read
  it from there.
- While the pause is set, the failback check on each healthy tick lists nothing
  and probes nothing.
- `failover status` and the first menu row say `failback paused after a manual
  switch` while a backup heads the order and automatic switching is on.

The pause ends when one of these happens:

- A switch back to preferred (`failover preferred` or **Switch back to preferred
  now**) is confirmed by the read-back. If that switch is refused or cannot be
  confirmed, the pause stays and nothing moves on its own.
- A request for preferred finds the preferred service already at the head of the
  order, for example after you reordered by hand. The outcome is
  `no switch: already on the preferred network`.
- The incident failover step finds the preferred service at the head of the order.
- An automatic failover happens. It sets no pause, so its failback runs as before.

A `failover backup` request that finds the machine already on a backup writes
nothing, so it does not pause the failback of an automatic failover.

**Limit:** after an automatic failover, failback still acts on the probe targets.
With gateway targets it can still return to a dead ISP link. See
[known-issues.md](../known-issues.md), "Decided".

### How a backup is chosen

1. Each configured backup found in the order is probed through its own interface
   (`IP_BOUND_IF`). Reachable backups are benchmarked.
2. The best candidate wins. With `--service`, the named backup wins.
3. If no backup answered, a manual switch still takes the first backup that has a
   device. The outcome then ends with `-- WARNING: this path was not verified reachable`.
4. A disabled backup is enabled first. The app records that, so the failback can
   disable it again.

## 3. Read the outcome

The app claims a switch only after it reads the order back.

| Outcome | Meaning |
|---|---|
| `ok: service order now starts with 'X' (failed over to backup 'X' at N Mbps)` | The read-back confirms X at the head. `(speed not measured)` replaces the speed when no benchmark ran. |
| `... (also enabled the service, which was off)` | The app enabled X before promoting it. |
| `ok: service order now starts with 'P' (failed back to preferred 'P' and disabled 'X' again, which this app had enabled)` | The recorded order is restored, and the enable is undone. |
| `... (the recorded pre-failover order no longer matches the current services, so the preferred link was promoted instead of an exact restore)` | Services were added or removed since the switch. P was moved to the head; the rest kept their current order. |
| `no switch: already on the backup network` / `already on 'X'` / `already on the preferred network` | Nothing to do. Nothing was written. |
| `no switch: '<head>' is at the head of the order, which is neither the preferred link nor a configured backup` | A third service leads. Nothing was written. |
| `no switch: another switch attempt is in progress` | Another thread in this process is switching. |
| `failed: refused to apply a service order that is not a permutation of the current one` | The guard refused. Nothing was written. |
| `failed: the service order changed during the check; nothing was applied` | The re-list right before the write differed. Try again. |
| `failed: could not re-read the service order right before writing; nothing was applied` | `networksetup -listnetworkserviceorder` failed. |
| `failed: networksetup exited N: ...` | The write command failed for a reason other than privilege. |
| `NEEDS_PRIVILEGE: reordering network services was refused; an administrator right is required` | macOS refused the write. The app does not ask for rights for this write. |
| `failed: networksetup reported success but the service order is unchanged` | `networksetup` exited 0 and changed nothing. |
| `failed: could not read the service order back to confirm the change` | The write may or may not have landed. Check with `networksetup -listnetworkserviceorder`. |
| `failed: '<name>' is not one of the configured backups (...)` | `--service` named a service that is not in the config. |

## 4. Verify

```bash
networksetup -listnetworkserviceorder     # the expected service is (1)
route -n get default | awk '/interface:/{print $2}'
python3 -m netdnsmonitor.cli failover status
```

The default route follows the head of the order only when that service has a
working link.

## Restore the recorded order

Before it writes a switch to a backup, the app records the full order when the
preferred side is active or when no record exists yet. A switch from one backup
to another keeps the existing record. The record lives in
`failover_state_path`, by default
`~/Library/Application Support/net-dns-monitor/failover.json`:

```json
{
  "original_order": ["USB 10/100/1G/2.5G LAN", "Wi-Fi", "Thunderbolt Bridge"],
  "enabled_by_us": null,
  "last_switch_at": 1757860000.0,
  "switch_times": [1757860000.0],
  "failback_paused": true
}
```

The app writes the file atomically with mode `0600`. The app and the CLI share it.
`failback_paused` is `true` after a manual switch to a backup and `false` after an
automatic one. A file written before the key existed loads as `false`.

### Normal path

```bash
python3 -m netdnsmonitor.cli failover preferred
```

Or click **Switch back to preferred now**. The failback restores
`original_order` exactly when both conditions hold:

- The recorded names are the same set as the current services.
- The first recorded name is not a configured backup.

Otherwise it promotes the preferred service and says why. After a successful
failback it clears `original_order` and `failback_paused`, and disables any
service it had enabled.

### By hand

Use this only when the app and the CLI cannot run.

```bash
cat ~/Library/Application\ Support/net-dns-monitor/failover.json
networksetup -listnetworkserviceorder
```

Compare the two lists. The command below rewrites the order to exactly the names
you give it. A name you leave out is removed from the service order. Give every
current service, including disabled ones marked `(*)`, each quoted exactly:

```bash
networksetup -ordernetworkservices "USB 10/100/1G/2.5G LAN" "Wi-Fi" "Thunderbolt Bridge"
networksetup -listnetworkserviceorder
```

If `enabled_by_us` names a service, disable it again when you no longer need it:

```bash
networksetup -setnetworkserviceenabled "<name>" off
```

Then clear the record. Quit the app first: a running app keeps the record in
memory and writes it back on its next save.

```bash
rm ~/Library/Application\ Support/net-dns-monitor/failover.json
```

Removing the file also clears the switch timestamps that the automatic cooldown
and hourly cap use, and the failback pause.

## Roll back

- To undo a switch to a backup, switch to preferred. A confirmed switch also ends
  the failback pause.
- To undo a failback, switch to the backup again. The app records a new
  `original_order` first.
