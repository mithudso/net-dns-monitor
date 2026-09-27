# Runbook: recover NAT for the `router/` stack

This runbook covers the `router/` stack only: dnsmasq DHCP and Unbound DNS on
`192.168.4.1`, NAT in the pf anchor `com.apple/custom_nat`, and the LaunchDaemon
`com.custom.router.nat`. The app's own Router menu (`netdnsmonitor/router.py`)
is a different router; see [router/docs/ROUTER.md](../../router/docs/ROUTER.md).

Sources: `router/scripts/enable_nat.sh`, `router/scripts/install_persistent_nat.sh`,
`router/scripts/test_router.sh`, `unbound/install.sh`, and the 2026-09-01 repair
recorded in `memory.md` v1.

## When to use

- LAN clients get a `192.168.4.x` address but cannot reach the internet.
- NAT stopped working after a reboot or after the upstream interface changed.
- The installed LaunchDaemon still runs `enable_nat.sh` from a checkout instead
  of `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh`. This is a
  root-escalation hole; see [SECURITY.md](../SECURITY.md) residual risk 1.

## Preconditions

- An administrator account. Every repair command below uses `sudo`.
- dnsmasq and Unbound are installed and configured with `unbound/install.sh`.
- The LAN adapter carries `192.168.4.1`. No script in this repository assigns
  that address; it is set outside the repository. On 2026-09-01 the LAN adapter
  was `en15` and the upstream was `en13` (`memory.md` v1). Interface names change
  when adapters are re-plugged.
- To reinstall the daemon, use a checkout whose installer copies the script to
  `/Library/PrivilegedHelperTools`. On 2026-09-14 only branch `feat/appstore-prep`
  had that installer. Check it first:

  ```bash
  grep -c PrivilegedHelperTools router/scripts/install_persistent_nat.sh   # must print a number above 0
  ```

- The installer copies the `enable_nat.sh` that sits next to it. Run it from the
  checkout whose `enable_nat.sh` you want installed.

## 1. Diagnose (read-only)

Run from the repository root.

```bash
# Which interface holds 192.168.4.1, and which holds the default route.
ifconfig -a | awk '/^[a-z]/{i=$1} /inet 192\.168\.4\.1 /{print i}'
route -n get default | awk '/interface:/{print $2}'

# Forwarding must be 1.
sysctl -n net.inet.ip.forwarding

# pf must be enabled, and the anchor must hold a "nat on" rule.
sudo pfctl -s info | grep Status
sudo pfctl -a com.apple/custom_nat -s nat

# DNS from Unbound, and DHCP from dnsmasq.
dig @192.168.4.1 google.com +short +time=2 +tries=1
sudo lsof -nP -iUDP:67 | grep dnsmasq

# What the daemon runs, and what it logged last.
plutil -p /Library/LaunchDaemons/com.custom.router.nat.plist
tail -n 20 /var/log/com.custom.router.nat.out.log
tail -n 20 /var/log/com.custom.router.nat.err.log

# The full suite of checks. Run with sudo so the pf checks are not skipped.
sudo router/scripts/test_router.sh
```

Read the results:

| Observation | Meaning |
|---|---|
| `ProgramArguments` points into a checkout (for example `/Users/.../router/scripts/enable_nat.sh`) | The daemon is the old, unsafe install. Do step 3. |
| `err.log` ends with `ERROR: no default route after 60s — cannot determine the upstream` | The Mac had no default route for 60 s. NAT was not configured on that run; forwarding stayed enabled. Fix the upstream link first. |
| `err.log` shows `ALTQ related functions disabled` or `No ALTQ support in kernel` | pfctl prints these on every run. They are not failures. |
| `out.log` ends with `✅ NAT configured.` and the `nat on` line names the current upstream | The last run succeeded. Look at clients, DNS or DHCP instead. |
| `pfctl -a com.apple/custom_nat -s nat` prints nothing | No NAT rule is loaded. Do step 2. |
| No `dnsmasq` on UDP 67 | Apple's `bootpd` job or another process holds the port. `enable_nat.sh` unloads `bootps`; then run `sudo brew services restart dnsmasq`. |
| `dig` prints nothing or a line starting with `;` | Unbound did not answer. Run `sudo brew services restart unbound`. |

## 2. Reapply NAT now

```bash
sudo router/scripts/enable_nat.sh
```

The script does the following, in order:

1. Unloads `/System/Library/LaunchDaemons/bootps.plist`, moves `/etc/bootpd.plist`
   to `/etc/bootpd.plist.bak`, and kills `bootpd`.
2. Sets `net.inet.ip.forwarding=1`.
3. Waits up to 60 s for a default route and takes its interface as the upstream.
   It exits 1 if no route appears.
4. Loads `nat on <upstream> from 192.168.4.0/24 to any -> (<upstream>)` into
   `com.apple/custom_nat`.
5. Enables pf and prints the pf status and the anchor's rules.

Expected end of output: `Status: Enabled`, a `nat on` line, and
`✅ NAT configured.`

If the daemon is installed, it runs the same script every 60 s. A manual run is
needed only when you cannot wait for the next run.

## 3. Reinstall the persistent daemon with the fixed installer

```bash
sudo router/scripts/install_persistent_nat.sh
```

The installer does the following, in order:

1. Refuses if `/Library/PrivilegedHelperTools/net-dns-monitor` or the helper path
   is a symlink.
2. Installs a copy of `enable_nat.sh` at
   `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh`, owned by
   `root:wheel`, mode `755`.
3. Writes the plist to a temporary file inside `/Library/LaunchDaemons`, sets
   `root:wheel` and `644`, and checks it with `plutil -lint`.
4. Unloads the existing daemon, renames the new plist to
   `/Library/LaunchDaemons/com.custom.router.nat.plist`, and loads it with
   `launchctl load -w`.

The new plist sets `RunAtLoad`, `StartInterval` 60,
`StandardOutPath` `/var/log/com.custom.router.nat.out.log` and
`StandardErrorPath` `/var/log/com.custom.router.nat.err.log`.

After you edit `enable_nat.sh`, run the installer again. The daemon runs the
installed copy, not the file in the repository.

## 4. Verify

```bash
# The daemon runs the root-owned copy.
plutil -p /Library/LaunchDaemons/com.custom.router.nat.plist | grep -A2 ProgramArguments
ls -ld /Library/PrivilegedHelperTools/net-dns-monitor
ls -l /Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh

# launchd loaded the job. Look for the program path, the run interval and the last exit code.
sudo launchctl print system/com.custom.router.nat

# Within about 60 s a new run appears in the log.
tail -n 8 /var/log/com.custom.router.nat.out.log

# NAT, DNS and DHCP.
sudo pfctl -a com.apple/custom_nat -s nat
dig @192.168.4.1 google.com +short +time=2 +tries=1
sudo router/scripts/test_router.sh
```

Pass criteria:

- `ProgramArguments` is `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh`.
- The directory and the script are owned by `root` and group `wheel`, and neither
  is group- or world-writable.
- The anchor shows `nat on <current upstream> ... from 192.168.4.0/24`.
- `dig` prints at least one address.

Clients that took a lease while NAT was down may need a DHCP renewal, a
reconnect, or a reboot (`memory.md` v1).

## Roll back

Unload the daemon first. While it is loaded, it re-applies NAT and forwarding
every 60 s and undoes any manual change.

```bash
# Remove the persistent daemon and its helper.
sudo launchctl unload -w /Library/LaunchDaemons/com.custom.router.nat.plist
sudo rm -f /Library/LaunchDaemons/com.custom.router.nat.plist
sudo rm -rf /Library/PrivilegedHelperTools/net-dns-monitor

# Remove the NAT rule. Flush the anchor only: `pfctl -d` would disable pf for everything else.
sudo pfctl -a com.apple/custom_nat -F all

# Stop routing for LAN clients.
sudo sysctl -w net.inet.ip.forwarding=0

# Only if Apple's bootpd served DHCP before this stack: restore its config and job.
sudo mv /etc/bootpd.plist.bak /etc/bootpd.plist
sudo launchctl load -w /System/Library/LaunchDaemons/bootps.plist
```

Do not restore an older plist that points `ProgramArguments` into a checkout. That
plist runs a user-writable script as root.

After the daemon plist is gone, the app's Router menu stops refusing to start.
The two stacks conflict; see [router/docs/ROUTER.md](../../router/docs/ROUTER.md).
