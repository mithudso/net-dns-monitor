# Work Memory

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
