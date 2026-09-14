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
