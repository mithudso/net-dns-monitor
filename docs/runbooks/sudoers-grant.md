# Runbook: grant and revoke elevated permissions

The grant is one sudoers file that lets your account run two exact root
commands without a password. The implementation is `netdnsmonitor/privileges.py`.
The threat analysis is in [SECURITY.md](../SECURITY.md) section 1.

**UNVERIFIED:** no test or live run has written the file through the app. The
tests inject a fake `run_fn`.

## When to use

- Grant: "Flush DNS cache" reports `partial: ... requires elevated privilege`,
  or "renew DHCP lease" reports `NEEDS_PRIVILEGE`, and you want both repairs to
  run fully.
- Grant again: the dashboard's "Renew DHCP lease" row says the default route is
  on an interface the grant does not cover. This happens after a new Ethernet
  adapter appears.
- Revoke: you no longer want any process running as your account to run these
  commands as root without a prompt.

## What the grant writes

| Property | Value |
|---|---|
| Path | `/etc/sudoers.d/net-dns-monitor` |
| Owner and mode | `root:wheel`, `0440` |
| Account | The account the app process runs as (`pwd.getpwuid(os.getuid())`) |
| Rules | `<account> ALL=(root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder`, plus `<account> ALL=(root) NOPASSWD: /usr/sbin/ipconfig set <enN> DHCP` for each `en` interface in `ifconfig -l` at grant time |

The file has no wildcard and no shell. `toggle_network_service` is never granted;
it reports `NOT_AUTOMATED`.

## Preconditions

- The direct build. In the Mac App Store build, `distribution.detect` sets
  `privileged_repairs` to false, because store apps may not request root.
- An administrator account. macOS asks for a password or Touch ID.
- `/etc/sudoers` includes `/etc/sudoers.d`. Check it:

  ```bash
  sudo grep -E '^[@#]includedir[[:space:]]+/(private/)?etc/sudoers[.]d' /etc/sudoers
  ```

  If this prints nothing, the grant refuses and changes nothing. The app never
  edits `/etc/sudoers`.
- The app has run for a few seconds. Until its launch probe has listed the
  interfaces, the Grant button prints
  `Still working out which interfaces to authorise -- try again in a moment`.

## Grant from the app

1. In the menu bar, choose **Open dashboard**.
2. Click **Grant elevated permissions (changes system state)**.
3. Read the explanation in the output pane. It lists every command the file will
   permit.
4. Approve the macOS authentication dialog, or cancel it.

| Output pane text | Meaning |
|---|---|
| `Granted. /etc/sudoers.d/net-dns-monitor now permits: ...` | The script exited 0. The file is in place. |
| `Cancelled -- nothing was changed.` | You cancelled the dialog. |
| `/etc/sudoers does not include /etc/sudoers.d, so a file placed there would be ignored. Nothing was changed. ...` | The include line is missing. |
| `visudo rejected the generated file, so it was discarded and nothing was changed. This is a bug -- please report it.` | Validation failed. No file was installed. |
| `refusing to write a sudoers rule for the account name ...` or `... for the interface ...` | Input validation refused the value before any prompt. |
| `No Ethernet or Wi-Fi interface was found, so there is no DHCP renewal to authorise. Nothing was changed.` | `ifconfig -l` listed no `en` interface. |
| `Still working on the previous permission change.` | A grant or revoke is still running. |

The privileged script runs these steps as root, in one `osascript` call:

1. Exit 3 unless `/etc/sudoers` includes `/etc/sudoers.d`.
2. `mkdir -p /etc/sudoers.d`.
3. Create a staging file `/etc/sudoers.d/.net-dns-monitor.tmp.XXXXXX`. Sudo
   ignores file names that contain a dot.
4. Decode the base64 body into it, then `chown root:wheel` and `chmod 0440`.
5. Run `visudo -cf` on it. On failure, delete it and exit 4.
6. Rename it to `/etc/sudoers.d/net-dns-monitor`.

## Verify

The dashboard's **Permissions** section shows the result:

| Row | Granted value |
|---|---|
| Elevated permissions | `granted` |
| Sudoers file | `/etc/sudoers.d/net-dns-monitor` |
| Restart mDNSResponder | `yes -- Flush DNS cache fully clears DNS` |
| Renew DHCP lease | `yes -- on <interface>` |
| Interfaces the grant covers | the `en` interfaces in the file |

If "Sudoers file" reads `(absent -- another NOPASSWD rule grants this)`, another
rule on this Mac grants the commands and the app's file is not there.

Check from a terminal:

```bash
# What the app itself runs. -n never prompts; -k ignores a cached credential.
sudo -n -k -l

# The file, its owner and mode, and its syntax.
ls -l /etc/sudoers.d/net-dns-monitor          # expect -r--r----- root wheel
sudo cat /etc/sudoers.d/net-dns-monitor
sudo visudo -cf /etc/sudoers.d/net-dns-monitor

# The whole sudoers configuration.
sudo visudo -c
```

`sudo -n -k -l` lists `(root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder` and
one `(root) NOPASSWD: /usr/sbin/ipconfig set <enN> DHCP` line per covered
interface. It exits non-zero when no `NOPASSWD` entry exists for this account.

For an end-to-end check, click **Flush DNS cache (changes system state)** in the
dashboard. With the grant, the outcome is
`ok (mDNSResponder restarted using the granted privilege)`. This restarts the DNS
responder, which interrupts name resolution briefly.

## Revoke from the app

1. In the menu bar, choose **Open dashboard**.
2. Click **Revoke elevated permissions**.
3. Approve the macOS authentication dialog.

The script runs `/bin/rm -f /etc/sudoers.d/net-dns-monitor` as root. On success
the output pane says `Revoked. /etc/sudoers.d/net-dns-monitor is gone, ...`.
Other sudoers rules on this Mac are unaffected.

Verify with `ls -l /etc/sudoers.d/net-dns-monitor` (expect `No such file or
directory`) and `sudo -n -k -l`.

## Remove by hand

Use this when the app is not available.

```bash
sudo rm -f /etc/sudoers.d/net-dns-monitor
# Staging files left by an interrupted grant, if any.
sudo find /etc/sudoers.d -maxdepth 1 -name '.net-dns-monitor.tmp.*' -print -delete
sudo visudo -c
sudo -n -k -l
```

A staging file left behind is inert, because sudo ignores names that contain a
dot.

If `sudo` itself fails because of a broken file in `/etc/sudoers.d`, remove the
file without sudo. This is the command the Revoke button runs:

```bash
osascript -e 'do shell script "/bin/rm -f /etc/sudoers.d/net-dns-monitor" with administrator privileges'
```

## Roll back

- To undo a grant, revoke it.
- To undo a revoke, grant again. The app writes a new file from the interfaces
  present now, which can differ from the previous file.
