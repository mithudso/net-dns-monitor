# Remediation scripts

Every step on the troubleshooting ladder — each check the app runs and each repair it
attempts — is a short Python file. You can read them, change them, switch them off, and
add your own, from **Edit remediation scripts** (status-item menu, or the dashboard
button) without touching the app's source.

This is the author's manual: the file format, everything a script can call, the rules a
script must keep, and each shipped script.

- [Where scripts live](#where-scripts-live)
- [The editor](#the-editor)
- [Anatomy of a script](#anatomy-of-a-script)
- [The `ctx` object](#the-ctx-object)
- [Writing outcome strings](#writing-outcome-strings)
- [Adding a custom script](#adding-a-custom-script)
- [What happens when a script misbehaves](#what-happens-when-a-script-misbehaves)
- [Rules every script keeps](#rules-every-script-keeps)
- [The App Store edition](#the-app-store-edition)
- [The shipped scripts](#the-shipped-scripts)

## Where scripts live

| What | Where |
|---|---|
| Shipped scripts (read-only) | `netdnsmonitor/remediations/<name>.py` |
| Your edits and your own scripts | `~/Library/Application Support/net-dns-monitor/remediations/<name>.py` |

Editing a shipped script saves a file of the **same name** in your folder. That file wins.
**Reset** deletes it, which restores the shipped script exactly; saving text identical to
the shipped script also removes the override. A script with a name the app does not ship
is a **custom** script. The folder is created mode `0700` and files `0600`, because a
file there is code the app runs as you.

Set `NETDNS_REMEDIATION_DIR` to use a different folder.

Edits take effect on the next incident. Nothing needs a restart: the folder is read each
time a step runs.

## The editor

Open it from the status-item menu (**Edit remediation scripts**) or the dashboard
(**Edit remediation scripts (Python editor)**).

| Control | What it does |
|---|---|
| Script picker | Lists every script with its origin: `built-in`, `built-in, modified`, `custom`; `INVALID` and `off` are flagged. |
| **Save** | Checks the text, then writes it. Refuses anything **Check** refuses. |
| **Check** | Compiles the text and validates the metadata. Runs nothing. |
| **Run test** | Runs the text in the editor, saved or not, **for real**, through the same executor an incident uses, and prints the outcome, any `ctx.log` lines, and — here only — a traceback. A script of `KIND = "repair"` asks first. |
| **Reset… / Delete…** | Resets a modified built-in to the shipped script, or deletes a custom script. Asks first. |
| **New…** | Starts a custom script from a documented template. Nothing is written until **Save**. |

The lower pane shows the script's description (its docstring) until you run a test.
Python syntax is coloured as you type. Smart quotes, smart dashes and autocorrect are off,
because a curly quote is a syntax error that looks identical on screen.

## Anatomy of a script

```python
"""my_check -- one line saying what this does.

Everything here is shown as the script's description in the editor. Say what it
reads or changes and what each outcome means.
"""

NAME = "my_check"  # required; must equal the file name (my_check.py)
KIND = "check"  # required; "check" reads only, "repair" changes something
NEEDS_PRIVILEGE = False  # True if it needs the sudoers grant
REASON = "Why this is worth running."  # recorded in the forensic log
CLASSIFICATIONS = ("dns",)  # custom scripts: which incidents run it ("network", "dns")
ORDER = 100  # custom scripts: lower runs earlier
ENABLED = True  # False keeps the file but leaves it off the ladder


def run(ctx):
    return "ok: it worked"
```

The constants must be **literals** (`ast.literal_eval`): the editor lists scripts by
reading the syntax tree and never runs one to list it. `run(ctx)` must return a
non-empty string.

For the **shipped** steps, the ladder order and the `KIND`, `NEEDS_PRIVILEGE` and `REASON`
tags come from `netdnsmonitor/ladder.py`; changing those constants in an override of a
shipped script does not move or retag the step. What an override can change is `run`, and
`ENABLED` (`False` makes the step report `skipped:`). Custom scripts take all their
metadata from the file.

Where a custom script lands: after every shipped step and **before** the failover step,
ordered by `ORDER` then name. A custom step cannot push the network switch earlier.

## The `ctx` object

A script reaches the machine only through `ctx`. It must not import `socket`,
`subprocess`, `os` or `urllib` itself (the shipped scripts do not, and a test enforces
it): that is what lets the whole suite run every script against fakes, and it is how the
privilege and sandbox rules stay in one place. The standard library's pure modules
(`re`, `json`, `textwrap`) are fine.

**What the step is responding to**

| Name | Meaning |
|---|---|
| `ctx.step_name` | The step's name. |
| `ctx.classification` | `"network"` or `"dns"` for an incident; `None` for a manual step run with no classification. |
| `ctx.probe_domain` | The domain the public-resolver check asks about (`example.com`). |

**Running things**

| Name | Meaning |
|---|---|
| `ctx.run(args)` | Run a command (a list of strings, 5-second limit). Returns an object with `.returncode`, `.stdout`, `.stderr`. **Never raises.** If the command did not run to completion (timed out, binary missing) `returncode` is `None` and `stderr` holds the exception *class name*. |
| `ctx.did_not_complete(result)` | `True` when `result.returncode is None`. Check this before reading `returncode`: `None` is not `0` and not `1`. |
| `ctx.report_command(args)` | For checks. Runs the command and returns its output, `no output from …`, or a `failed: …` line. Never an empty string. |

Use absolute paths for binaries; the app's `PATH` is whatever `launchd` handed it.

**Tools** (`ctx.tools`)

| Name | Value |
|---|---|
| `ctx.tools.DSCACHEUTIL` | `/usr/bin/dscacheutil` |
| `ctx.tools.SCUTIL` | `/usr/sbin/scutil` |
| `ctx.tools.NETSTAT` | `/usr/sbin/netstat` |
| `ctx.tools.SUDO` | The `sudo` the grant is written for. |
| `ctx.tools.IPCONFIG` | `ipconfig`, the binary the DHCP grant names. |
| `ctx.tools.KILLALL` | `killall`, the binary the mDNSResponder grant names. |
| `ctx.tools.MDNS_HUP` | The exact argv for `killall -HUP mDNSResponder`. |
| `ctx.tools.ALL_INTERFACES_SENTINEL` | What the covered-interfaces list holds when the grant names every interface. |
| `ctx.tools.RESOLVER_DIR` | `/etc/resolver` |
| `ctx.tools.GRANT_HINT` | The sentence pointing at the **Grant elevated permissions** button. |

**DNS and files**

| Name | Meaning |
|---|---|
| `ctx.query_public_dns(domain)` | Ask a public DNS server (not the system resolver). Returns `True`, `False` or `None`. `None` means *no usable reply* and says nothing about the name — do not treat it as `False`. |
| `ctx.resolver_dir_exists(path)` | `os.path.isdir`, injectable. |
| `ctx.listdir(path)` | `os.listdir`, injectable. May raise `OSError`. |

**Privilege and build**

| Name | Meaning |
|---|---|
| `ctx.is_granted()` | `True` if the sudoers grant for the mDNSResponder restart is installed. |
| `ctx.dhcp_granted` | `None`, or a function `dhcp_granted(interface) -> bool` for the per-interface DHCP grant. Test for `None` before calling. |
| `ctx.covered_interfaces()` | Interfaces the grant names; empty means unknown. |
| `ctx.primary_interface()` | The Ethernet/Wi-Fi interface holding the default route, or `None` (none, or a VPN tunnel holds it). |
| `ctx.needs_privilege(step)` | The standard `NEEDS_PRIVILEGE: …` outcome text, with the hint. |
| `ctx.unavailable(what)` | `None` in the direct build. In the App Store build, the text saying this build does not do `what`. If it is not `None`, return it and do nothing else. |
| `ctx.failover` | `None`, or a function `failover(classification) -> str` that performs the network switch. The only sanctioned way to change the service order. |

**Logging**

| Name | Meaning |
|---|---|
| `ctx.log(message)` | A note shown in the editor's test run. Never recorded in a report. |
| `ctx.log_lines` | The list those notes accumulate in. |

## Writing outcome strings

The returned string goes into the incident report, the forensic log and the alert, and
people act on it. The first word is the contract; the CLI's exit code reads it too.

| Starts with | Means |
|---|---|
| `ok` | It did what it set out to do, and you observed that. |
| `partial:` | Part of it happened. Say which part. |
| `unknown:` | It may or may not have happened (a command timed out after it might have taken effect). |
| `failed:` | It was attempted and did not work, or could not be attempted. |
| `NEEDS_PRIVILEGE:` | Refused for want of the grant (use `ctx.needs_privilege`). |
| `cannot …:` | A precondition failed; nothing was changed. |
| `NOT_AUTOMATED:` | By design, never runs. |
| `skipped:` | Switched off. |
| anything else | A check's finding (command output, a sentence). |

## Adding a custom script

1. **New…** in the editor, give it a name (`restart_vpn_client`: lowercase letters, digits,
   underscores).
2. Edit `CLASSIFICATIONS` to say which incidents run it, and set `KIND` honestly.
3. **Check**, **Run test**, **Save**.

It runs on the next incident of that classification, after the shipped steps. It appears
in the report like any other step, under its `NAME`, with your `REASON`.

## What happens when a script misbehaves

Nothing it does can cost the incident its report.

- **Raises** (including `SystemExit`): the outcome is `failed: the <name> step raised
  <ExceptionClass>`. The exception *message* is never recorded — it can contain command
  output or a URL.
- **Takes longer than 60 seconds:** `unknown: <name> did not finish within 60s`. The
  script keeps running in the background (Python cannot stop a thread); stop writing
  loops with no exit.
- **Returns `None`, a non-string or an empty string:** `failed: the <name> script
  returned …`.
- **Does not compile, or has bad metadata:** the step reports `failed: the <name> script
  is invalid (…)` and does **not** fall back to the shipped logic — you replaced it on
  purpose, and silently running the old version would report a repair your change was
  meant to avoid. A custom script like this is left off the ladder. **Reset** the
  shipped one, or fix it.

## Rules every script keeps

These are the repository's non-negotiables (`CLAUDE.md`), restated for script authors.

1. **Never claim a repair that did not happen.** `ok` only for what you observed. A
   signal that was sent but not read back is "sent", not "restarted". Half-done is
   `partial:`.
2. **`None` is not `False`.** A probe that did not run is *unknown*. `ctx.query_public_dns`
   returns `None` for that; a command that did not complete has `returncode is None`.
3. **Touch the machine only through `ctx`.**
4. **No secret in a return value.** Never put an exception message, a URL, or a
   credential in the string you return. Return the class name or an exit status.
5. **Never build a `networksetup -ordernetworkservices` command.** It rewrites the
   service order to exactly the list it is given; a name dropped is a service deleted.
   Call `ctx.failover`, which checks, re-reads, writes and reads back.
6. **Do not run an interface-down/up pair as two commands.** An interruption between
   them leaves the machine offline with no network to repair it over.

## The App Store edition

The Mac App Store build runs the **shipped scripts only**. It has no editor, ignores any
folder of overrides, and runs no custom script, because executing code the user wrote is
not permitted there (Guideline 2.5.2). The shipped scripts are signed files inside the
app bundle. `ctx.unavailable` is how the two root-requiring scripts say they were not
attempted.

## The shipped scripts

Each script's docstring is the full reference; this is the index. Ladder order is
`netdnsmonitor/ladder.py`'s.

### Network ladder

| Script | Kind | Does |
|---|---|---|
| `check_interface_state` | check | `scutil --nwi`: is the link up and which interface is primary. |
| `check_default_route` | check | `netstat -rn` for IPv4 and IPv6; `partial:`/`failed:` prefix if a table could not be read. |
| `renew_dhcp_lease` | repair, needs grant | `sudo -n ipconfig set <if> DHCP`, only on an interface that already holds a lease, because the command replaces a hand-set address. |
| `toggle_network_service` | repair | Never automated; returns `NOT_AUTOMATED:` and why. |
| `switch_to_backup_network` | repair, needs grant | Calls `ctx.failover`; the last rung, after every cheaper repair. |

### DNS ladder

| Script | Kind | Does |
|---|---|---|
| `check_configured_dns_servers` | check | `scutil --dns`: which resolvers are in use. |
| `check_resolver_overrides` | check | Lists `/etc/resolver`; a listing error is `failed:`, never "none". |
| `flush_dns_cache` | repair | `dscacheutil -flushcache`, then an mDNSResponder HUP (through the grant if installed). `ok` only if both worked; `partial:` otherwise. |
| `resolve_against_public_resolver` | check | Asks a public resolver for `ctx.probe_domain`; `None` (no reply) is reported as saying nothing about the name. |

`switch_to_backup_network` is on the ladder only for classifications the failover
configuration allows (`failover_trigger_classifications`).
