"""Grant the two repair steps the rights they need, once, from a button.

Two repair paths used to report that they lacked privilege and offer no way to
acquire it:

* `repair_executor.flush_dns_cache` clears the cache successfully and then fails
  to signal mDNSResponder, because that process is owned by root. Without a grant
  it still reports a `partial` outcome -- now with a pointer to this button.
* `renew_dhcp_lease` (tagged `needs_privilege=True` in ladder.py) returned a
  `NEEDS_PRIVILEGE` stub unconditionally. With a grant it runs.

`toggle_network_service` is the third `needs_privilege=True` step and is *not* in
that list: it is withheld by choice rather than for want of permission, and now
says so with its own `NOT_AUTOMATED` outcome. See "WHAT IS DELIBERATELY NOT
GRANTED" below.

WHAT THIS INSTALLS, AND WHAT IT MEANS

The grant writes a single file, `/etc/sudoers.d/net-dns-monitor`, owned by
root:wheel with mode 0440. It lists the user's own account and an explicit set of
complete commands that account may then run as root without being asked for a
password.

This is a real and permanent widening of what this Mac will do without
authenticating. Once the file is in place, any process running as this user --
not only this app, and including software the user did not install deliberately
-- can run exactly those commands as root, with no prompt. That is the entire
point of the grant, and it is also its cost, so it is worth being precise about
what is on the list:

  /usr/bin/killall -HUP mDNSResponder     restarts the system DNS responder
  /usr/sbin/ipconfig set <interface> DHCP re-requests a DHCP lease

Both are complete command lines, not patterns: sudo matches the arguments too, so
the grant does not extend to `killall` in general or to `ipconfig` with other
arguments. Neither command takes a file path, neither reads or writes user data,
and neither can be made to run another program. There is no wildcard anywhere in
the file, and no shell: a rule permitting `/bin/sh` -- or any command with a `*`
in its arguments -- would be equivalent to handing over unrestricted root, which
is why the interfaces are enumerated at grant time and validated before they are
written. Every use is logged by sudo.

The worst realistic outcome of the grant being abused is a briefly interrupted
network connection on this machine. The user can withdraw it at any time with the
Revoke button, which deletes the file.

WHAT IS DELIBERATELY NOT GRANTED

`toggle_network_service` stays a stub. Bringing an interface down and back up
cannot be done as one command, and the only way to make it one command is to
allow a shell to run as root -- which, as above, is the same as granting
unrestricted root. Two separate calls are worse than the problem they solve: if
the app dies between them, or the machine sleeps, the interface stays down and the
user is offline with no network to fix it over. So the step reports why it is not
automated instead.

WHAT SUDO CANNOT FIX

macOS redacts private data in the unified log, so DNS queries read
`qname: <mask.hash: '+ii6T0lMiN55NCEFRMdtqQ=='>` rather than a hostname. That is
a logging configuration profile, not a permission, and no amount of sudo reveals
it. See system_log.py.

IMPLEMENTATION NOTES

The privileged work happens inside one `osascript ... with administrator
privileges` call, which is what raises the standard macOS authentication dialog.
The script it runs is passed inline rather than written to a file and executed,
so there is no moment where root is running something from a path that could be
swapped underneath it.

It refuses to do anything unless `/etc/sudoers` actually includes
`/etc/sudoers.d`, and it validates the file with `visudo -cf` before moving it
into place -- a syntactically invalid file in `sudoers.d` breaks `sudo` for the
whole machine, which is a considerably worse outcome than the missing privilege.
It never edits `/etc/sudoers` itself.

Every subprocess is injected, so no test in this suite runs `osascript`, prompts
for a password, or touches `/etc/sudoers.d`.
"""

import base64
import re
import subprocess
from collections.abc import Iterable
from typing import Callable, Optional

RunFn = Callable[..., object]

SUDOERS_MAIN = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"
SUDOERS_PATH = "/etc/sudoers.d/net-dns-monitor"

KILLALL = "/usr/bin/killall"
IPCONFIG = "/usr/sbin/ipconfig"
SUDO = "/usr/bin/sudo"
OSASCRIPT = "/usr/bin/osascript"

# The command `is_granted` probes. `sudo -n -k -l <command>` exits 0 only if this
# account may run it without a password -- see status_command for why each of those
# three flags is load-bearing. It reports on the command without running it;
# checking by running it would restart the DNS responder every time the window
# refreshed.
MDNS_HUP = (KILLALL, "-HUP", "mDNSResponder")

# Only physical Ethernet and Wi-Fi interfaces. `ifconfig -l` also lists loopback,
# utun tunnels, bridges, and awdl; a DHCP lease on any of those is meaningless.
#
# `\Z`, not `$`: Python's `$` also matches immediately before a trailing newline,
# so `^en\d+$` accepts "en0\n" -- which would emit a sudoers rule split across two
# physical lines. visudo would reject the result, but this is the validation
# boundary for a file that grants root, and it should not be relying on a
# downstream check to catch input it claimed to have refused.
_INTERFACE_RE = re.compile(r"^en\d+\Z")

# macOS account names allow dots (mitch.hudson). Anything outside this set is
# refused rather than escaped: this string is written into a file that grants
# root, and there is no legitimate account name it excludes. `\Z` for the same
# reason as above.
_USER_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")

# Markers the privileged script emits so the caller can explain a refusal rather
# than reporting a bare non-zero exit.
MISSING_INCLUDEDIR = "NET_DNS_MONITOR_NO_INCLUDEDIR"
INVALID_SUDOERS = "NET_DNS_MONITOR_INVALID_SUDOERS"

# A cancelled authentication dialog. AppleScript reports it as error -128, which
# osascript renders as "User canceled. (-128)".
#
# Anchored on the parenthesised number rather than a bare `"-128" in stderr`
# substring test, which was the first version and was wrong: an unrelated failure
# reported as "(-12800)" contains the sequence "-128" and was therefore announced
# to the user as "Cancelled -- nothing was changed." That is the one message that
# must never appear for a real failure, because it tells someone their machine is
# untouched at the exact moment something has gone wrong.
_CANCELLED_RE = re.compile(r"\(-128\)|user cancell?ed", re.IGNORECASE)

# Shown in the window before the authentication dialog appears, because "grant
# elevated permissions" is not a thing anyone should click without being told
# what it does.
EXPLANATION = """Granting elevated permissions writes /etc/sudoers.d/net-dns-monitor,
owned by root, mode 0440. It lets your account run these exact commands as root
without a password prompt:

    {commands}

What that means: from then on, any process running as you -- not only this app --
can run those specific commands as root with no prompt. sudo logs each use. The
commands cannot take a file path, cannot read or write your data, and cannot run
another program; the worst they can do is briefly interrupt this machine's own
network. There are no wildcards in the file and no shell.

Without this, "Flush DNS cache" only half works (the cache is cleared but
mDNSResponder is not restarted) and "renew DHCP lease" does not run at all.

macOS will ask for your password or Touch ID. "Revoke elevated permissions"
deletes the file and puts everything back."""


def dhcp_interfaces(run_fn: RunFn = subprocess.run) -> list[str]:
    """The Ethernet and Wi-Fi interfaces on this machine, in `ifconfig -l` order.

    Enumerated so the sudoers file can name each one explicitly. A rule of
    `ipconfig set * DHCP` would be shorter and is exactly the kind of wildcard
    that turns a narrow grant into a broad one.
    """
    try:
        result = run_fn(
            ["/sbin/ifconfig", "-l"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return []
    if getattr(result, "returncode", 1) != 0:
        return []
    return [name for name in (result.stdout or "").split() if _INTERFACE_RE.match(name)]


def primary_interface(run_fn: RunFn = subprocess.run) -> Optional[str]:
    """Whichever interface currently carries the default route.

    Read-only and unprivileged. Used to decide which interface a DHCP renewal
    should target; the grant covers all of them, so the answer only has to be
    right, not authorised.
    """
    try:
        result = run_fn(
            ["/sbin/route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return None
    for line in (getattr(result, "stdout", "") or "").splitlines():
        key, _, value = line.strip().partition(":")
        if key.strip() == "interface":
            candidate = value.strip()
            if _INTERFACE_RE.match(candidate):
                return candidate
    return None


def granted_commands(interfaces: Iterable[str]) -> list[list[str]]:
    """Every command the grant covers, as argv lists -- the single source of truth
    for the sudoers file, the explanation text, and the status check.
    """
    commands = [list(MDNS_HUP)]
    commands.extend([IPCONFIG, "set", name, "DHCP"] for name in interfaces)
    return commands


def describe_commands(interfaces: Iterable[str]) -> str:
    return "\n    ".join(" ".join(command) for command in granted_commands(interfaces))


def explanation(interfaces: Iterable[str]) -> str:
    return EXPLANATION.format(commands=describe_commands(interfaces))


def sudoers_body(user: str, interfaces: Iterable[str]) -> str:
    """The file's contents.

    Raises ValueError on anything it will not write. This function is the boundary
    between user- or system-supplied strings and a file that grants root, so it
    validates rather than escapes: an account name or interface name outside the
    permitted character set is refused, not quoted.
    """
    if not _USER_RE.match(user or ""):
        raise ValueError(
            f"refusing to write a sudoers rule for the account name {user!r}: "
            "only letters, digits, dot, underscore and hyphen are accepted"
        )
    names = list(interfaces)
    for name in names:
        if not _INTERFACE_RE.match(name):
            raise ValueError(
                f"refusing to write a sudoers rule for the interface {name!r}: "
                "expected a name like en0"
            )

    lines = [
        '# Written by Net-DNS-Monitor\'s "Grant elevated permissions" button.',
        "#",
        f"# Lets {user} run exactly the commands below as root without a password.",
        "# Each is a complete command line: sudo matches the arguments too, so this",
        "# does not permit killall or ipconfig in general. No wildcards, no shell.",
        "#",
        "# Delete this file to withdraw the grant, or use the Revoke button in the",
        "# app's window. Do not edit it by hand: an invalid file in sudoers.d breaks",
        "# sudo for the whole machine.",
        "",
    ]
    lines.extend(
        f"{user} ALL=(root) NOPASSWD: {' '.join(command)}" for command in granted_commands(names)
    )
    return "\n".join(lines) + "\n"


def _applescript_string(text: str) -> str:
    """Escape for embedding in an AppleScript double-quoted string literal."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _install_script(body: str) -> str:
    """The shell script run as root.

    The file's contents travel base64-encoded. That is not for secrecy -- the text
    is shown to the user beforehand -- but because base64 is alphanumeric plus
    `+/=`, so a comment or an account name cannot terminate a quote or inject a
    second command on its way through two layers of interpretation (AppleScript,
    then sh).
    """
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return "; ".join(
        [
            "set -e",
            # A file in sudoers.d that nothing includes is a grant that silently
            # does not work, which is worse than a refusal: the button would say
            # "granted" and the repairs would keep failing.
            f"if ! /usr/bin/grep -Eq '^[@#]includedir[[:space:]]+/(private/)?etc/sudoers[.]d'"
            f" {SUDOERS_MAIN}; then echo {MISSING_INCLUDEDIR} >&2; exit 3; fi",
            f"/bin/mkdir -p {SUDOERS_DIR}",
            # Staged *inside* sudoers.d, not in a temp directory, and the mkdir
            # above therefore has to come first.
            #
            # A bare `mktemp` lands in $TMPDIR, and `do shell script` inherits the
            # invoking user's environment -- so the staging file could sit in a
            # directory that user owns. That opens a window between `visudo -cf`
            # and `mv` in which unprivileged code could swap the validated file for
            # an arbitrary one, and land it at SUDOERS_PATH unvalidated. sudoers.d
            # is root-only, which closes the window; it also makes the final move a
            # same-directory rename rather than a cross-filesystem copy.
            #
            # The leading dot matters: sudo ignores files in sudoers.d whose names
            # contain a `.`, so even a staging file left behind by an interrupted
            # run is inert rather than half-active.
            f"tmp=$(/usr/bin/mktemp {SUDOERS_DIR}/.net-dns-monitor.tmp.XXXXXX)",
            f'echo {encoded} | /usr/bin/base64 -D > "$tmp"',
            '/usr/sbin/chown root:wheel "$tmp"',
            '/bin/chmod 0440 "$tmp"',
            # Validated before it is anywhere sudo will read it. A syntax error
            # here would otherwise break sudo for every user on the machine.
            'if ! /usr/sbin/visudo -cf "$tmp" >/dev/null 2>&1; then /bin/rm -f "$tmp";'
            f" echo {INVALID_SUDOERS} >&2; exit 4; fi",
            f'/bin/mv "$tmp" {SUDOERS_PATH}',
        ]
    )


def _osascript_admin(shell_script: str) -> list[str]:
    """Wrap a shell script in the macOS authentication dialog.

    One function rather than two call sites building the same string, so that
    "every privileged script is escaped and admin-wrapped" is enforced in a single
    place a third caller cannot bypass. Note `_applescript_string` escapes `\\` and
    `"` but not newlines -- both callers are newline-free by construction, and this
    is the chokepoint where that stays checkable.
    """
    return [
        OSASCRIPT,
        "-e",
        f'do shell script "{_applescript_string(shell_script)}" with administrator privileges',
    ]


def install_command(body: str) -> list[str]:
    return _osascript_admin(_install_script(body))


def revoke_command() -> list[str]:
    return _osascript_admin(f"/bin/rm -f {SUDOERS_PATH}")


def status_command() -> list[str]:
    """`sudo -n -k -l <command>`: may this account run it *without a password*?

    `-l` asks whether the command is permitted instead of running it, which is the
    only acceptable way to check -- running the real command to find out would
    restart the DNS responder every time the window refreshed. `-n` means a
    missing grant fails immediately rather than blocking on a password prompt
    nobody is there to answer.

    `-k` is the part that makes the answer mean what this module needs it to mean,
    and leaving it out was a real bug. `sudo -l <command>` exits 0 whenever the
    command is permitted *by policy*, and macOS ships `%admin ALL=(ALL) ALL` -- so
    for any admin account `killall` is already permitted, just password-gated.
    Without `-k`, `-n` then only fails while no credential is cached: run any
    `sudo` in a terminal and for the next few minutes this check would report
    "granted" with no grant file installed at all. The window would claim a
    privilege the machine does not have, and `flush_dns_cache` would take its
    granted branch and then report the "the granted sudo rule did not work"
    message -- which sends the reader to the wrong fix entirely.

    `-k` makes sudo ignore the cached credential for this one query, so a
    password-gated command fails and only a NOPASSWD rule exits 0. Used with a
    command rather than on its own, `-k` ignores the timestamp instead of removing
    it, so this does not disturb an unrelated `sudo` session in a terminal.
    """
    return [SUDO, "-n", "-k", "-l", *MDNS_HUP]


def is_granted(run_fn: RunFn = subprocess.run) -> bool:
    try:
        result = run_fn(
            status_command(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return False
    return getattr(result, "returncode", 1) == 0


def _authorisation_outcome(result) -> dict:
    """Turn one osascript run into something the window can print.

    A cancelled password dialog is not a failure and must not be reported as one:
    AppleScript signals it as error -128, and treating it as breakage would tell
    someone who changed their mind that something went wrong.
    """
    stderr = (getattr(result, "stderr", "") or "").strip()
    if getattr(result, "returncode", 1) == 0:
        return {"ok": True, "cancelled": False, "message": ""}
    if _CANCELLED_RE.search(stderr):
        return {"ok": False, "cancelled": True, "message": "Cancelled -- nothing was changed."}
    if MISSING_INCLUDEDIR in stderr:
        return {
            "ok": False,
            "cancelled": False,
            "message": (
                f"{SUDOERS_MAIN} does not include {SUDOERS_DIR}, so a file placed "
                "there would be ignored. Nothing was changed. Adding the include "
                f"line is an edit to {SUDOERS_MAIN} itself, which this app will not "
                "make on its own -- do it with `sudo visudo` if you want to."
            ),
        }
    if INVALID_SUDOERS in stderr:
        return {
            "ok": False,
            "cancelled": False,
            "message": (
                "visudo rejected the generated file, so it was discarded and "
                "nothing was changed. This is a bug -- please report it."
            ),
        }
    return {"ok": False, "cancelled": False, "message": stderr or "osascript failed with no output"}


def _run_privileged(command: list[str], run_fn: RunFn) -> dict:
    try:
        result = run_fn(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            # No timeout: the macOS authentication dialog waits for a human, and a
            # timeout here would kill osascript mid-prompt.
        )
    except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
        return {"ok": False, "cancelled": False, "message": f"could not run osascript: {exc}"}
    return _authorisation_outcome(result)


def grant(
    user: str,
    interfaces: Iterable[str],
    run_fn: RunFn = subprocess.run,
) -> dict:
    """Install the sudoers file. Returns {"ok", "cancelled", "message"}.

    The body is built -- and therefore validated -- before anything is run, so a
    rejected account or interface name never reaches an authentication prompt.
    """
    names = list(interfaces)
    if not names:
        return {
            "ok": False,
            "cancelled": False,
            "message": (
                "No Ethernet or Wi-Fi interface was found, so there is no DHCP "
                "renewal to authorise. Nothing was changed."
            ),
        }
    try:
        body = sudoers_body(user, names)
    except ValueError as exc:
        return {"ok": False, "cancelled": False, "message": str(exc)}

    outcome = _run_privileged(install_command(body), run_fn)
    if outcome["ok"]:
        outcome["message"] = (
            f"Granted. {SUDOERS_PATH} now permits:\n    {describe_commands(names)}\n"
            "Revoke removes it."
        )
    return outcome


def revoke(run_fn: RunFn = subprocess.run) -> dict:
    outcome = _run_privileged(revoke_command(), run_fn)
    if outcome["ok"]:
        outcome["message"] = (
            f"Revoked. {SUDOERS_PATH} is gone; nothing runs as root without a "
            "prompt any more. Flushing DNS will go back to reporting a partial "
            "result, and DHCP renewal to reporting that it needs privilege."
        )
    return outcome


def status_rows(granted: bool, interfaces: Iterable[str], primary: Optional[str]) -> list:
    """(label, value) pairs for the window's Permissions section.

    States what each right actually unlocks rather than only whether it is held: a
    row reading "elevated permissions: no" tells someone nothing about what they
    are missing or whether they should care.
    """
    names = list(interfaces)
    rows = [
        ("Elevated permissions", "granted" if granted else "not granted"),
        ("Sudoers file", SUDOERS_PATH if granted else f"{SUDOERS_PATH} (absent)"),
        (
            "Restart mDNSResponder",
            "yes -- Flush DNS cache fully clears DNS"
            if granted
            else "no -- Flush DNS cache clears the cache but cannot restart the resolver",
        ),
        (
            "Renew DHCP lease",
            f"yes -- on {primary or 'the default-route interface'}"
            if granted
            else "no -- the ladder step reports NEEDS_PRIVILEGE instead of running",
        ),
        (
            "Toggle network service",
            "no -- never granted, by choice: it needs two commands, and a crash "
            "between them leaves this machine offline",
        ),
        (
            "Unmasked DNS names in the log",
            "no -- macOS private-data redaction needs a logging profile, not sudo",
        ),
    ]
    if names:
        rows.append(("Interfaces covered", ", ".join(names)))
    return rows
