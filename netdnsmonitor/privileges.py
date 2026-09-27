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

The worst realistic outcome of the grant being abused is an interrupted network
connection on this machine, and it is not always brief. `ipconfig set <interface>
DHCP` de-configures the interface's existing IPv4 service first, so on an address
set by hand it replaces that configuration with DHCP; with no DHCP server on the
network, the interface then has no working IPv4 until the next network
configuration change. The app's own renewal checks for a DHCP lease before it
runs the command (repair_executor.py), but any other process using the grant does
not have to. The user can withdraw the grant at any time with the Revoke button,
which deletes the file.

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

# The exact argv the grant permits, and the exact string `is_granted` looks for in the
# `sudo -l` listing.
#
# Do not reintroduce a `sudo -l <command>` exit-status probe here. That was the original
# implementation and it was wrong twice over -- `status_command` documents why, and
# `tests/test_privileges.py::test_the_grant_is_detected_by_its_rule_not_by_policy` fails if
# it comes back. Nothing is executed to answer the question; the listing is parsed.
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

# Names `_USER_RE` accepts that sudoers does not read as one account. `ALL` in the
# user column is every account on the machine. A name of an uppercase letter then
# uppercase letters, digits or underscores is alias syntax, so sudoers reads it as a
# User_Alias. `Defaults` and the `*_Alias` words begin other kinds of line. Used
# with `fullmatch`.
_RESERVED_USER_RE = re.compile(r"[A-Z][A-Z0-9_]*|Defaults|(User|Runas|Host|Cmnd|Cmd)_Alias")

# Stands in for "every interface", when a blanket `NOPASSWD: ALL` rule is what grants
# this rather than the file this app writes.
ALL_INTERFACES_SENTINEL = ("(all, via a blanket NOPASSWD rule)",)

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
another program. The worst they can do is interrupt this machine's own network,
and not always briefly: on an interface whose address was set by hand, the DHCP
command replaces that address, and with no DHCP server on the network the
interface has no working IPv4 address until the network configuration next
changes. There are no wildcards in the file and no shell.

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
    """The Ethernet or Wi-Fi interface that carries the default route, if one does.

    Read-only and unprivileged. Used to decide which interface a DHCP renewal
    should target; the grant covers all of them, so the answer only has to be
    right, not authorised.

    None covers three different situations: no default route, a default route on
    an interface other than Ethernet or Wi-Fi (a full-tunnel VPN puts it on utun),
    or a failed lookup. A caller describing None must not pick one of them -- "no
    default route" is false on a machine whose VPN is carrying all of its traffic.
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
    if _RESERVED_USER_RE.fullmatch(user):
        raise ValueError(
            f"refusing to write a sudoers rule for the account name {user!r}: "
            "sudoers reads it as a reserved word or an alias, not as one account"
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
            # `set -e` does not notice a failing non-final member of the decode
            # pipeline above, and `visudo -cf` accepts an empty file. A truncated
            # decode would therefore validate, be moved into place, and be announced
            # as "Granted" for a file that permits nothing. The byte count is the
            # one thing about the decoded file this script can know in advance.
            f'if [ "$(/usr/bin/wc -c < "$tmp")" -ne {len(body.encode("utf-8"))} ];'
            f' then /bin/rm -f "$tmp"; echo {INVALID_SUDOERS} >&2; exit 4; fi',
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
    """`sudo -n -k -l`: list what this account may do, without prompting.

    The rules are then read out of stdout by `parse_granted_commands`. Exit status
    cannot answer this question, and two earlier versions of this function got it
    wrong by trying:

    * `sudo -n -l <command>` exits 0 whenever the command is permitted *by
      policy* (sudo(8): "the exit value will only be 0 if the command is permitted
      by the security policy"), and macOS ships `%admin ALL=(ALL) ALL`. So for any
      admin account `killall` is already permitted, merely password-gated, and the
      check passed for anyone holding a cached credential from a recent terminal
      `sudo`.
    * Adding `-k` closed only that subcase. sudoers(5): "if the NOPASSWD tag is
      applied to **any** of a user's entries for the current host, the user will be
      able to run 'sudo -l' without a password." So on a machine with any unrelated
      NOPASSWD rule -- one from MDM, a VPN or container helper, a dev convenience
      entry -- the listing needs no password, `killall` is still policy-permitted,
      and the exit status is 0 with no grant file anywhere on disk.

    Both failures are the same shape and it is the expensive one: the window
    reports a privilege the machine does not have, `flush_dns_cache` takes its
    granted branch, and the outcome then blames a sudoers rule that was never
    installed. Reading the rule out of the listing cannot drift that way: the
    policy-only `%admin ALL=(ALL) ALL` carries no NOPASSWD tag, so
    `parse_granted_commands` never collects it, while a blanket `NOPASSWD: ALL`
    is accepted on purpose because it genuinely does permit the command.

    `-n` so a missing grant fails instead of blocking on a password prompt nobody
    is there to answer. `-k` so a cached credential does not decide the answer.
    Used alongside `-l` rather than on its own, `-k` ignores the timestamp rather
    than removing it, so an unrelated terminal `sudo` session is left alone.
    """
    return [SUDO, "-n", "-k", "-l"]


# The runas column that opens a `sudo -l` entry: `(root)`, `(ALL : ALL)`,
# `(root, _postgres)`. The group after the colon does not change the user.
_RUNAS_RE = re.compile(r"^\s*\(([^)]*)\)")


def _runs_as_root(head: str) -> bool:
    """Does the runas column in front of a NOPASSWD tag include root?

    Negation (`ALL, !root`) is refused rather than evaluated. Misreading it would
    claim a root privilege the machine does not have; refusing costs only a repair
    step. A later spec on the same line that carries its own runas column keeps
    that column in its text, so it never equals `ALL` or an exact command.
    """
    match = _RUNAS_RE.match(head)
    if not match:
        return False
    users = [name.strip() for name in match.group(1).partition(":")[0].split(",")]
    if any(name.startswith("!") for name in users):
        return False
    return "root" in users or "ALL" in users


def parse_granted_commands(stdout: str) -> list[str]:
    """The NOPASSWD command specs in `sudo -l` output, as whitespace-joined argv.

    `sudo -l` lists entries like:

        (root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder
        (ALL) ALL

    Only NOPASSWD lines are of interest: a password-gated entry is exactly what
    this module does not count as granted. Commas separate several specs on one
    line, which is how sudo renders a rule listing more than one command.

    Only entries that run as root count. `(_postgres) NOPASSWD: ALL` is
    passwordless but permits nothing as root, and the repair's `sudo -n` runs as
    root -- reading it as granted sent the flush down its granted branch, whose
    failure message then blamed a grant rule for not working.
    """
    specs: list[str] = []
    for line in (stdout or "").splitlines():
        head, marker, rest = line.partition("NOPASSWD:")
        if not marker or not _runs_as_root(head):
            continue
        for spec in rest.split(","):
            collapsed = " ".join(spec.split())
            if collapsed:
                specs.append(collapsed)
    return specs


def granted_commands_now(run_fn: RunFn = subprocess.run) -> list[str]:
    """Ask sudo what is currently granted. Empty on any failure.

    Empty is the safe answer: it reads as "not granted", which costs a working
    repair step and never claims a privilege that is absent.
    """
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
        return []
    if getattr(result, "returncode", 1) != 0:
        # A listing that needs a password means no NOPASSWD entry exists for this
        # host at all -- including ours -- so there is nothing to find.
        return []
    return parse_granted_commands(getattr(result, "stdout", "") or "")


def covers(specs: Iterable[str], command: Iterable[str]) -> bool:
    """Does this set of NOPASSWD specs permit `command`?

    A bare `ALL` spec has to count. `mitch ALL=(ALL) NOPASSWD: ALL` -- the "dev convenience
    entry" this module names elsewhere as realistic -- renders in `sudo -l` as
    `(ALL) NOPASSWD: ALL`, and it genuinely does permit the command. Exact-string matching
    alone answered "not granted" on such a machine while `sudo -n killall ...` would have
    succeeded, so the window under-reported what the app could do and the repair step
    refused to try something that would have worked.

    This does not reopen the false positive that `status_command` guards against: macOS's
    shipped `%admin ALL=(ALL) ALL` carries no `NOPASSWD:` prefix, so it never reaches this
    function -- `parse_granted_commands` only collects specs from NOPASSWD lines.

    A spec naming the bare command with no arguments also counts: sudoers(5) says a Cmnd
    without arguments matches that command run with any arguments.
    """
    argv = list(command)
    joined = " ".join(argv)
    return any(spec == "ALL" or spec == joined or spec == argv[0] for spec in specs)


def is_granted(run_fn: RunFn = subprocess.run) -> bool:
    """Is the mDNSResponder restart actually granted, by rule and not by policy?"""
    return is_granted_from(granted_commands_now(run_fn))


def is_granted_from(specs: Iterable[str]) -> bool:
    """Same question as `is_granted`, from an already-fetched listing.

    The app parses one `sudo -l` listing and asks two questions of it. It must ask
    this one here rather than compare the joined argv against the spec list itself:
    exact matching is what `covers` replaced, and bypassing it reports a blanket
    NOPASSWD rule as "not granted" in the window while the repairs run under it.
    """
    return covers(specs, MDNS_HUP)


def own_rule_listed(specs: Iterable[str]) -> bool:
    """Is this app's own mDNSResponder rule in the listing, exactly as written?

    Not the same question as `covers`. A blanket `NOPASSWD: ALL` grants the restart
    with no file from this app on disk, so "granted" cannot say whether
    `SUDOERS_PATH` is there. The exact line can: only the grant writes it.
    """
    return " ".join(MDNS_HUP) in specs


def granted_interfaces_from(specs: Iterable[str]) -> list[str]:
    """The interfaces the *installed grant* covers, read out of an already-fetched
    `sudo -l` listing.

    Split from `granted_interfaces` so one listing can answer both questions --
    whether the DNS restart is granted and which interfaces are covered -- instead
    of paying for a second subprocess on a path that runs at every window open.

    This is not the same set as the interfaces the machine currently has. The
    sudoers file enumerates what existed at grant time; dock a laptop, or plug in a
    USB Ethernet adapter, and `dhcp_interfaces()` grows a name the grant says
    nothing about. Reporting the live enumeration as "covered" is a claim the file
    does not support, and it is wrong in exactly the case where the DHCP step is
    about to fail on the new interface carrying the default route.
    """
    prefix = f"{IPCONFIG} set "
    suffix = " DHCP"
    specs = list(specs)
    if "ALL" in specs:
        # A blanket NOPASSWD covers every interface, but this function's contract is to
        # name the ones the *file* enumerates. Returning [] here would make the window say
        # "granted" and "covers no interfaces" simultaneously, so say what is true instead.
        return list(ALL_INTERFACES_SENTINEL)
    names = []
    for spec in specs:
        if spec.startswith(prefix) and spec.endswith(suffix):
            name = spec[len(prefix) : -len(suffix)].strip()
            if _INTERFACE_RE.match(name):
                names.append(name)
    return names


def granted_interfaces(run_fn: RunFn = subprocess.run) -> list[str]:
    return granted_interfaces_from(granted_commands_now(run_fn))


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
            f"Revoked. {SUDOERS_PATH} is gone, so this app's grant no longer lets "
            "anything run as root without a prompt. Other sudoers rules on this Mac "
            "are unaffected: unless one of them permits the same commands, Flush DNS "
            "goes back to reporting a partial result and DHCP renewal to reporting "
            "that it needs privilege."
        )
    return outcome


def status_rows(
    granted: bool,
    interfaces: Iterable[str],
    primary: Optional[str],
    file_rule_listed: Optional[bool] = None,
) -> list:
    """(label, value) pairs for the window's Permissions section.

    States what each right actually unlocks rather than only whether it is held: a
    row reading "elevated permissions: no" tells someone nothing about what they
    are missing or whether they should care.

    `interfaces` must be what the *grant* covers (`granted_interfaces`), not what
    the machine currently has (`dhcp_interfaces`). Those diverge the moment a dock
    or adapter appears, and the divergence matters: it is exactly when the DHCP step
    is about to fail on the new interface while this section says it is covered.

    `file_rule_listed` is `own_rule_listed` of the same listing. It decides the
    "Sudoers file" row, because `granted` alone cannot: a blanket `NOPASSWD: ALL`
    grants the restart with no file from this app on disk. None keeps the older
    behaviour of following `granted`.
    """
    names = list(interfaces)
    # The step targets whichever interface carries the default route, so a covered
    # set that does not include it is not a working DHCP renewal. A blanket rule
    # covers every interface, but a renewal still needs one to target; checking
    # `blanket` alone made this row read "yes -- on None".
    blanket = list(names) == list(ALL_INTERFACES_SENTINEL)
    primary_covered = bool(primary) and (blanket or primary in names)
    if not granted:
        renew = "no -- the ladder step reports NEEDS_PRIVILEGE instead of running"
    elif primary_covered:
        renew = f"yes -- on {primary}"
    elif primary:
        renew = (
            f"no -- the default route is on {primary}, which the grant does not cover. "
            "Re-grant to include it."
        )
    else:
        renew = (
            "unknown -- no Ethernet or Wi-Fi interface was found on the default route "
            "(there may be none, a VPN or tunnel may hold it, or the lookup failed)"
        )

    listed = granted if file_rule_listed is None else file_rule_listed
    if listed:
        sudoers_file = SUDOERS_PATH
    elif granted:
        sudoers_file = f"{SUDOERS_PATH} (absent -- another NOPASSWD rule grants this)"
    else:
        sudoers_file = f"{SUDOERS_PATH} (absent)"

    rows = [
        ("Elevated permissions", "granted" if granted else "not granted"),
        ("Sudoers file", sudoers_file),
        (
            "Restart mDNSResponder",
            "yes -- Flush DNS cache fully clears DNS"
            if granted
            else "no -- Flush DNS cache clears the cache but cannot restart the resolver",
        ),
        ("Renew DHCP lease", renew),
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
        rows.append(("Interfaces the grant covers", ", ".join(names)))
    return rows
