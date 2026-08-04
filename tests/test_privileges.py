"""The elevated-permission grant.

Every subprocess is injected. Nothing here runs `osascript`, raises an
authentication dialog, reads `/etc/sudoers`, or writes to `/etc/sudoers.d` -- a
test suite that did any of those would be prompting for a password on every run
and modifying the machine it is testing on.

The generated file was checked against the real `visudo -cf` once, by hand, and
`sudo -n -l` was confirmed to report the grant without executing the command. What
these tests hold in place is everything around that: which commands are granted,
what is refused, and how each failure is explained.
"""

from types import SimpleNamespace

import pytest

from netdnsmonitor.privileges import (
    INVALID_SUDOERS,
    MISSING_INCLUDEDIR,
    SUDOERS_DIR,
    SUDOERS_PATH,
    _install_script,
    describe_commands,
    dhcp_interfaces,
    explanation,
    grant,
    granted_commands,
    install_command,
    is_granted,
    primary_interface,
    revoke,
    status_command,
    status_rows,
    sudoers_body,
)

IFCONFIG_L = "lo0 gif0 stf0 anpi0 en0 en9 bridge0 awdl0 llw0 utun0 utun1 en1\n"

ROUTE_DEFAULT = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en9
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""


def ok(stdout="", stderr="", returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def recorder(result):
    """A run_fn that records how it was called and returns a fixed result."""
    calls = []

    def run_fn(command, **kwargs):
        calls.append({"command": command, "kwargs": kwargs})
        if isinstance(result, Exception):
            raise result
        return result

    run_fn.calls = calls
    return run_fn


# --- discovering what to authorise -----------------------------------------


def test_only_ethernet_and_wifi_interfaces_are_considered():
    """`ifconfig -l` also lists loopback, tunnels, bridges and awdl. A DHCP lease
    on any of those is meaningless, and every extra name is another line in a file
    that grants root.
    """
    assert dhcp_interfaces(recorder(ok(IFCONFIG_L))) == ["en0", "en9", "en1"]


def test_a_failed_interface_listing_yields_nothing_rather_than_raising():
    assert dhcp_interfaces(recorder(ok(IFCONFIG_L, returncode=1))) == []
    assert dhcp_interfaces(recorder(OSError("no ifconfig"))) == []


def test_the_primary_interface_comes_from_the_default_route():
    assert primary_interface(recorder(ok(ROUTE_DEFAULT))) == "en9"


def test_no_default_route_means_no_primary_interface():
    assert primary_interface(recorder(ok("route: writing to routing socket"))) is None
    assert primary_interface(recorder(OSError("no route"))) is None


def test_an_implausible_interface_name_from_route_is_refused():
    """Belt and braces: this value is only used to pick a target, but it comes from
    parsing another program's output, and the same regex guards the sudoers file.
    """
    assert primary_interface(recorder(ok("  interface: ../../etc/passwd\n"))) is None


# --- what the grant covers -------------------------------------------------


def test_the_grant_covers_the_dns_restart_and_a_dhcp_renewal_per_interface():
    commands = granted_commands(["en0", "en9"])
    assert ["/usr/bin/killall", "-HUP", "mDNSResponder"] in commands
    assert ["/usr/sbin/ipconfig", "set", "en0", "DHCP"] in commands
    assert ["/usr/sbin/ipconfig", "set", "en9", "DHCP"] in commands
    assert len(commands) == 3


def test_the_sudoers_file_names_complete_commands_with_no_wildcard_or_shell():
    """A rule ending in a wildcard, or naming any shell, is equivalent to granting
    unrestricted root. This is the assertion that keeps the grant narrow, so it is
    written as a property of the file rather than a review comment.
    """
    body = sudoers_body("mitch.hudson", ["en0", "en9"])
    assert "*" not in body
    assert "ALL=(root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder" in body
    for shell in ("/bin/sh", "/bin/bash", "/bin/zsh", "sudoedit", "NOPASSWD: ALL"):
        assert shell not in body


def test_the_file_says_how_to_withdraw_the_grant():
    """Someone finding this file in a year has to be able to tell what put it there
    and how to undo it.
    """
    body = sudoers_body("mitch.hudson", ["en0"])
    assert "Net-DNS-Monitor" in body
    assert "Delete this file" in body


@pytest.mark.parametrize(
    "user",
    [
        "",
        "root ALL=(ALL) NOPASSWD: ALL #",
        "mitch hudson",
        "mitch\nroot ALL=(ALL) NOPASSWD: ALL",
        "mitch;id",
        # A bare trailing newline, which `^...$` accepts and `^...\Z` does not.
        # It produced a rule split across two physical lines. visudo would have
        # rejected the file, but this boundary's whole claim is that it refuses
        # such input rather than relying on a downstream check.
        "mitch.hudson\n",
    ],
)
def test_an_account_name_that_could_forge_a_rule_is_refused_not_escaped(user):
    """This string is written into a file that grants root. The boundary validates
    rather than escapes -- there is no legitimate account name being excluded, and
    escaping is the approach that eventually gets one character wrong.
    """
    with pytest.raises(ValueError, match="refusing to write"):
        sudoers_body(user, ["en0"])


@pytest.mark.parametrize(
    "interface",
    ["", "en0 DHCP\nroot ALL=(ALL) NOPASSWD: ALL", "*", "../en0", "en0\n"],
)
def test_an_interface_name_that_could_forge_a_rule_is_refused(interface):
    with pytest.raises(ValueError, match="refusing to write"):
        sudoers_body("mitch.hudson", [interface])


# --- the privileged script -------------------------------------------------


def test_the_grant_runs_through_the_macos_authentication_dialog():
    command = install_command(sudoers_body("mitch.hudson", ["en0"]))
    assert command[0] == "/usr/bin/osascript"
    assert "with administrator privileges" in command[2]


def test_the_file_contents_reach_root_base64_encoded_not_as_raw_text():
    """Two layers of interpretation stand between here and the file (AppleScript,
    then sh). Base64 is alphanumeric plus +/=, so a comment or an account name
    cannot terminate a quote or append a second command on the way through.
    """
    body = sudoers_body("mitch.hudson", ["en0"])
    script = _install_script(body)
    assert "base64 -D" in script
    assert "NOPASSWD" not in script


def test_the_script_refuses_to_act_if_sudoers_d_is_not_included():
    """A file in sudoers.d that nothing includes is a grant that silently does not
    work: the button would report success and every repair would keep failing.
    """
    script = _install_script(sudoers_body("mitch.hudson", ["en0"]))
    assert "includedir" in script
    assert MISSING_INCLUDEDIR in script


def test_the_script_validates_with_visudo_before_installing_anything():
    """An invalid file in sudoers.d breaks `sudo` for the whole machine, which is a
    far worse outcome than the missing privilege this is trying to fix.
    """
    script = _install_script(sudoers_body("mitch.hudson", ["en0"]))
    assert "visudo -cf" in script
    assert INVALID_SUDOERS in script
    # Validated before it is moved anywhere sudo reads.
    assert script.index("visudo -cf") < script.index(f'/bin/mv "$tmp" {SUDOERS_PATH}')


def test_the_script_never_edits_the_main_sudoers_file():
    script = _install_script(sudoers_body("mitch.hudson", ["en0"]))
    assert "> /etc/sudoers" not in script
    assert "/bin/mv $tmp /etc/sudoers\n" not in script
    assert script.count(SUDOERS_PATH) == 1


# --- checking the grant ----------------------------------------------------


def test_the_status_check_asks_whether_the_command_is_allowed_rather_than_running_it():
    """`sudo -l <command>` reports permission without executing. Checking by
    running the real command would restart the DNS responder every time the window
    refreshed.
    """
    command = status_command()
    assert command[:4] == ["/usr/bin/sudo", "-n", "-k", "-l"]
    assert command[4:] == ["/usr/bin/killall", "-HUP", "mDNSResponder"]


def test_the_status_check_never_prompts():
    """-n, so a missing grant fails immediately instead of blocking on a password
    prompt with nobody there to answer it -- on the main thread, at that.
    """
    assert "-n" in status_command()


def test_the_status_check_ignores_a_cached_sudo_credential():
    """The bug this pins, which shipped in the first version of this module.

    `sudo -l <command>` exits 0 whenever the command is permitted *by policy*, and
    macOS ships `%admin ALL=(ALL) ALL` -- so for an admin account `killall` is
    already permitted, merely password-gated. With only `-n`, the check therefore
    passed for anyone who had run `sudo` in a terminal in the last few minutes,
    reporting "granted" with no grant file installed at all: the window claimed a
    privilege the machine did not have, and `flush_dns_cache` took its granted
    branch and then blamed the (nonexistent) rule for not working.

    `-k` makes sudo ignore the cached credential for this one query, so only a real
    NOPASSWD rule exits 0. Verified on a real admin account: without a grant,
    `sudo -n -k -l /usr/bin/killall -HUP mDNSResponder` exits 1.

    Asserted as a property of the argv because the semantics live in sudo, and
    every consumer test here injects a fixed returncode -- so nothing else in the
    suite can catch the flag going missing again.
    """
    assert "-k" in status_command()


def test_a_zero_exit_from_sudo_means_granted():
    assert is_granted(recorder(ok())) is True
    assert is_granted(recorder(ok(returncode=1))) is False
    assert is_granted(recorder(OSError("no sudo"))) is False


# --- outcomes --------------------------------------------------------------


def test_a_successful_grant_reports_what_is_now_permitted():
    run_fn = recorder(ok())
    result = grant("mitch.hudson", ["en0"], run_fn=run_fn)
    assert result["ok"] is True
    assert result["cancelled"] is False
    assert "ipconfig set en0 DHCP" in result["message"]


def test_cancelling_the_password_dialog_is_not_reported_as_a_failure():
    """AppleScript signals a cancelled dialog as error -128. Reporting that as
    breakage tells someone who changed their mind that something went wrong.
    """
    run_fn = recorder(ok(stderr="User canceled. (-128)", returncode=1))
    result = grant("mitch.hudson", ["en0"], run_fn=run_fn)
    assert result["ok"] is False
    assert result["cancelled"] is True
    assert "nothing was changed" in result["message"].lower()


def test_an_unrecognised_failure_is_not_reported_as_a_cancellation():
    """The cancel check was a bare `"-128" in stderr` substring test, so any error
    whose text contained that sequence -- `(-12800)`, say -- was announced as
    "Cancelled -- nothing was changed."

    That is the one message that must never appear for a real failure: it tells
    someone their machine is untouched at the moment something has actually gone
    wrong, and it hides the stderr that would have said what.
    """
    run_fn = recorder(ok(stderr="execution error: something broke (-12800)", returncode=1))
    result = grant("mitch.hudson", ["en0"], run_fn=run_fn)
    assert result["cancelled"] is False
    assert "something broke" in result["message"]


def test_a_real_cancellation_is_still_recognised():
    """Guard against the fix being too strict: both spellings and the bare
    parenthesised code have to keep working.
    """
    for stderr in (
        "User canceled. (-128)",
        "User cancelled. (-128)",
        "execution error: (-128)",
    ):
        result = grant("mitch.hudson", ["en0"], run_fn=recorder(ok(stderr=stderr, returncode=1)))
        assert result["cancelled"] is True, stderr


def test_the_staging_file_never_leaves_the_root_only_sudoers_directory():
    """Staged inside sudoers.d rather than $TMPDIR.

    `do shell script` inherits the invoking user's environment, so a bare `mktemp`
    could stage the file in a directory that user owns -- leaving a window between
    `visudo -cf` and `mv` in which unprivileged code could swap the validated file
    for an arbitrary one and land it at SUDOERS_PATH unvalidated. sudoers.d is
    root-only, which closes that window and makes the final move a same-directory
    rename. The leading dot matters too: sudo ignores sudoers.d filenames
    containing a `.`, so a staging file left by an interrupted run is inert.
    """
    script = _install_script(sudoers_body("mitch.hudson", ["en0"]))
    assert f"mktemp {SUDOERS_DIR}/.net-dns-monitor.tmp.XXXXXX" in script
    # The directory has to exist before mktemp is asked to create a file in it.
    assert script.index("/bin/mkdir -p") < script.index("mktemp")


def test_a_missing_includedir_is_explained_rather_than_worked_around():
    """Adding the include line is an edit to /etc/sudoers itself, which this app
    will not make on its own.
    """
    run_fn = recorder(ok(stderr=MISSING_INCLUDEDIR, returncode=1))
    result = grant("mitch.hudson", ["en0"], run_fn=run_fn)
    assert result["ok"] is False
    assert "does not include" in result["message"]
    assert "visudo" in result["message"]


def test_a_file_visudo_rejects_is_reported_as_a_bug_and_nothing_is_installed():
    run_fn = recorder(ok(stderr=INVALID_SUDOERS, returncode=1))
    result = grant("mitch.hudson", ["en0"], run_fn=run_fn)
    assert result["ok"] is False
    assert "nothing was changed" in result["message"].lower()


def test_no_interfaces_means_no_prompt_at_all():
    """Nothing to authorise, so nobody should be asked for a password."""
    run_fn = recorder(ok())
    result = grant("mitch.hudson", [], run_fn=run_fn)
    assert result["ok"] is False
    assert run_fn.calls == []


def test_a_rejected_account_name_never_reaches_an_authentication_prompt():
    run_fn = recorder(ok())
    result = grant("root ALL=(ALL) NOPASSWD: ALL #", ["en0"], run_fn=run_fn)
    assert result["ok"] is False
    assert run_fn.calls == []


def test_the_prompt_is_not_given_a_timeout():
    """The authentication dialog waits for a human. A timeout would kill osascript
    mid-prompt, which looks exactly like the grant failing.
    """
    run_fn = recorder(ok())
    grant("mitch.hudson", ["en0"], run_fn=run_fn)
    assert "timeout" not in run_fn.calls[0]["kwargs"]


def test_revoking_deletes_the_file_and_says_what_stops_working():
    run_fn = recorder(ok())
    result = revoke(run_fn=run_fn)
    assert result["ok"] is True
    assert SUDOERS_PATH in " ".join(run_fn.calls[0]["command"])
    assert "/bin/rm" in run_fn.calls[0]["command"][2]
    assert "partial" in result["message"]


# --- what the window shows -------------------------------------------------


def test_the_explanation_lists_the_exact_commands_before_anyone_clicks():
    text = explanation(["en0", "en9"])
    assert "/usr/bin/killall -HUP mDNSResponder" in text
    assert "ipconfig set en9 DHCP" in text
    assert "any process running as you" in text
    assert "no wildcards" in text.lower()


def test_the_explanation_says_what_is_broken_without_the_grant():
    text = explanation(["en0"])
    assert "half works" in text
    assert "Revoke" in text


def test_describe_commands_is_the_same_list_the_file_is_built_from():
    described = describe_commands(["en0"])
    for command in granted_commands(["en0"]):
        assert " ".join(command) in described


def test_the_permissions_section_says_what_each_right_unlocks():
    """ "elevated permissions: no" tells someone nothing about what they are missing
    or whether they should care.
    """
    rows = dict(status_rows(granted=False, interfaces=["en0"], primary="en0"))
    assert rows["Elevated permissions"] == "not granted"
    assert "cannot restart the resolver" in rows["Restart mDNSResponder"]
    assert "NEEDS_PRIVILEGE" in rows["Renew DHCP lease"]


def test_the_permissions_section_says_which_things_sudo_will_never_fix():
    """Two of them, and both are otherwise indistinguishable from "the grant did
    not work": the interface toggle is withheld by choice, and the masked DNS names
    in the log are not a permission at all.
    """
    rows = dict(status_rows(granted=True, interfaces=["en0"], primary="en0"))
    assert "by choice" in rows["Toggle network service"]
    assert "logging profile" in rows["Unmasked DNS names in the log"]


def test_the_granted_section_names_the_interface_a_renewal_would_target():
    rows = dict(status_rows(granted=True, interfaces=["en0", "en9"], primary="en9"))
    assert "en9" in rows["Renew DHCP lease"]
    assert rows["Interfaces covered"] == "en0, en9"
