"""The elevated-permission grant.

Every subprocess is injected. Nothing here runs `osascript`, raises an
authentication dialog, reads `/etc/sudoers`, or writes to `/etc/sudoers.d` -- a
test suite that did any of those would be prompting for a password on every run
and modifying the machine it is testing on.

Checked by hand against the real thing, once: `visudo -cf` accepts the generated
file, `sudo -n -k -l` lists rules without executing anything, and the AppleScript
layer was run with the privileges clause stripped to prove the string literal
parses and the includedir guard fires before any write. What these tests hold in
place is everything around that: which commands are granted, what is refused, how
the grant is detected, and how each failure is explained.
"""

from types import SimpleNamespace

import pytest

from netdnsmonitor.privileges import (
    ALL_INTERFACES_SENTINEL,
    INVALID_SUDOERS,
    MDNS_HUP,
    MISSING_INCLUDEDIR,
    SUDOERS_DIR,
    SUDOERS_PATH,
    _install_script,
    describe_commands,
    dhcp_interfaces,
    explanation,
    grant,
    granted_commands,
    granted_interfaces,
    granted_interfaces_from,
    install_command,
    is_granted,
    own_rule_listed,
    parse_granted_commands,
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


def test_a_default_route_held_by_a_tunnel_is_not_reported_as_no_default_route():
    """A full-tunnel VPN puts the default route on utun3. `primary_interface` still
    answers None -- a DHCP lease on a tunnel is meaningless -- but None then covers
    two different machines, and the Permissions row used to describe only one of
    them: "nothing currently carries the default route" on a machine whose VPN is
    carrying all of its traffic.
    """
    assert primary_interface(recorder(ok("  interface: utun3\n"))) is None
    rows = dict(status_rows(granted=True, interfaces=["en0"], primary=None))
    renew = rows["Renew DHCP lease"]
    assert "nothing currently carries" not in renew
    assert "no interface currently carries" not in renew
    assert "Ethernet or Wi-Fi" in renew
    assert "VPN" in renew


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
        # sudoers reads ALL in the user column as every account on the machine,
        # and any all-capitals name as a User_Alias -- neither is this one account.
        "ALL",
        "ADMINS",
        # A keyword, not a user: the line parses as a Defaults entry.
        "Defaults",
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


def test_the_status_check_lists_rules_rather_than_asking_about_one_command():
    """`sudo -l` with no command, because the answer has to come from the listing.

    Two earlier versions asked `sudo -l <command>` and read the exit status, and
    both were wrong for reasons documented in sudo's own man pages -- see
    test_the_grant_is_detected_by_its_rule_not_by_policy below.
    """
    assert status_command() == ["/usr/bin/sudo", "-n", "-k", "-l"]


def test_the_status_check_never_prompts_and_ignores_a_cached_credential():
    """-n so a missing grant fails instead of blocking on a password prompt nobody
    is there to answer; -k so a credential cached by a terminal `sudo` minutes ago
    does not decide the answer.
    """
    assert "-n" in status_command()
    assert "-k" in status_command()


SUDO_LIST_WITH_GRANT = """Matching Defaults entries for mitch.hudson on host:
    !visiblepw, always_set_home

User mitch.hudson may run the following commands on host:
    (root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder
    (root) NOPASSWD: /usr/sbin/ipconfig set en0 DHCP
    (root) NOPASSWD: /usr/sbin/ipconfig set en9 DHCP
    (ALL) ALL
"""

# The exact machine state that defeated both earlier versions of this check: an
# unrelated NOPASSWD rule (from MDM, a VPN helper, a dev convenience entry) plus
# the `%admin ALL=(ALL) ALL` macOS ships. sudoers(5): "if the NOPASSWD tag is
# applied to any of a user's entries for the current host, the user will be able
# to run 'sudo -l' without a password." So the listing succeeds, `killall` is
# policy-permitted, and an exit-status check reports a grant that is not there.
SUDO_LIST_WITHOUT_GRANT = """User mitch.hudson may run the following commands on host:
    (root) NOPASSWD: /usr/local/bin/some-vpn-helper
    (ALL) ALL
"""


def test_granted_commands_are_read_out_of_the_listing():
    specs = parse_granted_commands(SUDO_LIST_WITH_GRANT)
    assert "/usr/bin/killall -HUP mDNSResponder" in specs
    assert "/usr/sbin/ipconfig set en0 DHCP" in specs
    # `(ALL) ALL` is not a NOPASSWD entry, so it must not be read as one.
    assert "ALL" not in specs


def test_several_specs_on_one_line_are_split():
    """sudo renders a rule listing more than one command as a comma-separated line."""
    specs = parse_granted_commands(
        "    (root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder, /bin/ls\n"
    )
    assert specs == ["/usr/bin/killall -HUP mDNSResponder", "/bin/ls"]


def test_the_grant_is_detected_by_its_rule_not_by_policy():
    """The HIGH finding this pins, which survived one round of fixing.

    v1 ran `sudo -n -l <command>` and trusted the exit status. sudo(8): "the exit
    value will only be 0 if the command is permitted by the security policy" -- and
    macOS ships `%admin ALL=(ALL) ALL`, so `killall` is permitted for any admin,
    merely password-gated. Anyone with a cached credential got a false "granted".

    v2 added `-k`, which fixed only that subcase. Per sudoers(5), *any* NOPASSWD
    entry lets `sudo -l` run without a password, so on a machine with an unrelated
    NOPASSWD rule the listing still succeeds and the exit status is still 0 with no
    grant file anywhere.

    Both produce the same expensive failure: the window claims a privilege the
    machine does not have, `flush_dns_cache` takes its granted branch, and the
    outcome blames a sudoers rule that was never installed. Reading the rule out of
    the listing cannot drift that way.
    """
    assert " ".join(MDNS_HUP) in parse_granted_commands(SUDO_LIST_WITH_GRANT)
    assert " ".join(MDNS_HUP) not in parse_granted_commands(SUDO_LIST_WITHOUT_GRANT)

    assert is_granted(recorder(ok(SUDO_LIST_WITH_GRANT))) is True
    # Exit 0, an unrelated NOPASSWD rule, no grant -- False is the only right answer.
    assert is_granted(recorder(ok(SUDO_LIST_WITHOUT_GRANT))) is False


def test_a_blanket_nopasswd_rule_counts_as_granted():
    """The opposite error to the one -k fixed, and it shipped alongside it.

    `mitch ALL=(ALL) NOPASSWD: ALL` -- the dev-convenience entry this module names as
    realistic -- renders as `(ALL) NOPASSWD: ALL` and genuinely does permit the command.
    Exact-string matching answered 'not granted' on such a machine, so the window said the
    resolver could not be restarted while `sudo -n killall ...` would have succeeded, and
    the repair refused to attempt something that worked.

    This does not reopen the false positive: macOS's shipped `%admin ALL=(ALL) ALL` carries
    no NOPASSWD prefix, so it never reaches the spec list at all.
    """
    blanket = "User mitch may run the following commands on host:\n    (ALL) NOPASSWD: ALL\n"
    assert is_granted(recorder(ok(blanket))) is True
    # ...and it must still refuse the policy-only case.
    policy_only = "User mitch may run the following commands on host:\n    (ALL) ALL\n"
    assert is_granted(recorder(ok(policy_only))) is False


@pytest.mark.parametrize(
    "listing",
    [
        # Passwordless, but only as another account. `sudo -n killall ...` runs as
        # root, which this rule does not permit.
        "    (_postgres) NOPASSWD: ALL\n",
        "    (_postgres) NOPASSWD: /usr/bin/killall -HUP mDNSResponder\n",
        # Every account except root.
        "    (ALL, !root) NOPASSWD: ALL\n",
        # A group-only runas keeps the invoking user.
        "    (: wheel) NOPASSWD: ALL\n",
    ],
)
def test_a_nopasswd_rule_that_does_not_run_as_root_is_not_a_grant(listing):
    """The runas column decides who the command runs as. Reading only the command
    column said "granted" on a machine where the repair's `sudo -n` would fail, and
    the outcome then blamed a grant rule for not working.
    """
    assert is_granted(recorder(ok(listing))) is False


@pytest.mark.parametrize(
    "listing",
    [
        "    (root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder\n",
        "    (ALL : ALL) NOPASSWD: ALL\n",
        "    (root, _postgres) NOPASSWD: ALL\n",
    ],
)
def test_a_nopasswd_rule_that_runs_as_root_is_still_a_grant(listing):
    """Guard against the runas check being too strict."""
    assert is_granted(recorder(ok(listing))) is True


def test_a_blanket_rule_is_reported_as_covering_every_interface():
    """Otherwise the window says 'granted' and 'covers no interfaces' at the same time."""
    blanket = parse_granted_commands("    (ALL) NOPASSWD: ALL\n")
    covered = granted_interfaces_from(blanket)
    assert covered and covered != []
    rows = dict(status_rows(granted=True, interfaces=covered, primary="en9"))
    assert rows["Renew DHCP lease"].startswith("yes")


def test_a_blanket_rule_with_no_primary_interface_is_unknown_not_yes_on_none():
    """The blanket rule covers every interface, but a renewal still needs one to
    target. Without one the row read "yes -- on None".
    """
    rows = dict(status_rows(granted=True, interfaces=ALL_INTERFACES_SENTINEL, primary=None))
    assert rows["Renew DHCP lease"].startswith("unknown")
    assert "None" not in rows["Renew DHCP lease"]


def test_the_sudoers_file_row_is_not_claimed_when_a_blanket_rule_grants_instead():
    """A blanket `(ALL) NOPASSWD: ALL` grants the restart with no file from this app
    on disk. The row names the file only when sudo lists the file's own rule.
    """
    blanket = parse_granted_commands("    (ALL) NOPASSWD: ALL\n")
    assert own_rule_listed(blanket) is False
    assert own_rule_listed(parse_granted_commands(SUDO_LIST_WITH_GRANT)) is True

    rows = dict(
        status_rows(
            granted=True,
            interfaces=granted_interfaces_from(blanket),
            primary="en0",
            file_rule_listed=False,
        )
    )
    assert rows["Elevated permissions"] == "granted"
    assert rows["Sudoers file"] != SUDOERS_PATH
    assert "absent" in rows["Sudoers file"]

    listed = dict(
        status_rows(granted=True, interfaces=["en0"], primary="en0", file_rule_listed=True)
    )
    assert listed["Sudoers file"] == SUDOERS_PATH


def test_the_sudoers_file_row_follows_granted_when_the_caller_does_not_say():
    """Existing callers pass no `file_rule_listed`; their rows must not change."""
    granted = dict(status_rows(granted=True, interfaces=["en0"], primary="en0"))
    assert granted["Sudoers file"] == SUDOERS_PATH
    absent = dict(status_rows(granted=False, interfaces=[], primary=None))
    assert absent["Sudoers file"] == f"{SUDOERS_PATH} (absent)"


def test_a_listing_that_needs_a_password_means_not_granted():
    """No NOPASSWD entry exists for this host at all, including ours."""
    assert is_granted(recorder(ok("sudo: a password is required", returncode=1))) is False
    assert is_granted(recorder(OSError("no sudo"))) is False


def test_the_covered_interfaces_come_from_the_grant_not_from_the_hardware():
    """The sudoers file enumerates what existed at grant time. Dock a laptop and
    `dhcp_interfaces()` grows a name the grant says nothing about, so reporting the
    live enumeration as "covered" is a claim the file does not support -- and it is
    wrong exactly when the DHCP step is about to fail on the new interface.
    """
    assert granted_interfaces(recorder(ok(SUDO_LIST_WITH_GRANT))) == ["en0", "en9"]
    assert granted_interfaces(recorder(ok(SUDO_LIST_WITHOUT_GRANT))) == []


def test_a_forged_interface_name_in_the_listing_is_ignored():
    """The listing is another program's output being parsed, and the result is shown
    to the user as what root may do.
    """
    assert granted_interfaces_from(["/usr/sbin/ipconfig set ../../etc DHCP"]) == []


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


def test_revoking_does_not_claim_the_whole_machine_is_now_password_gated():
    """Deleting this app's file removes this app's rule and nothing else. On a Mac
    with another NOPASSWD rule -- MDM, a VPN helper, a blanket dev entry -- "nothing
    runs as root without a prompt any more" is false, and a blanket rule keeps the
    DNS flush fully working after the revoke.
    """
    result = revoke(run_fn=recorder(ok()))
    assert "nothing runs as root" not in result["message"]
    assert "Other sudoers rules" in result["message"]


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
    assert rows["Interfaces the grant covers"] == "en0, en9"


def test_a_default_route_the_grant_does_not_cover_is_called_out():
    """Dock a laptop after granting: the default route moves to a new interface the
    sudoers file never mentioned. "yes -- on en5" would be false, and the DHCP step
    is about to fail on exactly that interface.
    """
    rows = dict(status_rows(granted=True, interfaces=["en0"], primary="en5"))
    assert rows["Renew DHCP lease"].startswith("no")
    assert "en5" in rows["Renew DHCP lease"]
    assert "Re-grant" in rows["Renew DHCP lease"]


def test_no_default_route_is_reported_as_unknown_rather_than_yes():
    rows = dict(status_rows(granted=True, interfaces=["en0"], primary=None))
    assert rows["Renew DHCP lease"].startswith("unknown")
