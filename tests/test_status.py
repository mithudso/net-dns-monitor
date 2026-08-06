from netdnsmonitor.status import build_failover_lines, build_title


def test_healthy_state_shows_healthy_regardless_of_past_classification():
    assert "healthy" in build_title("healthy", None).lower()
    assert "healthy" in build_title("healthy", "dns").lower()


def test_healthy_state_never_mentions_issue():
    assert "issue" not in build_title("healthy", "dns").lower()


def test_incident_state_includes_last_classification():
    title = build_title("incident", "dns")
    assert "dns" in title.lower()
    assert "issue" in title.lower()


def test_incident_state_with_no_classification_yet_says_unknown():
    title = build_title("incident", None)
    assert "unknown" in title.lower()


# --- failover indicator rows ------------------------------------------------


PREFERRED_ROW = {"name": "AX88179B", "device": "en6", "found": True, "reachable": True}
BACKUP_ROW = {"name": "Wi-Fi", "device": "en0", "found": True, "reachable": True}


def snapshot(**overrides):
    """`active_service` is what the system reports; `active_side` is derived
    from it. A fixture where the two disagree describes a state that cannot
    happen, so the helper keeps them consistent unless told otherwise.
    """
    snap = {
        "error": None,
        "active_side": "preferred",
        "active_service": "AX88179B",
        "preferred": dict(PREFERRED_ROW),
        "backup": dict(BACKUP_ROW),
        "backups": [dict(BACKUP_ROW)],
        "auto_enabled": True,
        "last_event": None,
    }
    snap.update(overrides)
    if "active_service" not in overrides:
        snap["active_service"] = (
            snap["backup"]["name"] if snap["active_side"] == "backup"
            else snap["preferred"]["name"]
        )
    return snap


def test_unconfigured_failover_says_so_rather_than_showing_nothing():
    lines = build_failover_lines(None)
    assert len(lines) == 1
    assert "not configured" in lines[0]


def test_unreadable_order_is_reported_not_invented():
    lines = build_failover_lines({"error": "could not read the network service order"})
    assert len(lines) == 1
    assert "could not read" in lines[0]


def test_three_rows_in_a_fixed_order():
    """The answer to "which one am I on" has to be in the same place each time."""
    lines = build_failover_lines(snapshot())
    assert len(lines) == 3
    assert lines[0].startswith("Active:")
    assert "Preferred:" in lines[1]
    assert "Backup:" in lines[2]


def test_the_live_side_is_marked_and_the_other_is_not():
    on_preferred = build_failover_lines(snapshot(active_side="preferred"))
    assert on_preferred[1].startswith("●") and on_preferred[2].startswith("○")
    on_backup = build_failover_lines(snapshot(active_side="backup"))
    assert on_backup[1].startswith("○") and on_backup[2].startswith("●")


def test_rows_name_the_device():
    lines = build_failover_lines(snapshot())
    assert "(en6)" in lines[1] and "(en0)" in lines[2]


def test_reachability_is_tri_state_not_a_boolean():
    """An unplugged adapter must not read as 'unreachable' -- that sends
    someone looking for the wrong fault.
    """
    snap = snapshot(
        preferred={"name": "AX88179B", "device": None, "found": True, "reachable": None},
        backup={"name": "Wi-Fi", "device": "en0", "found": True, "reachable": False},
    )
    lines = build_failover_lines(snap)
    assert "not probed" in lines[1]
    assert "unreachable" in lines[2]


def test_a_missing_service_is_called_out():
    snap = snapshot(
        preferred={"name": "Ethernet", "device": None, "found": False, "reachable": None}
    )
    assert "NOT FOUND" in build_failover_lines(snap)[1]


def test_manual_only_mode_is_visible_in_the_first_row():
    assert "manual only" in build_failover_lines(snapshot(auto_enabled=False))[0]
    assert "automatic" in build_failover_lines(snapshot(auto_enabled=True))[0]
