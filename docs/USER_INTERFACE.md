# User interface

The windows are AppKit shells. What they say and which controls exist is decided in
pure modules the offline suite covers; the windows only draw it.

| Window | Module | Opened from |
|---|---|---|
| Dashboard | `netdnsmonitor/dashboard.py` | status-item menu, Dock click |
| Settings | `netdnsmonitor/settings_window.py` | dashboard **Tools ▾**, menu, ⌘, |
| Remediation editor | `netdnsmonitor/remediation_window.py` | **Tools ▾**, menu, Settings |
| Console | `netdnsmonitor/console_window.py` | **Tools ▾**, menu |
| Router console | `netdnsmonitor/router_window.py` | **Tools ▾**, Router menu |
| Mini window | `netdnsmonitor/mini_window.py` | **Tools ▾**, menu |

## Liquid Glass

`netdnsmonitor/ui_style.py` puts every window on a glass background
(`NSGlassEffectView`, macOS 26 or later) and gives buttons the glass bezel. Both are looked
up at run time. On a system without them the window gets a vibrancy background
(`NSVisualEffectView`) and rounded buttons, and nothing else changes. Text panes are
rounded and lightly translucent so monospaced text stays legible over the material.
`window.glass_kind` is `"glass"`, `"vibrancy"` or `"plain"`, and a test checks each path.

## The dashboard

The two actions you reach for during an outage stay buttons: **Ping now** and **Run full
diagnosis**. Everything else sits in a pull-down menu by category:

| Menu | Holds |
|---|---|
| Checks | the read-only diagnostics, DNS prewarm |
| Repairs | flush DNS cache (changes system state) |
| Tools | remediation editor, console, router console, Settings, mini window |
| Reports | last incident report, forensic folder, test alert |
| Permissions | grant / revoke the sudoers rule |

A menu with nothing available in this build is left out, so the App Store edition shows
no empty menu. The grouping is `ui_catalog.ACTION_GROUPS`; an action no group names appears
under **More**, so a new action is never unreachable.

## Tooltips

Every button, menu, menu item, field and toggle has a tooltip. `ui_style.tip` refuses an
empty one, and `tests/test_ui_windows.py` builds each window and fails on any operable
control without one. The text lives in `netdnsmonitor/ui_catalog.py`:

- `SETTING_TIPS`: one per config key (a test fails if a key has none, or if a restart-only
  key's tip does not say so);
- `ACTION_TIPS`, `LOG_ACTION_TIPS`, `CONTROL_TIPS`: dashboard, log and other fixed controls.

## Settings

Every key in `config.DEFAULT_CONFIG` has a field (`tests/test_ui_catalog.py` checks this).
The options that are not config keys sit in a row at the top of the window: **Start at
login**, **Allow Claude diagnosis**, **Credentials ▾** (API key, Slack webhook, SMTP
password, remove), **Permissions ▾** and **Edit scripts…**. They call the same app methods
as the menu bar. The build decides which exist: the App Store edition has no login item,
no root grant and no script editor.

## Adding a control

1. Add the action to `dashboard.ALL_ACTIONS` (or the key to `config.DEFAULT_CONFIG` and
   `settings_window.GROUPS`).
2. Add its tooltip in `ui_catalog.py`, and place an action in `ACTION_GROUPS`.
3. If a build cannot run it, add it to `app.GATED_DASHBOARD_ACTIONS`.
4. `pytest tests/test_ui_catalog.py tests/test_ui_windows.py`.

## Not covered by tests

How the glass looks, and that every menu item does what its label says when clicked in the
running app. The window tests build views headlessly and never show them; look at the
windows by hand after changing a layout.
