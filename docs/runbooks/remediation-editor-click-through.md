# Runbook: remediation editor click-through

**When:** after any change to `netdnsmonitor/remediation_window.py`,
`remediation_editor.py` or `remediation_scripts.py`. The editor is an AppKit window, so
the offline suite cannot cover it, and `CLAUDE.md` forbids an agent launching the app.
A person runs this.

**Time:** about five minutes. **Changes:** only files in
`~/Library/Application Support/net-dns-monitor/remediations/`; step 7 removes them again.

## Steps

1. Start the app from a terminal:

   ```bash
   cd /Users/mitch/dev/net-dns-monitor && .venv/bin/python -m netdnsmonitor.app
   ```

2. Click the status-item menu, then **Edit remediation scripts** (or the dashboard's
   **Tools ▾** menu, or **Edit scripts…** in Settings). A window titled
   "Remediation scripts" opens with **9 scripts** in the picker.
3. Pick `check_interface_state`. Change `--nwi` to `--proxy`. The window title gains
   "(edited)" and keywords are coloured.
4. Click **Save**. The picker label becomes `check_interface_state  [built-in, modified]`.
5. Click **Run test**. The lower pane shows `outcome:` followed by the `scutil --proxy`
   output, and the run time.
6. Click **Reset…**, confirm. The label returns to `[built-in]` and the text shows `--nwi`.
7. Click **New…**, enter `my_check`. A template appears. Click **Save**. It appears as
   `my_check  [custom]`. Click **Delete…**, confirm. It disappears.

## Also worth a look

- **Check** on text with a typo (delete a `)`): the pane lists a `syntax error` and
  **Save** refuses the same text.
- **Run test** on `flush_dns_cache` asks "Run … for real?" first (it is a repair).
- A custom script with `CLASSIFICATIONS = ("dns",)` and `ORDER = 5` runs first among custom
  steps on the next DNS incident, after the built-in DNS steps.
- In the App Store build (`NETDNS_DISTRIBUTION=appstore`) the menu item and button are
  absent.

## If something is wrong

Scripts are plain files in the folder above; delete one to restore the shipped version.
Report what you saw; the logic is in `remediation_editor.py` and the window shell in
`remediation_window.py`. Background: `docs/REMEDIATION_SCRIPTS.md`.
