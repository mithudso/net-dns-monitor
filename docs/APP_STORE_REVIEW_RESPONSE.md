# App Review reply — Guideline 2.1 Information Needed, build 1.0 (3)

- **Submission ID:** `4283c533-7a50-4d5d-91ff-af3f312417de`
- **Rejected:** 2026-09-28 19:16, Guideline 2.1 — Information Needed (new developer account)
- **Bundle ID:** confirm in App Store Connect before sending. The repo default
  (`com.net-dns-monitor.app`, `scripts/appstore/build_appstore.py:586`) is a dev value.
- **Status of this document:** every claim below was checked against the code on
  2026-10-02 (TASK-367). Re-check any line you change.

## Before you send — do these in order

0. **Build 1.0 (4) from `master` and select it on the version page.** Build 3 posts a
   "Console … UNAVAILABLE_IN_APP_STORE_BUILD" banner about a second after every launch:
   `launch_tick` opened the shell console because `auto_open_console` defaults on. The
   reviewer, and the video, would see it. Fixed on `master` 2026-10-02 (TASK-367). The
   version is in Rejected, not Waiting for Review, so a new build can go with the reply.
1. **Record the video on this Mac (macOS 27.2) from the signed, sandboxed build 4.**
   The GUI has never been launched sandboxed on 27.2, so the recording is also the
   first real test. Use `scripts/appstore/record_demo.py` (section 3).
2. **Watch for two things while recording.** If the prompt does not appear, quit the app
   and re-record. If the banner does not appear, leave that
   step out:
   - The **Local Network** permission prompt appears on the first peer broadcast. Click
     Allow on camera, and keep it in the video.
   - **Test network alert** must show a banner. `rumps.notification` uses the deprecated
     `NSUserNotificationCenter` (`netdnsmonitor/alert.py:31-35`). If no banner appears,
     leave that step out of the video rather than ship a step that fails.
3. **Attach the MP4 to the reply** in the Resolution Center. Do not cite
   `https://llms-explorer.com/net-dns-monitor/app-review-demo.mp4` until it serves a video:
   on 2026-10-02 it returned the site's HTML shell (`content-type: text/html`).
4. Paste section 2 into **App Review Information → Notes** first, then section 1 into
   **Reply to App Review**, then **Resubmit to App Review**. After that, do not upload
   another build while the submission is waiting for review.

## 1. Reply to App Review (2,563 characters — limit 4,000)

```text
Hello,

Thank you for the review. Answers to each item follow; the setup, entitlement and privacy information is also in the App Review Information Notes.

1. SCREEN RECORDING
Attached: app-review-demo.mp4, recorded on a physical Mac running macOS 27.2. It starts at launch and shows: the menu bar status item and Dock latency badge; the Local Network permission prompt; the menu; the dashboard; "Run full diagnosis"; the mini window; the Claude consent dialog (Allow, then Withdraw Claude permission); and the Privacy Policy link.

2. PURPOSE AND AUDIENCE
Net-DNS-Monitor is a menu bar utility that tells a Mac user whether a connectivity problem is their Wi-Fi/Ethernet link, their router, or DNS. A browser only says "no internet". The app checks reachability every few seconds, runs a read-only troubleshooting ladder when something fails, and writes a local incident report the user can hand to IT. Audience: remote workers, developers, and IT/help-desk staff.

3. SETUP
The app has no accounts, no login, no user-generated content, and no paid content or in-app purchases. No credentials or sample files are needed.
1) Launch the app. A status item appears in the menu bar; the Dock tile shows the latest ping time.
2) Allow Local Network access when macOS asks (used to compare status with other Macs on the same LAN; optional).
3) Menu > Open dashboard shows live status. Click "Run full diagnosis".
4) Optional: Menu > Credentials stores the user's own Anthropic API key, Slack webhook, or SMTP password in the macOS Keychain. Every core feature works without them.

4. EXTERNAL SERVICES
- Reachability: ICMP ping to 8.8.8.8; TCP connects to 1.1.1.1:443 and 8.8.8.8:443; a DNS query to 1.1.1.1:53 during diagnosis; a system DNS lookup of api.anthropic.com as a control name (name resolution only, no data sent). These carry no personal data.
- LAN peer status (on by default, can be turned off in Settings): a UDP broadcast on the local subnet, port 45737, containing the Mac's hostname and health. Nothing leaves the LAN.
- Anthropic Claude API (optional): only with the user's own API key AND explicit consent in an in-app dialog that lists the data sent. Consent is versioned and can be withdrawn from the menu.
- Slack webhook / SMTP (optional): alerts to the user's own channel or mailbox.
- No analytics, advertising, tracking, or crash-reporting SDKs.

5. REGIONS
The app works the same in every region. No regional differences.

6. REGULATION
The app is not in a regulated industry and contains no protected third-party material.

Mitchell Hudson
```

## 2. App Review Information → Notes (1,991 characters — limit 4,000)

```text
NO ACCOUNT NEEDED. No login, no demo account, no sample files, no in-app purchases.

WHAT IT DOES: Menu bar utility that tells the user whether a connection problem is the local link, the router, or DNS, and writes a local incident report.

HOW TO REVIEW
1. Launch. A status item appears in the menu bar; the Dock tile shows the latest ping time.
2. macOS asks for Local Network access (LAN peer status). Allow or deny; the app works either way.
3. Menu > Open dashboard: live link, gateway, DNS and latency status.
4. Dashboard > Run full diagnosis. On a healthy network it reports that nothing is broken. Steps that need administrator rights are not in this edition and say so.
5. Menu > Toggle mini window: floating status window.
6. Menu > Allow Claude diagnosis…: consent dialog listing exactly what would be sent to Anthropic. Menu > Withdraw Claude permission revokes it.
7. Menu > Privacy Policy opens https://llms-explorer.com/net-dns-monitor/privacy/

NOT IN THE MAC APP STORE EDITION: switching the network service order, privileged repairs (DNS cache restart, DHCP renew), reading the system log, the router feature, the shell console, and the login-item agent. These need privileges the App Sandbox does not grant; the edition omits their controls.

ENTITLEMENTS (no temporary exceptions)
- com.apple.security.network.client: outbound reachability probes, DNS lookups, and optional user-configured HTTPS (Anthropic, Slack) and SMTP.
- com.apple.security.network.server: binds one UDP socket on port 45737 to receive LAN peer-status broadcasts. Can be turned off in Settings.

AI DISCLOSURE (5.1.2(i)): Nothing is sent to Anthropic unless the user has added their own API key and accepted the consent dialog, which names Anthropic and lists the data. Consent is versioned and revocable.

PRIVACY: No analytics, advertising, tracking or crash-reporting SDKs. Incident reports stay on the Mac.

The app bundles a Python runtime inside the signed app. It downloads and runs no code.
```

## 3. Making the recording

`scripts/appstore/record_demo.py` wraps `screencapture -v` and an `ffmpeg` H.264 encode.
It captures the full screen, and the terminal needs Screen Recording permission
(System Settings → Privacy & Security → Screen Recording).

Quit the app first, so the video starts at launch.

```bash
cd /Users/mitch/dev/net-dns-monitor
python3 scripts/appstore/record_demo.py start
# … perform the steps below …
python3 scripts/appstore/record_demo.py stop   # writes build/appstore/demo/app-review-demo.mp4
```

Recording order (60–120 s):

1. Open the store build from `/Applications` (Finder double-click).
2. Point at the menu bar status item and the Dock latency badge.
3. Allow the **Local Network** prompt when it appears.
4. Open the menu. Pause on it so every item is readable.
5. **Open dashboard** → **Run full diagnosis**. Let the output finish.
6. **Toggle mini window**, then close it.
7. **Test network alert** — keep only if a banner appears (see "Before you send").
8. **Allow Claude diagnosis…** → read the dialog → Allow. Then **Withdraw Claude permission**.
9. **Privacy Policy** → the browser opens the policy page.

Keep the file small (well under 100 MB). Apple publishes no Resolution Center attachment
limit, and App Preview limits (15–30 s) do not apply to a review recording.

## 4. Known second-rejection risks (open on `master`)

Fixed on `master` on 2026-10-02 and shipped in build 4: the launch console banner, the
`osascript` notification fallback in the sandbox (now skipped), a Keychain read that could
raise during app construction, and the failover rows that pointed store users at
`config.yaml`. The risks below remain. The reply above describes the build as it is, so
it can go without them.

| Risk | Where | Option |
|---|---|---|
| Peer discovery is on by default, so the Local Network prompt appears at launch; `network.server` exists only for it. | `netdnsmonitor/config.py:115`, `packaging/appstore/entitlements.plist` | Default it off in the store build, or drop it and the entitlement. |
| Alert banners rely on deprecated `NSUserNotificationCenter`; the store build has no fallback if it fails. | `netdnsmonitor/alert.py` | Move to `UNUserNotificationCenter`. |
| Gated modules (shell console, router, failover) still ship in the store bundle. | `netdnsmonitor/distribution.py` | Exclude them from the store bundle at build time. |
| The `api.anthropic.com` control lookup runs before AI consent. | `netdnsmonitor/config.py:180` | Use a neutral control domain in the store build. |

Research behind this: rabbithole report (session scratchpad, 2026-10-02) citing
https://developer.apple.com/app-store/review/guidelines/ and
https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy
