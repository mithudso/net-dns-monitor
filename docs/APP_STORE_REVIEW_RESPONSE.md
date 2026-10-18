# App Review reply — Guideline 2.1 Information Needed, build 1.0 (3)

- **Submission ID:** `4283c533-7a50-4d5d-91ff-af3f312417de`
- **Rejected:** 2026-09-28 19:16, Guideline 2.1 — Information Needed (new developer account)
- **Bundle ID:** `com.mitchhudson.netdnsmonitor`, team `L9ELX85ZFD`, from the App Store profile
  `/Users/mitch/Documents/NetDNSMonitor_AppStore.provisionprofile` (expires 2027-09-27). Pass it
  as `--bundle-id` to `scripts/appstore/build_appstore.py`; the script's default is a dev value.
- **Status of this document:** every claim below was checked against the code on
  2026-10-02 (TASK-367). The Notes, the reply's external-services list and section 4 were
  re-checked against a fresh ad-hoc store bundle on 2026-10-17 (TASK-417). Re-check any
  line you change.

## Before you send — do these in order

0. **Build 1.0 (4) from `master` and select it on the version page.** Build 3 posts a
   "Console … UNAVAILABLE_IN_APP_STORE_BUILD" banner about a second after every launch:
   `launch_tick` opened the shell console because `auto_open_console` defaults on. The
   reviewer, and the video, would see it. Fixed on `master` 2026-10-02 (TASK-367). The
   version is in Rejected, not Waiting for Review, so a new build can go with the reply.
1. **Record the video from the signed, sandboxed build 4 on a release macOS, and put
   its exact version in the reply** (Apple menu → About This Mac). This Mac reports
   macOS 27.2 build 26B5091g, which is a beta. Apple asks for "the latest operating
   system", so record on the current public release if you can, and never call a beta a
   release. The GUI has never been launched sandboxed on 27.x, so the recording is also the
   first real test. Use `scripts/appstore/record_demo.py` (section 3).
2. **Watch for two things while recording.** If the prompt does not appear, quit the app
   and re-record. If the banner does not appear, leave that
   step out:
   - Build 4 starts with LAN peer status off (`distribution.default_overrides`). The
     **Local Network** prompt appears only after you turn it on in Settings (recording
     step 9). Click Allow on camera.
   - **Test network alert** must show a banner. `rumps.notification` uses the deprecated
     `NSUserNotificationCenter` (`netdnsmonitor/alert.py:31-35`). If no banner appears,
     leave that step out of the video rather than ship a step that fails.
3. **Attach the MP4 to the reply** in the Resolution Center. Do not cite
   `https://llms-explorer.com/net-dns-monitor/app-review-demo.mp4` until it serves a video:
   on 2026-10-02 it returned the site's HTML shell (`content-type: text/html`).
4. Paste section 2 into **App Review Information → Notes** first, then section 1 into
   **Reply to App Review**, then **Resubmit to App Review**. After that, do not upload
   another build while the submission is waiting for review.

## 1. Reply to App Review (3,102 characters — limit 4,000)

```text
Hello,

Thank you for the review. Answers to each item follow; the setup, entitlement and privacy information is also in the App Review Information Notes.

1. SCREEN RECORDING
Attached: app-review-demo.mp4, recorded on a physical Mac running macOS [EXACT VERSION — fill in from About This Mac]. It starts at launch and shows: the menu bar status item and Dock latency badge; the menu; the dashboard; "Run full diagnosis"; the mini window; the Claude consent dialog (Allow, then Withdraw Claude permission); turning on LAN peer status and the Local Network permission prompt; and the Privacy Policy link.

2. PURPOSE AND AUDIENCE
Net-DNS-Monitor is a menu bar utility that tells a Mac user whether a connectivity problem is their Wi-Fi/Ethernet link, their router, or DNS. A browser only says "no internet". The app checks reachability every few seconds, runs a read-only troubleshooting ladder when something fails, and writes a local incident report the user can hand to IT. Audience: remote workers, developers, and IT/help-desk staff.

3. SETUP
The app has no accounts, no login, no user-generated content, and no paid content or in-app purchases. No credentials or sample files are needed.
1) Launch the app. A status item appears in the menu bar; the Dock tile shows the latest ping time.
2) Menu > Open dashboard shows live status. Click "Run full diagnosis".
3) Optional: Dashboard > Open settings > LAN peer discovery turns on status sharing with other Macs on the same network (takes effect at next launch); macOS then asks for Local Network access.
4) Optional: Menu > Credentials stores the user's own Anthropic API key, Slack webhook, or SMTP password in the macOS Keychain. Every core feature works without them.

4. EXTERNAL SERVICES
- Reachability: ICMP ping to 2001:4860:4860::8888, then 8.8.8.8 and 1.1.1.1, and last the name dns.google over IPv6 (so an IPv6-only network can still answer); TCP connects to 1.1.1.1:443 and 8.8.8.8:443; during diagnosis, a DNS query to 2606:4700:4700::1111 (Cloudflare), then 1.1.1.1:53; a system DNS lookup of api.anthropic.com as a control name (name resolution only, no data sent). These carry no personal data.
- LAN peer status (off by default; the user turns it on in Settings): a UDP broadcast on the local subnet, port 45737, containing the Mac's hostname and health. Nothing leaves the LAN.
- Anthropic Claude API (optional): only with the user's own API key AND explicit consent in an in-app dialog that lists the data sent (the incident classification, probe results with domain names, and the text of each troubleshooting step, which includes interface names, this Mac's IP addresses, router and DNS server addresses, and DNS search domains). Consent is versioned and can be withdrawn from the menu.
- Slack webhook / SMTP (optional): alerts to the user's own channel or mailbox.
- No analytics, advertising, tracking, or crash-reporting SDKs.

5. REGIONS
The app works the same in every region. No regional differences.

6. REGULATION
The app is not in a regulated industry and contains no protected third-party material.

Mitchell Hudson
```

## 2. App Review Information → Notes (2,876 characters — limit 4,000)

```text
NO ACCOUNT NEEDED. No login, no demo account, no sample files, no in-app purchases.

WHAT IT DOES: Menu bar utility that tells the user whether a connection problem is the local link, the router, or DNS, and writes a local incident report.

HOW TO REVIEW
1. Launch. A status item appears in the menu bar; the Dock tile shows the latest ping time.
2. Menu > Open dashboard: live ping time, packet loss, throughput and DNS status.
3. Dashboard > Run full diagnosis. On a healthy network it reports that nothing is broken. Steps that need administrator rights are not in this edition and say so.
4. Menu > Toggle mini window: floating status window.
5. Menu > Test network alert posts a sample banner. Menu > Open last report opens the newest incident report (none exists until an incident occurs). Menu > Refresh network status re-reads the network service order shown in the top rows (read only).
6. Menu > Credentials stores the user's own Anthropic key, Slack webhook or SMTP password in the Keychain. All are optional.
7. Menu > Allow Claude diagnosis...: consent dialog listing exactly what would be sent to Anthropic. Menu > Withdraw Claude permission revokes it.
8. Menu > Privacy Policy opens https://llms-explorer.com/net-dns-monitor/privacy/

NOT IN THE MAC APP STORE EDITION: switching the network service order, privileged repairs (DNS cache restart, DHCP renew), reading the system log, the router, the shell console, and the login-item agent. The shell console, router and command-line code are not in this bundle. The source for privileged repairs and the network-order switch is in the bundle but never runs: the app turns it off when it detects the App Sandbox, and the menus and buttons for it do not exist. A step that would need it reports UNAVAILABLE_IN_APP_STORE_BUILD and says nothing was changed. Nothing is hidden or obfuscated.

ENTITLEMENTS (no temporary exceptions)
- com.apple.security.network.client: outbound reachability probes, DNS lookups, and optional user-configured HTTPS (Anthropic, Slack) and SMTP.
- com.apple.security.network.server: UDP and ICMP need it in the sandbox (the ping heartbeat). It also lets the optional LAN peer socket (UDP port 45737) receive broadcasts, which is off by default and enabled in Settings > LAN peer discovery; macOS then shows the Local Network prompt. In the default configuration the app contacts only public addresses and the system resolver, so no Local Network prompt is expected at first launch.

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
3. Open the menu. Pause on it so every item is readable.
4. **Open dashboard** → **Run full diagnosis**. Let the output finish.
5. **Toggle mini window**, then close it.
6. **Test network alert** — keep only if a banner appears (see "Before you send").
7. **Allow Claude diagnosis…** → read the dialog → Allow. Then **Withdraw Claude permission**.
8. **Privacy Policy** → the browser opens the policy page.
9. Dashboard → **Open settings** → LAN peer discovery → tick **Enabled** → Save. The
   setting takes effect at the next launch (`settings_window.py` lists it as restart-only),
   so quit from the menu and reopen the app. Allow the **Local Network** prompt when it
   appears.

Keep the file small (well under 100 MB). Apple publishes no Resolution Center attachment
limit, and App Preview limits (15–30 s) do not apply to a review recording.

## 4. Known second-rejection risks (open on `master`)

Fixed on `master` on 2026-10-02 and shipped in build 4: the launch console banner, the
`osascript` notification fallback in the sandbox (now skipped), a Keychain read that could
raise during app construction, and the failover rows that pointed store users at
`config.yaml`. Build 4 also starts with LAN peer discovery and the console auto-open off
(owner decision, 2026-10-02). Changed on 2026-10-17 (TASK-417), and in the next build:
the store bundle no longer contains the shell console, router or command-line modules; it
carries a valid `PrivacyInfo.xcprivacy`; the Local Network prompt text names what
triggers it; the Claude consent text names what the step outcomes contain (consent
version 2, so no earlier grant counts); and the heartbeat ends with an IPv6 ping to a
host name for NAT64 networks. The risks below remain. The reply above describes the build
as it is, so it can go without them.

| Risk | Where | Option |
|---|---|---|
| **Not yet run on an IPv6-only NAT64 network (Guideline 2.5.5).** Mitigated: the heartbeat pings `2001:4860:4860::8888`, then 8.8.8.8 and 1.1.1.1, then the name `dns.google` with `ping6`, which uses the NAT64-synthesized address (`/sbin/ping` is IPv4-only and an IPv6 literal may have no route on Apple's test network). The diagnosis DNS query tries `2606:4700:4700::1111` before 1.1.1.1, and the TCP probes use `socket.create_connection` on IPv4 literals, which macOS rewrites for NAT64. Measured only on a dual-stack network. | `netdnsmonitor/app.py` (`ping_heartbeat`), `netdnsmonitor/ping.py`, `netdnsmonitor/dns_query.py` | On a second Mac, hold Option and open System Settings → General → Sharing → Internet Sharing, tick **Create NAT64 Network**, join this Mac to it, and run the build. The heartbeat should stay green and no "network failed" banner should appear. https://developer.apple.com/support/ipv6 |
| Alert banners rely on deprecated `NSUserNotificationCenter`; the store build has no fallback if it fails. Guideline 2.4.5(viii) lists deprecated technologies. | `netdnsmonitor/alert.py` | Move to `UNUserNotificationCenter`. It needs an authorization request and a signed bundle to test, so it was not done blind; the runtime dependency list (`requirements.txt`, four packages) would also grow by `pyobjc-framework-UserNotifications` unless the framework is loaded through `objc.loadBundle`. |
| The privileged-repair and network-order source still ships (`privileges.py` with the sudoers writer and its administrator dialog, `repair_executor.py`, `failover.py`), switched off by `distribution.detect()`. The Notes say so. | `netdnsmonitor/distribution.py` | Split the privilege probes the tick path uses (`privileges.primary_interface`, `granted_commands_now`) out of `privileges.py`, then delete the sudoers writer from the store bundle as `prune_store_bundle` deletes the router. Not done: it touches the tick path and no rejection precedent names it. If a review cites 2.4.5(v) or 2.5.19 for root privileges, this is the module to remove first. |
| The `api.anthropic.com` control lookup runs before AI consent. It is a name lookup through the system resolver; nothing is sent to Anthropic, and the Notes and the privacy policy disclose it. | `netdnsmonitor/config.py` (`control_domain`) | A neutral control domain in the store build would remove the question; `distribution.default_overrides` is where to set it. |
| The hosted privacy policy is older than `docs/PRIVACY_POLICY.md` (checked 2026-10-17): it says peer discovery is on by default and that declining the Local Network prompt stops router checks, and it lacks the IPv6 addresses. The Support page (`index.astro` in the same directory) says macOS asks about the local network at first launch and that allowing it lets the app check whether the router answers; since build 4 the prompt appears only when LAN peer discovery or a local monitor target is configured. The hosted pages are what App Review reads. | `llms-explorer` repository, `site/src/pages/net-dns-monitor/privacy.astro` and `index.astro` | Mirror `docs/PRIVACY_POLICY.md` into the first, correct the Local Network paragraph in the second, and deploy before submitting. |
| The Support and Privacy Policy pages sit inside the llms-explorer site, whose navigation carries a "Support the project / Help fund the work" link. Guideline 3.1.1 and 3.2.1 scrutinize donation links reachable from reviewed pages. | `llms-explorer` repository | Serve the two net-dns-monitor pages without the site navigation, or remove the funding link from that layout. `https://llms-explorer.com/net-dns-monitor/app-review-demo.mp4` returned 404 on 2026-10-17; attach the recording instead. |
| `LSMinimumSystemVersion` is 27.0 because Homebrew's Python is built for macOS 27 (was 26.0 on 2026-09-27). Reviewers on the current public macOS 27 can run it; macOS 26 users cannot install it. | `scripts/appstore/build_appstore.py`, `docs/APP_STORE_SUBMISSION.md` section 4.3 | Decide whether macOS 26 matters; if so, build with a Python that targets an older macOS. |

Research behind this: rabbithole report (session scratchpad, 2026-10-02) citing
https://developer.apple.com/app-store/review/guidelines/ and
https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy
