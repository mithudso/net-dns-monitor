# Submitting Net-DNS-Monitor to the Mac App Store

This is the complete path from this repository to a submitted build, with the
decisions that are yours to make called out. Facts were checked against
Apple's documentation in September 2026; each source is linked where it is
used.

## 1. Read this first: what the store build can and cannot do

Every Mac App Store app runs in the App Sandbox, and Mac App Store apps may not
ask for root ([Guideline 2.4.5](https://developer.apple.com/app-store/review/guidelines/#2.4.5)).
Several features of the direct build therefore cannot ship in the store
build. The app detects the sandbox at startup
(`netdnsmonitor/distribution.py`). It switches those features off, and a
report says "not available in the Mac App Store build" rather than failing in
a way that looks like a network fault.

The table below was **measured** on 2026-09-14. The test was an ad-hoc-signed,
sandboxed build of this repo running `sandbox_probe` on macOS 26 (§4.1 shows
how to repeat it). "Apple docs" means the row rests on Apple's documentation,
not on a measurement.

| Feature | Direct build | Store build | Evidence |
|---|---|---|---|
| TCP reachability probes | yes | yes | measured |
| DNS lookups (system resolver and UDP to 1.1.1.1) | yes | yes | measured |
| Per-interface probe (`IP_BOUND_IF`) | yes | yes | measured, en0 connected |
| Ping heartbeat (`/sbin/ping`) | yes | yes | measured |
| Throughput counters (`netstat -ibn`) | yes | yes | measured |
| Ladder read-only checks (`scutil --nwi`, `scutil --dns`, `netstat -rn`, `route`) | yes | yes | measured |
| Failover **status** (`networksetup -listnetworkserviceorder`) | yes | yes, read-only | measured |
| Failover **switch** (`-ordernetworkservices`) | yes | no | Apple docs: the sandbox forbids "Configuring network settings" ([source](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox)) |
| DNS flush, DHCP renew, sudoers grant | yes | no | Guideline 2.4.5(v): no root |
| System log evidence, log pane, learned domains | yes | no | measured: `log: Cannot run while sandboxed` |
| Arbitrary-shell console | yes | no | Guideline 2.5.2 risk. Commands would also run sandboxed. |
| Router (pf, bootpd, dnsmasq, unbound) | yes | no | Guideline 2.4.5(ii) and (v) |
| Start at Login (LaunchAgent plist) | yes | no | Outside the container. Users add the app in System Settings → General → Login Items. |
| Keychain credentials | yes | yes | measured round trip |
| Reading `~/.config/net-dns-monitor/config.yaml` | yes | no | measured: blocked. The store build keeps its config in its container. |
| Claude diagnosis | yes, if key set | yes, after an explicit in-app permission | Guideline 5.1.2(i) |
| Slack and email alerts | yes | yes | network client entitlement; not delivered live |

**Decision for you:** if the failover switch, repairs, log evidence or router
are the reason you use this app, the store build is a reduced edition. The
full app can still ship outside the store with Developer ID signing and
notarization (§10). Both can coexist.

## 2. What is already done in this repo

- `netdnsmonitor/distribution.py` detects the sandbox and says which features are off.
- `netdnsmonitor/credentials.py` reads API keys from the Keychain as well as the environment. A sandboxed app launched from Finder has no shell environment.
- `netdnsmonitor/ai_consent.py` holds explicit, versioned, revocable permission before anything goes to Anthropic.
- `packaging/appstore/entitlements.plist` and `entitlements-helper.plist` define the sandbox, network client and network server entitlements, with no temporary exceptions.
- `scripts/appstore/build_appstore.py` builds, fixes and signs the bundle, then packages it:
  - rebuilds py2app's launcher against the current SDK;
  - strips the `itms-services` string that App Review has rejected in bundled Python ([cpython#120522](https://github.com/python/cpython/issues/120522));
  - deletes rpaths that point outside the bundle, and refuses any link to a library outside the bundle or the OS;
  - sets the minimum macOS version from the bundled binaries;
  - signs inside-out, verifies, and runs `productbuild`.
- `scripts/appstore/make_icon.py` generates a placeholder ICNS with the 512 and 512@2x sizes App Store Connect requires.
- `scripts/appstore/sandbox_probe.py` measures sandbox behaviour (§4.1).
- `docs/PRIVACY_POLICY.md` is a draft privacy policy with placeholders.

**Not verified here:**
- **Release mode was never run.** This Mac has no Apple Distribution or Mac Installer Distribution certificate, so release signing, provisioning-profile embedding and `productbuild` signing have not been run. Ad-hoc mode was run end to end.
- **The GUI app itself was not launched sandboxed.** Launching it cannot be automated (see CLAUDE.md). Only the probe executable was run.
- **Two helpers still shell out in the store build.** "Open forensic logs folder" runs `/usr/bin/open`, and the alert's notification fallback runs `osascript`. Neither has run sandboxed. Reports themselves now open through NSWorkspace. Click both once in the ad-hoc build.
- **Pasting into the credentials dialog needs a manual check.** The app now installs a standard Edit menu, so ⌘V should paste into Credentials → Set Anthropic API key…. No automated test can send a real keystroke. Try it once in the ad-hoc build before submitting.

## 3. One-time Apple setup

You need an [Apple Developer Program](https://developer.apple.com/programs/) membership ($99/year) and Xcode 26 or later. Xcode 26.6 is installed on this Mac.

### 3.1 Choose the bundle identifier

Use reverse-DNS on a domain or name you control, for example
`com.<yourname>.netdnsmonitor`. The default in `setup.py`
(`com.net-dns-monitor.app`) is only a placeholder for local builds.
**You cannot change a bundle ID after the first upload.**

### 3.2 Register the App ID

1. Go to [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/identifiers/list) → Identifiers → **+** → App IDs → App.
2. Platform: **macOS**. Enter a description. Choose **Explicit** and enter your bundle ID.
3. Capabilities: leave all unchecked. The sandbox is an entitlement, not a portal capability.

### 3.3 Create the two certificates

Either use Xcode → Settings → Accounts → your team → **Manage Certificates** → **+**, or create a CSR in Keychain Access and upload it on the Certificates page.

- **Apple Distribution** signs the app. Older name: "Mac App Distribution" / "3rd Party Mac Developer Application".
- **Mac Installer Distribution** signs the `.pkg`. Its identity is named `3rd Party Mac Developer Installer: <Name> (<TEAMID>)`.

Check that both are installed:

```bash
security find-identity -v -p codesigning   # shows "Apple Distribution: …"
security find-identity -v                  # also shows "3rd Party Mac Developer Installer: …"
```

The installer identity only appears without `-p codesigning`
([Apple forum](https://developer.apple.com/forums/thread/740423)). Your Team
ID is the 10-character value in parentheses.

### 3.4 Create the provisioning profile

Profiles → **+** → Distribution → **Mac App Store Connect** → select the App ID →
select the Apple Distribution certificate → name it → Download. The build
embeds it as `Contents/embedded.provisionprofile`. It is required for
TestFlight (otherwise ITMS-90889) ([Apple forum](https://developer.apple.com/forums/thread/733942)).

### 3.5 Create the app record in App Store Connect

[App Store Connect](https://appstoreconnect.apple.com/) → Apps → **+** → New App:

| Field | Value |
|---|---|
| Platforms | macOS |
| Name | `Net-DNS-Monitor` (30 characters max, must be unique on the store) |
| Primary language | English (U.S.) |
| Bundle ID | the one from §3.1 |
| SKU | any private string, e.g. `NETDNSMONITOR001` |
| User access | Full access |

### 3.6 Create an API key for uploads

App Store Connect → Users and Access → Integrations → App Store Connect API →
Team Keys → **+**, role **App Manager**. Download `AuthKey_<KEYID>.p8` once;
Apple does not let you download it again. Save it to
`~/.appstoreconnect/private_keys/`, where `altool` looks for it. Note the
**Key ID** and the **Issuer ID** shown on that page.

## 4. Build

Run from the repository root. The build uses the project venv with the pinned
tools:

```bash
python3.13 -m venv .venv            # or: uv venv -p python3.13 .venv
.venv/bin/pip install -r requirements-dev.txt -c constraints.txt
.venv/bin/pip install py2app -c constraints.txt
```

### 4.1 Ad-hoc build and sandbox probe (no Apple account needed)

```bash
.venv/bin/python scripts/appstore/build_appstore.py adhoc --with-probe
build/appstore/adhoc/dist/Net-DNS-Monitor.app/Contents/MacOS/sandbox_probe
```

The probe prints JSON and writes it to the probe's own container. Do this
after any change that adds a subprocess or file access, then update the table
in §1.

To try the sandboxed GUI app itself, run
`open build/appstore/adhoc/dist/Net-DNS-Monitor.app`. Quit your normal copy
first: two copies alert and fail over independently.

### 4.2 Release build

```bash
.venv/bin/python scripts/appstore/build_appstore.py release \
  --team-id <TEAMID> \
  --bundle-id <your.bundle.id> \
  --version 1.0 --build-number 1 \
  --copyright "2026 <Your Name>" \
  --privacy-policy-url "https://<where you host PRIVACY_POLICY.md>" \
  --app-identity "Apple Distribution: <Your Name> (<TEAMID>)" \
  --installer-identity "3rd Party Mac Developer Installer: <Your Name> (<TEAMID>)" \
  --profile ~/Downloads/<profile>.provisionprofile
```

- Add `--declare-exempt-encryption` only after you have answered §6.5.
- Increase `--build-number` on every upload. App Store Connect rejects a reused build number for the same version.

The build refuses to continue if:
- the privacy policy URL is missing, is not https, or still holds a placeholder;
- the profile belongs to a different app ID;
- the probe is in the bundle;
- `itms-services` survives anywhere;
- any binary links a library outside the bundle or `/System` / `/usr/lib`.

Output: `build/appstore/release/Net-DNS-Monitor-<version>-<build>.pkg`.

### 4.3 Facts about the resulting bundle

| Property | Value |
|---|---|
| Architecture | arm64 only |
| Minimum macOS | 26.0 |
| Size | about 57 MB |
| Category | `public.app-category.utilities` |

The minimum is 26.0 because Homebrew's Python 3.13 is built for macOS 26 on
Apple silicon, and an app cannot run below the highest minimum of its
binaries. Apple accepts arm64-only Mac apps, and macOS 27 is Apple-silicon
only ([Apple news](https://developer.apple.com/news/?id=k1mtkt1k)).

To support older macOS or Intel Macs, build with a python.org universal2
Python 3.13 instead. The script still patches `itms-services` and recomputes
the minimum.

## 5. Validate and upload

```bash
xcrun altool --validate-app build/appstore/release/Net-DNS-Monitor-1.0-1.pkg \
  --api-key <KEY_ID> --api-issuer <ISSUER_ID>

xcrun altool --upload-package build/appstore/release/Net-DNS-Monitor-1.0-1.pkg \
  --api-key <KEY_ID> --api-issuer <ISSUER_ID> --wait
```

Syntax is from the local `altool` 26.40.1 help. Alternatively, drag the
`.pkg` into Apple's **Transporter** app. Processing takes minutes to an hour.
The build then appears under the app's TestFlight tab. Mac TestFlight
installs it through the TestFlight app, which is the closest you can get to
the real store environment before review.

### 5.1 Menus in each build

Measured from the menu model after rumps registers its handlers. rumps adds "Quit" last in both builds, and three failover status rows sit at the top.

| Build | Top-level menu |
|---|---|
| Store | Open dashboard · Toggle mini window · Open last report · — · Test network alert · Credentials ▸ · Allow Claude diagnosis… · Withdraw Claude permission · Privacy Policy · — · Refresh network status |
| Direct | Open dashboard · Open console · Toggle mini window · Open last report · — · Router ▸ · Start at Login · Test network alert · Credentials ▸ · — · Switch to backup now · Switch back to preferred now · Refresh network status |

Credentials ▸ (both builds): Set Anthropic API key… · Set Slack webhook URL… · Set SMTP password… · — · Remove saved credentials.

Use these titles for screenshots and in the review notes below.

## 6. App Store Connect metadata

### 6.1 App Information

| Field | Proposed value | Notes |
|---|---|---|
| Subtitle | `Network & DNS troubleshooter` | 28 of 30 characters |
| Category | Primary **Utilities**; secondary **Developer Tools** | Must match `LSApplicationCategoryType` |
| Content rights | Does not contain third-party content | |
| Age rating | Answer the questionnaire truthfully | No web browsing, user-generated content, gambling or mature content. The app can show AI-written diagnostic text; say so if asked. ([age ratings](https://developer.apple.com/help/app-store-connect/reference/app-information/age-ratings-values-and-definitions)) |
| Privacy Policy URL | `<URL where you host docs/PRIVACY_POLICY.md>` | Required for macOS. GitHub Pages works. |

### 6.2 Pricing and Availability

Choose a price tier (free is fine) and territories. Pricing must be set before
you can submit ([source](https://developer.apple.com/help/app-store-connect/manage-app-pricing/set-a-price)).

### 6.3 App Privacy ("nutrition label")

The publisher receives no data and the app has no analytics.

The optional Claude diagnosis sends incident data from the user's Mac to
Anthropic under the user's own API key, and Anthropic may keep API data for a
period. Apple counts data as "collected" when it leaves the device and is
kept "longer than what is necessary to service the transmitted request in
real time" ([definition](https://developer.apple.com/app-store/app-privacy-details/)).

**Decision for you.** Two defensible answers:

1. **Conservative (recommended).** Data Types → **Diagnostics → Other Diagnostic Data** and **Other Data → Other Data Types**. For each: **Not linked** to the user's identity, **not used for tracking**, purpose **App Functionality**.
2. **Data Not Collected.** Defensible because nothing reaches the publisher, and the only destinations that receive incident content are services the user configures (Anthropic, Slack, email). It is weaker if a reviewer treats Anthropic as a third-party partner of the app. Note that the default connectivity checks (1.1.1.1, 8.8.8.8, a DNS lookup of api.anthropic.com) and the on-by-default LAN peer announcement run without configuration; they carry no incident content, and the privacy policy discloses both.

Slack and email alerts go to destinations the user controls. They are
disclosed in the privacy policy either way.

### 6.4 Version information (1.0)

**Description** (1,369 of 4,000 characters):

```
Net-DNS-Monitor watches your Mac's internet and DNS connectivity from the menu bar and tells you what is actually wrong when it breaks.

When a check fails, it separates the three things that look identical from a browser: your Mac's own link, the local network, and DNS. It runs an offline troubleshooting ladder, records what each step found, and writes an incident report you can hand to IT.

• Live round-trip time, packet loss and throughput in the menu bar and Dock
• Reachability checks against addresses you choose, bound to each network interface
• DNS checks with a control domain, so a DNS outage is not mistaken for a dead network
• An anti-flap gate: one outage, one alert
• Incident reports and a forensic timeline stored on your Mac
• Read-only view of your network service order
• Optional: Slack or email alerts when an incident starts
• Optional: ask Claude (your own Anthropic API key) for a diagnosis when the checks cannot explain an outage. Nothing is sent until you explicitly allow it, and you can withdraw permission at any time.
• Optional: compare notes with other Macs running the app on the same network

The app never claims a repair it did not perform. Anything this edition cannot do inside the Mac App Store sandbox, such as changing network settings, is reported as unavailable rather than attempted.

No account, no analytics, no ads.
```

**Keywords** (87 of 100 bytes):

```
network,DNS,monitor,wifi,outage,internet,ping,latency,diagnostics,troubleshoot,menu bar
```

| Field | Value |
|---|---|
| Support URL | `<URL with real contact information>` (required ([source](https://developer.apple.com/help/app-store-connect/reference/app-information/platform-version-information))) |
| Marketing URL | optional |
| Copyright | `2026 <Your Name>` |
| Build | select the processed upload |

**Screenshots:** 1 to 10 images, 16:10, exactly 1280x800, 1440x900, 2560x1600
or 2880x1800, JPEG or PNG with no alpha
([spec](https://developer.apple.com/help/app-store-connect/reference/app-information/screenshot-specifications)).
Suggested shots:
1. dashboard with live graphs;
2. menu bar menu open;
3. an incident report;
4. Settings;
5. the Claude permission dialog.

Take them on a Retina display at 1440x900 "looks like" so captures come out
at 2880x1800. Then strip alpha:

```bash
sips -s format jpeg shot.png --out shot.jpg
sips -g pixelWidth -g pixelHeight shot.jpg   # must read 2880 x 1800
```

### 6.5 Export compliance

The app uses HTTPS to Anthropic and Slack, and STARTTLS for SMTP, through
Python's `ssl` module and the OpenSSL library bundled in the app, not the
operating system's. Apple says encryption built into the OS is typically
exempt. Standard algorithms in a bundled library are a separate question you
must answer ([Apple](https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations),
[overview](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance)).

**Decision for you.** Answer App Store Connect's encryption questions for
standard TLS used only to protect data in transit. If your answer is
"exempt", rebuild with `--declare-exempt-encryption`. That writes
`ITSAppUsesNonExemptEncryption = NO` so later uploads skip the question.
Until then the key is deliberately absent, and App Store Connect asks on
each upload.

### 6.6 App Review Information

| Field | Value |
|---|---|
| Sign-in required | No |
| Contact | your name, phone, email |

**Notes** (1,796 of 4,000 bytes):

```
Net-DNS-Monitor is a menu bar and Dock utility that monitors network and DNS connectivity. No account is needed.

How to review:
1. Launch the app. A status item appears in the menu bar and the Dock tile shows the current round-trip time.
2. Choose "Open dashboard" to see live checks, graphs and the network service order (read-only).
3. In the dashboard, "Run full diagnosis" runs the troubleshooting checks. Steps that would need root or network-configuration rights say they are not available in this edition.
4. "Test network alert" shows the alert that normally appears when connectivity is lost.
5. "Allow Claude diagnosis…" shows exactly what would be sent to Anthropic and asks for permission. "Privacy Policy" opens the policy.

Sandbox and entitlements:
- com.apple.security.network.client: reachability checks, DNS lookups, HTTPS to the Anthropic API and Slack, SMTP.
- com.apple.security.network.server: UDP DNS responses and ICMP ping replies (Apple documents that both need client and server), and optional discovery of other copies of the app on the same local subnet.
- No temporary exception entitlements. Features that would need root or network-configuration rights (switching the network service order, flushing DNS, reading the system log) are disabled in this edition and reported as unavailable.

Third-party AI:
The optional Claude diagnosis requires the user's own Anthropic API key and an explicit in-app permission dialog that lists exactly what is sent, before anything is sent (Guideline 5.1.2(i)). Permission can be withdrawn from the menu. Reviewers do not need a key to use every other feature.

The app launches no helper processes that outlive it, installs nothing outside its container, and does not start at login unless the user adds it in System Settings.
```

## 7. Submit

Add the build to the 1.0 version and complete every section marked
incomplete. Click **Add for Review**, then **Submit to App Review**. Most
reviews finish within a few days. Answer rejections in Resolution Center;
you can reply without a new build when a note is enough.

## 8. Rejection risks and what to do

| Risk | Status | Mitigation |
|---|---|---|
| 2.5.2: bundled Python flagged for `itms-services` | Mitigated | Build strips and scans for it |
| 2.5.2: bundled interpreter treated as executing code | Unverified; no Apple text either way | Review notes state all code ships in the bundle and nothing is downloaded |
| 5.1.2(i): third-party AI without permission | Mitigated | Versioned consent gate, disclosure dialog, revoke menu |
| 5.1.1(i): privacy policy link inside the app | Mitigated | The store build's Privacy Policy menu item opens the bundled `NDMPrivacyPolicyURL`; release builds refuse to run without `--privacy-policy-url` |
| 2.4.5(viii): deprecated technologies | Risk | `rumps` posts notifications with `NSUserNotificationCenter`, deprecated since macOS 11; `alert.py` falls back to `osascript`. Neither has been tested sandboxed. If review objects, move to `UNUserNotificationCenter`, which needs a new dependency (`pyobjc-framework-UserNotifications`). |
| 4.2: minimum functionality | Low | Native menu bar utility with a real window |
| Icon quality | Placeholder | Replace `make_icon.py` output with a designed icon before release |
| ITMS-90236 (icon sizes) | Mitigated | ICNS includes 512 and 512@2x |
| Signing / provisioning errors | Release path unrun | Fix identities or profile per the error text, then re-run §4.2 |

## 9. Every upload

1. Bump `--build-number` (and `--version` for a new release).
2. Run `.venv/bin/python -m pytest -q`, then the ad-hoc build and probe (§4.1).
3. Run the release build (§4.2), then validate and upload (§5).
4. Update "What's New" and submit.

## 10. The full-featured alternative: Developer ID

Outside the store, the sandbox is optional and every feature works. The steps:

1. Sign the py2app bundle inside-out with a **Developer ID Application** certificate, `--options runtime --timestamp`.
2. Run `xcrun notarytool submit Net-DNS-Monitor.zip --keychain-profile <profile> --wait`.
3. Run `xcrun stapler staple Net-DNS-Monitor.app`, then distribute the app or a DMG from your own site.

`scripts/install.sh` builds that bundle today, but no signing or
notarization script exists for it yet.
