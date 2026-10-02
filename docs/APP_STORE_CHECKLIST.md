# Mac App Store submission checklist

State as of **2026-09-27**, branch `master` (the App Store work merged in
PR #6). This file orders the
work and records what is done; `docs/APP_STORE_SUBMISSION.md` explains each
step and holds the metadata text. Section numbers in the form §n refer to that
document.

The store edition is a reduced build: no failover switch, no privileged
repairs, no unified-log evidence, no router, no shell console, no LaunchAgent
login item (§1 has the measured table). If those are why you use the app,
ship the full build outside the store instead (§10). Both can coexist.

## 1. Done and verified on this Mac

| Item | Evidence (2026-09-17) |
|---|---|
| Store edition code | `netdnsmonitor/distribution.py` (sandbox gating), `credentials.py` (Keychain), `ai_consent.py` (Guideline 5.1.2(i) permission) |
| Tests and lint | `python3 -m pytest -q`: 2129 passed in 27 s, offline (2026-09-27). `ruff check .` and `ruff format --check .` clean |
| Ad-hoc sandboxed build | `build_appstore.py adhoc --with-probe` produced `build/appstore/adhoc/dist/Net-DNS-Monitor.app`: 58 MB, arm64, `LSMinimumSystemVersion` 26.0, `codesign --verify --strict --deep` valid, entitlements exactly app-sandbox + network.client + network.server, no `itms-services` anywhere, icon holds the 512 and 512@2x elements |
| Sandbox probe, run inside that bundle | Same result as 2026-09-14. Works: container write, TCP connect, `getaddrinfo`, UDP DNS, HTTPS, interface-bound connect on `en0`, UDP bind, Keychain round trip, `ping`, `networksetup -listnetworkserviceorder`, `scutil`, `netstat`, `ifconfig`, `route`. Refused: `log show` (`Cannot run while sandboxed`), reading the real `~/.config` |
| Local-network permission text | `NSLocalNetworkUsageDescription` is in every build's plist; the store build refuses a bundle without it (macOS 15+ prompt, Apple TN3179) |
| Apple rules re-checked | 5.1.2(i) names third-party AI (consent gate exists); privacy manifests and the April 2026 Xcode 26 SDK floor do not name macOS; the quarantine-attribute rule is handled by `xattr -cr`; the 2026 age-rating questionnaire and EU trader status are on the metadata list (§6) |
| Metadata drafts | Subtitle, category, description, keywords, review notes, privacy-label answers and the export answer: §6 |
| Privacy policy | `docs/PRIVACY_POLICY.md` complete (publisher, contact, effective date 2026-09-27); public copy at <https://llms-explorer.com/net-dns-monitor/privacy/>, support page at <https://llms-explorer.com/net-dns-monitor/> (both from the `llms-explorer` repository, deployed by Cloudflare Pages) |
| Icon | Drawn in code by `scripts/appstore/make_icon.py`, reviewed 2026-09-27; the ICNS carries 512 and 512@2x |
| Tooling | Xcode 27.0 (27A266a) on macOS 27.0, `altool` 27.0.5, Transporter installed, `.venv` on Python 3.13.15 with py2app 0.28.10 |
| Rebuilt on `master` (2026-09-27) | After the dependency bumps (`anthropic` 1.8.0, `pyobjc` 12.2.2), with the repo `.venv` on Python 3.14.7: 81 MB, `LSMinimumSystemVersion` 26.0, signature valid, same three entitlements, probe result unchanged. The first rebuild said 27.0: Homebrew's `liblzma` bottle is built for macOS 27, and the build sets the minimum from the highest `minos` in the bundle. `setup.py` now excludes `lzma` from the store build; nothing uses xz |
| Team ID | `L9ELX85ZFD`, from the OU field of the Apple Development certificate in the login keychain |

Not verified, because it cannot be from a script: the sandboxed GUI app was
not launched, so the manual checks in step 5 are still open. Release signing
has never run: this Mac has no distribution certificates (step 2).

## 2. Steps, in order

### Step 0. Decide (nothing to run)

- [x] **Bundle identifier.** Decided 2026-09-27: `com.mitchhudson.netdnsmonitor`,
      reverse-DNS on the publisher's name, and distinct from the direct build's
      `com.net-dns-monitor.app` so both editions can be installed side by side. It
      cannot change after the first upload (§3.1).
- [x] **Store name.** `Net-DNS-Monitor` (30 characters max, unique across the store).
      Fallback if taken: `Net-DNS-Monitor: Network Check`.
- [x] **Price and territories.** Free. All territories; the European Union needs
      the DSA trader-status declaration (§6.6), answered as a non-trader since the
      app earns nothing.
- [x] **Publisher name, contact email, support URL, policy effective date.**
      Mitchell Hudson · mitchphudson@gmail.com ·
      <https://llms-explorer.com/net-dns-monitor/> · 2026-09-27. Filled into
      `docs/PRIVACY_POLICY.md`; the same values go into App Store Connect.
- [x] **Icon.** Drawn in code by `scripts/appstore/make_icon.py` (reviewed
      2026-09-27 via `make_icon.py preview.png`); every build gets it without
      `--icon`. A hand-made replacement still ships through `--icon`; to make an
      `.icns` from a PNG set:

```bash
mkdir AppIcon.iconset
for s in 16 32 128 256 512; do
  sips -z $s $s icon1024.png --out AppIcon.iconset/icon_${s}x${s}.png
  sips -z $((s*2)) $((s*2)) icon1024.png --out AppIcon.iconset/icon_${s}x${s}@2x.png
done
iconutil -c icns AppIcon.iconset -o NetDNSMonitor.icns
```

### Step 1. Apple Developer Program

- [x] Membership is **paid and active** (owner, 2026-09-27) for team `L9ELX85ZFD`:
      <https://developer.apple.com/account> → Membership details. A free
      "Personal Team" cannot create distribution certificates; enrolling costs
      $99/year and can take a day or two to activate.
- [x] The **latest Program License Agreement is accepted** (owner, 2026-09-27) (App Store Connect →
      Agreements). Uploads are refused until the account holder accepts the
      current version; this is the most common first-upload blocker.
- [x] Two-factor authentication is on (the distribution certificates could not have been created without it) for the Apple ID (required for the program).

### Step 2. Identifier, certificates, profile

- [x] Register the App ID: explicit, the bundle ID from step 0, macOS, no
      capabilities ticked (§3.2).
- [x] Create and install **Apple Distribution** and **Mac Installer Distribution**
      certificates (§3.3). Done when both lines print:

```bash
security find-identity -v -p codesigning | grep "Apple Distribution: Mitchell Hudson (L9ELX85ZFD)"
security find-identity -v | grep "3rd Party Mac Developer Installer: Mitchell Hudson (L9ELX85ZFD)"
```

- [x] Create a **Mac App Store Connect** provisioning profile for the App ID with
      the Apple Distribution certificate (§3.4) and download it to
      `~/Downloads/NetDNSMonitor_AppStore.provisionprofile`. Done when this prints
      `L9ELX85ZFD.<your bundle id>`:

```bash
security cms -D -i ~/Downloads/NetDNSMonitor_AppStore.provisionprofile \
  | python3 -c 'import plistlib,sys; print(plistlib.loads(sys.stdin.buffer.read())["Entitlements"]["com.apple.application-identifier"])'
```

(Not `plutil -extract`: it splits key paths on dots, and the key name
contains dots, so it reports "No value at that key path" for a good profile.)

### Step 3. Public pages

- [x] Publisher, contact and effective date filled into `docs/PRIVACY_POLICY.md`
      (2026-09-27).
- [x] Hosted at <https://llms-explorer.com/net-dns-monitor/privacy/>. This
      repository is private and GitHub Pages on a private repository needs a paid
      plan, so the page lives in the `llms-explorer` repository
      (`site/src/pages/net-dns-monitor/privacy.astro`), which Cloudflare Pages
      deploys on merge to `main`. The release build refuses to run until the URL
      answers (§4.2); check with `curl -sI` before step 6.
- [x] Support URL with real contact information (§6.4):
      <https://llms-explorer.com/net-dns-monitor/>, same repository.

### Step 4. App Store Connect record

- [ ] Apps → **+** → New App: macOS, the name, English (U.S.), the bundle ID, an SKU
      such as `NETDNSMONITOR001` (§3.5).
- [ ] For command-line uploads, an App Store Connect API key with the App Manager
      role, saved to `~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8`; note the
      Key ID and Issuer ID (§3.6). Skip this if you will drag the package into
      Transporter.

### Step 5. Manual checks on the ad-hoc build (no account needed)

Quit your normal copy first; two copies alert and fail over independently.

```bash
.venv/bin/python scripts/appstore/build_appstore.py adhoc --with-probe
build/appstore/adhoc/dist/Net-DNS-Monitor.app/Contents/MacOS/sandbox_probe   # JSON; compare with §1
open build/appstore/adhoc/dist/Net-DNS-Monitor.app
```

- [ ] The **Local Network** prompt appears on first launch and shows the app's
      reason text; allow it.
- [ ] **Credentials → Set Anthropic API key…**: ⌘V pastes into the field.
- [ ] **Open forensic logs folder** opens Finder (this runs `/usr/bin/open` inside
      the sandbox; not yet observed).
- [ ] **Test network alert** shows a notification (rumps uses the deprecated
      `NSUserNotificationCenter`, with an `osascript` fallback; not yet observed,
      and §8 names the fallback plan).
- [ ] **Open dashboard → Run full diagnosis**: every step that needs root or
      network-configuration rights reads "not available in the Mac App Store
      build", and nothing reads like a network fault.
- [ ] **Allow Claude diagnosis…** lists what would be sent and asks; **Withdraw
      Claude permission** reverses it; **Privacy Policy** opens the bundled URL
      (in the ad-hoc build the URL is empty, so expect nothing to open).
- [ ] Deny the Local Network permission once (System Settings → Privacy &
      Security → Local Network), note what the dashboard reports, then re-allow.
      `docs/known-issues.md` records why this matters.
- [ ] Take the screenshots for step 8 while the app is open.

### Step 6. Release build

Run from the repository root with its `.venv`. Check that the build prints
`Minimum macOS: 26.0`; a higher number means a newly bundled binary raised the
floor (find it with `otool -l <file> | grep minos`).
The identity strings must match `security find-identity -v` exactly; the icon
needs no flag (the build draws it).

```bash
.venv/bin/python scripts/appstore/build_appstore.py release \
  --team-id L9ELX85ZFD \
  --bundle-id com.mitchhudson.netdnsmonitor \
  --version 1.0 --build-number 1 \
  --copyright "2026 Mitchell Hudson" \
  --privacy-policy-url "https://llms-explorer.com/net-dns-monitor/privacy/" \
  --declare-exempt-encryption \
  --app-identity "Apple Distribution: Mitchell Hudson (L9ELX85ZFD)" \
  --installer-identity "3rd Party Mac Developer Installer: Mitchell Hudson (L9ELX85ZFD)" \
  --profile ~/Downloads/NetDNSMonitor_AppStore.provisionprofile
```

- [x] Output is `build/appstore/release/Net-DNS-Monitor-1.0-1.pkg` and the
      script's own `pkgutil --check-signature` passed. First run with real
      certificates, 2026-09-27, from a clean checkout of `e71a6de`: 34 MB pkg;
      app signed `Apple Distribution: Mitchell Hudson (L9ELX85ZFD)`, profile
      embedded (expires 2027-09-27), entitlements app-sandbox + network.client +
      network.server + the application and team identifiers,
      `LSMinimumSystemVersion` 26.0, `ITSAppUsesNonExemptEncryption` false, no
      sandbox probe. Build from a clean checkout: the build bundles whatever is
      in the working tree, uncommitted edits included.
- [ ] If it stops, the message names the check that failed (§4.2 lists them);
      an identity-not-found error means the quoted name differs from
      `security find-identity -v`.

### Step 7. Validate, upload, TestFlight

```bash
xcrun altool --validate-app build/appstore/release/Net-DNS-Monitor-1.0-1.pkg \
  --api-key <KEY_ID> --api-issuer <ISSUER_ID>
xcrun altool --upload-package build/appstore/release/Net-DNS-Monitor-1.0-1.pkg \
  --api-key <KEY_ID> --api-issuer <ISSUER_ID> --wait
```

Or drag the `.pkg` into `/Applications/Transporter.app` (§5).

Uploads so far (2026-09-27):

| Build | From | State |
|---|---|---|
| 1.0 (1) | `e71a6de` | Uploaded via Transporter. **Never submit it**: its store dashboard still shows "Open console (arbitrary shell)", the elevated-permission, router and prewarm buttons (Guidelines 2.5.2, 2.4.5) |
| 1.0 (2) | `320fb1f` | Built from a clean checkout; those buttons and Flush DNS hidden; 2124 tests passed there; bundled `netdnsmonitor/` byte-identical to the commit. Staged at `build/appstore/upload/Net-DNS-Monitor-1.0-2.pkg` for upload |

- [x] The build shows as processed under the app's TestFlight tab (minutes to an
      hour). Processing e-mails name any ITMS-* problem; §8 has the known ones.
      1.0 (3), built from `395c14e` (the store dashboard without the log column),
      uploaded 2026-09-27 19:59 CDT, processed by 20:01, and attached to
      version 1.0. It is the submitted build.
- [ ] Optional but recommended: install it through TestFlight on a second Mac.

### Step 8. Metadata in App Store Connect (§6 has every value)

- [x] **App Information**: subtitle, primary category Utilities, secondary
      Developer Tools, content rights, privacy policy URL (§6.1).
- [x] **Pricing and Availability**: price tier (free), territories (§6.2).
- [x] **EU trader status** declared if the EU is in the territory list (§6.6).
      Account-level, so the territories page never asks: Business → Agreements
      → the banner's "Complete Compliance Requirements" → "I'm not a trader
      under the DSA". Done 2026-09-27; the Compliance table shows Digital
      Services Act, 27 countries, Active.
- [x] **App Privacy**: "Yes, we collect data" with the two declared types, not
      linked to the user, not used for tracking, App Functionality (§6.3).
      Published 2026-09-27 (an earlier draft had picked Crash Data and
      Performance Data, which the app does not collect; replaced).
- [x] **Age rating**: the questionnaire that took effect on 2026-01-31, answered
      fresh (§6.1).
- [x] **Version 1.0**: description, keywords, support URL, marketing URL
      (optional), copyright `2026 Mitchell Hudson`, the processed build, "What's
      New" (not needed for 1.0) (§6.4). Build 1.0 (3) selected 2026-09-27.
- [x] **Screenshots**: three prepared 2026-09-27 in `build/appstore/screenshots/`
      (the dashboard, the dashboard after Run full diagnosis, the Claude
      permission dialog), each exactly 2880x1800 PNG without alpha. Retake
      after any UI change:

```bash
.venv/bin/python scripts/appstore/shoot_screenshots.py build/appstore/screenshots/raw
.venv/bin/python scripts/appstore/compose_screenshots.py build/appstore/screenshots/raw build/appstore/screenshots
```

      The first runs the app from source as the store edition, isolated under
      its output directory (its own config with every path the app writes moved
      there, alerts and peer discovery off, empty credentials, its own consent
      file), waits for
      each of the app's readiness signals and renders each window in-process,
      so it needs no screen-recording permission; it clicks the diagnosis only
      on a healthy network. The second composes each window on a 2880x1800
      background. The spec: 1 to 10 images, exactly 2880x1800 (or the other
      three 16:10 sizes), JPEG or PNG without alpha (§6.4).
- [x] **App Review Information**: contact name, phone, e-mail; sign-in not
      required; the notes text from §6.7. Done 2026-09-27 ("Sign-in required"
      had been ticked with placeholder credentials; unticked).
- [x] **Export compliance**: exempt; the plist already says
      `ITSAppUsesNonExemptEncryption = NO` (§6.5). App Store Connect never
      asked.
- [x] **EULA**: Apple's standard EULA.

### Step 9. Submit and afterwards

- [x] **Add for Review**, then **Submit to App Review** (§7). Submitted
      2026-09-27 at 20:08 CDT: "1.0 Waiting for Review", one item, build
      1.0 (3), set to release automatically on approval. App Store Connect app
      ID `6816765128` (<https://appstoreconnect.apple.com/apps/6816765128>).
- [x] On rejection (2026-09-28: Guideline 2.1 App Completeness / new developer account questionnaire):
      Complete response prepared in `docs/APP_STORE_REVIEW_RESPONSE.md` addressing all 6 items
      (screen recording walkthrough guide, purpose, setup instructions, external services,
      regional consistency, regulatory compliance). Updated review notes in `docs/APP_STORE_SUBMISSION.md`.
      No new build required; reply directly in App Store Connect Resolution Center.
- [ ] After approval: tag the submitted commit on `master`
      (`git tag v1.0-appstore-3 395c14e && git push github v1.0-appstore-3`).

## 3. Every later upload

1. Bump `--build-number` (and `--version` for a new release).
2. `ruff check . && ruff format --check . && python3 -m pytest -q`.
3. Ad-hoc build, probe, and the step 5 checks that touch what changed.
4. Release build (step 6), validate and upload (step 7), "What's New", submit.

## 4. Open items that do not block submission

- Done 2026-09-27 (owner chose to fix before submitting): the store build's
  dashboard leaves out the system-log column, which in the sandbox could only
  answer `UNAVAILABLE_IN_APP_STORE_BUILD`; the window is the left column alone
  (`DashboardWindow(log_column=False)`). Needs build 3 and retaken screenshots.

- The NAT LaunchDaemon on this Mac still runs a user-writable script as root
  until `sudo router/scripts/install_persistent_nat.sh` is re-run (CLAUDE.md,
  Known-unverified areas).
- `net-dns-monitor/net-dns-monitor/` in the main checkout is a stock Xcode
  SwiftUI template created on 2026-09-15, untracked, with its own `.git`. It
  is not part of this build; delete it or move it out of the repository.
- `docs/MCP.md` and `docs/caching-and-optimization.md` arrived empty from
  `master`; fill or delete them.
