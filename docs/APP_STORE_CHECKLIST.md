# Mac App Store submission checklist

State as of **2026-09-17**, branch `feat/appstore-prep`. This file orders the
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
| Tests and lint | `python3 -m pytest -q`: 1884 passed in 22 s, offline. `ruff check .` and `ruff format --check .` clean |
| Ad-hoc sandboxed build | `build_appstore.py adhoc --with-probe` produced `build/appstore/adhoc/dist/Net-DNS-Monitor.app`: 58 MB, arm64, `LSMinimumSystemVersion` 26.0, `codesign --verify --strict --deep` valid, entitlements exactly app-sandbox + network.client + network.server, no `itms-services` anywhere, icon holds the 512 and 512@2x elements |
| Sandbox probe, run inside that bundle | Same result as 2026-09-14. Works: container write, TCP connect, `getaddrinfo`, UDP DNS, HTTPS, interface-bound connect on `en0`, UDP bind, Keychain round trip, `ping`, `networksetup -listnetworkserviceorder`, `scutil`, `netstat`, `ifconfig`, `route`. Refused: `log show` (`Cannot run while sandboxed`), reading the real `~/.config` |
| Local-network permission text | `NSLocalNetworkUsageDescription` is in every build's plist; the store build refuses a bundle without it (macOS 15+ prompt, Apple TN3179) |
| Apple rules re-checked | 5.1.2(i) names third-party AI (consent gate exists); privacy manifests and the April 2026 Xcode 26 SDK floor do not name macOS; the quarantine-attribute rule is handled by `xattr -cr`; the 2026 age-rating questionnaire and EU trader status are on the metadata list (§6) |
| Metadata drafts | Subtitle, category, description, keywords, review notes, privacy-label answers and the export answer: §6 |
| Privacy policy | `docs/PRIVACY_POLICY.md` drafted; three placeholders remain (publisher, contact, date) |
| Tooling | Xcode 27.0 (27A266a) on macOS 27.0, `altool` 27.0.5, Transporter installed, `.venv` on Python 3.13.15 with py2app 0.28.10 |
| Team ID | `L9ELX85ZFD`, from the OU field of the Apple Development certificate in the login keychain |

Not verified, because it cannot be from a script: the sandboxed GUI app was
not launched, so the manual checks in step 5 are still open. Release signing
has never run: this Mac has no distribution certificates (step 2).

## 2. Steps, in order

### Step 0. Decide (nothing to run)

- [ ] **Bundle identifier.** Recommended `com.mitchhudson.netdnsmonitor`: reverse-DNS
      on your name, and distinct from the direct build's `com.net-dns-monitor.app`
      so both editions can be installed side by side. It cannot change after the
      first upload (§3.1).
- [ ] **Store name.** `Net-DNS-Monitor` (30 characters max, unique across the store).
      Have a fallback ready, for example `Net-DNS-Monitor: Network Check`.
- [ ] **Price and territories.** Free is fine. Including the European Union
      requires the DSA trader-status declaration (§6.6).
- [ ] **Publisher name, contact email, support URL, policy effective date.** They
      go into `docs/PRIVACY_POLICY.md` and App Store Connect.
- [ ] **Icon.** A designed 1024x1024 icon; the build generates a placeholder
      otherwise. To make an `.icns` from a PNG set:

```bash
mkdir AppIcon.iconset
for s in 16 32 128 256 512; do
  sips -z $s $s icon1024.png --out AppIcon.iconset/icon_${s}x${s}.png
  sips -z $((s*2)) $((s*2)) icon1024.png --out AppIcon.iconset/icon_${s}x${s}@2x.png
done
iconutil -c icns AppIcon.iconset -o NetDNSMonitor.icns
```

### Step 1. Apple Developer Program

- [ ] Membership is **paid and active** for team `L9ELX85ZFD`:
      <https://developer.apple.com/account> → Membership details. A free
      "Personal Team" cannot create distribution certificates; enrolling costs
      $99/year and can take a day or two to activate.
- [ ] The **latest Program License Agreement is accepted** (App Store Connect →
      Agreements). Uploads are refused until the account holder accepts the
      current version; this is the most common first-upload blocker.
- [ ] Two-factor authentication is on for the Apple ID (required for the program).

### Step 2. Identifier, certificates, profile

- [ ] Register the App ID: explicit, the bundle ID from step 0, macOS, no
      capabilities ticked (§3.2).
- [ ] Create and install **Apple Distribution** and **Mac Installer Distribution**
      certificates (§3.3). Done when both lines print:

```bash
security find-identity -v -p codesigning | grep "Apple Distribution: Mitchell Hudson (L9ELX85ZFD)"
security find-identity -v | grep "3rd Party Mac Developer Installer: Mitchell Hudson (L9ELX85ZFD)"
```

- [ ] Create a **Mac App Store Connect** provisioning profile for the App ID with
      the Apple Distribution certificate (§3.4) and download it to
      `~/Downloads/NetDNSMonitor_AppStore.provisionprofile`. Done when this prints
      `L9ELX85ZFD.<your bundle id>`:

```bash
security cms -D -i ~/Downloads/NetDNSMonitor_AppStore.provisionprofile \
  | plutil -extract Entitlements.com.apple.application-identifier raw -
```

### Step 3. Public pages

- [ ] Replace `<PUBLISHER NAME>`, `<CONTACT EMAIL>` and `<EFFECTIVE DATE>` in
      `docs/PRIVACY_POLICY.md`.
- [ ] Host it at an `https://` URL. This repository is private and GitHub Pages on
      a private repository needs a paid plan, so use a small public repository
      with Pages, a public Gist, or a site you control. The release build refuses
      to run until the URL is real (§4.2).
- [ ] A support URL with real contact information (§6.4). The same page can serve
      both.

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

Run from this worktree (`.claude/worktrees/appstore-prep`) with its `.venv`.
Replace the four placeholders; the identity strings must match
`security find-identity -v` exactly.

```bash
.venv/bin/python scripts/appstore/build_appstore.py release \
  --team-id L9ELX85ZFD \
  --bundle-id com.mitchhudson.netdnsmonitor \
  --version 1.0 --build-number 1 \
  --copyright "2026 Mitchell Hudson" \
  --privacy-policy-url "https://<where the policy is hosted>" \
  --declare-exempt-encryption \
  --icon "<path to the designed .icns>" \
  --app-identity "Apple Distribution: Mitchell Hudson (L9ELX85ZFD)" \
  --installer-identity "3rd Party Mac Developer Installer: Mitchell Hudson (L9ELX85ZFD)" \
  --profile ~/Downloads/NetDNSMonitor_AppStore.provisionprofile
```

- [ ] Output is `build/appstore/release/Net-DNS-Monitor-1.0-1.pkg` and the
      script's own `pkgutil --check-signature` passed.
- [ ] This mode has never run with real certificates. If it stops, the message
      names the check that failed (§4.2 lists them); an identity-not-found error
      means the quoted name differs from `security find-identity -v`.

### Step 7. Validate, upload, TestFlight

```bash
xcrun altool --validate-app build/appstore/release/Net-DNS-Monitor-1.0-1.pkg \
  --api-key <KEY_ID> --api-issuer <ISSUER_ID>
xcrun altool --upload-package build/appstore/release/Net-DNS-Monitor-1.0-1.pkg \
  --api-key <KEY_ID> --api-issuer <ISSUER_ID> --wait
```

Or drag the `.pkg` into `/Applications/Transporter.app` (§5).

- [ ] The build shows as processed under the app's TestFlight tab (minutes to an
      hour). Processing e-mails name any ITMS-* problem; §8 has the known ones.
- [ ] Optional but recommended: install it through TestFlight on a second Mac.

### Step 8. Metadata in App Store Connect (§6 has every value)

- [ ] **App Information**: subtitle, primary category Utilities, secondary
      Developer Tools, content rights, privacy policy URL (§6.1).
- [ ] **Pricing and Availability**: price tier (free), territories (§6.2).
- [ ] **EU trader status** declared if the EU is in the territory list (§6.6).
- [ ] **App Privacy**: "Yes, we collect data" with the two declared types, not
      linked to the user, not used for tracking, App Functionality (§6.3).
- [ ] **Age rating**: the questionnaire that took effect on 2026-01-31, answered
      fresh (§6.1).
- [ ] **Version 1.0**: description, keywords, support URL, marketing URL
      (optional), copyright `2026 Mitchell Hudson`, the processed build, "What's
      New" (not needed for 1.0) (§6.4).
- [ ] **Screenshots**: 1 to 10, exactly 2880x1800 (or the other three 16:10
      sizes), JPEG or PNG without alpha; capture at 1440x900 "looks like" on a
      Retina display and strip alpha with `sips` (§6.4).
- [ ] **App Review Information**: contact name, phone, e-mail; sign-in not
      required; the notes text from §6.7.
- [ ] **Export compliance**: exempt; the plist already says
      `ITSAppUsesNonExemptEncryption = NO` (§6.5).
- [ ] **EULA**: leave Apple's standard EULA unless you have your own.

### Step 9. Submit and afterwards

- [ ] **Add for Review**, then **Submit to App Review** (§7).
- [ ] On rejection, answer in Resolution Center; §8 lists the likely causes and
      the prepared responses. Only a code change needs a new build (bump
      `--build-number`).
- [ ] After approval: tag this branch (`git tag v1.0-appstore-1`), record the App
      Store Connect app ID in this file, and merge `feat/appstore-prep` into
      `master`. That merge changes the live resolver on this Mac
      (`unbound/unbound.conf` and `dnsmasq/dnsmasq.conf` are symlinked from
      `/opt/homebrew/etc`), so plan an unbound restart.

## 3. Every later upload

1. Bump `--build-number` (and `--version` for a new release).
2. `ruff check . && ruff format --check . && python3 -m pytest -q`.
3. Ad-hoc build, probe, and the step 5 checks that touch what changed.
4. Release build (step 6), validate and upload (step 7), "What's New", submit.

## 4. Open items that do not block submission

- The NAT LaunchDaemon on this Mac still runs a user-writable script as root
  until `sudo router/scripts/install_persistent_nat.sh` is re-run (CLAUDE.md,
  Known-unverified areas).
- `net-dns-monitor/net-dns-monitor/` in the main checkout is a stock Xcode
  SwiftUI template created on 2026-09-15, untracked, with its own `.git`. It
  is not part of this build; delete it or move it out of the repository.
- `docs/MCP.md` and `docs/caching-and-optimization.md` arrived empty from
  `master`; fill or delete them.
- The GitHub repository's default branch is `docs/scripts-manual`, not
  `master`; PRs and CI default to it.
- `master`'s working tree holds uncommitted lint edits (8 files) that this
  branch has already superseded; discard them when `master` is fast-forwarded.
