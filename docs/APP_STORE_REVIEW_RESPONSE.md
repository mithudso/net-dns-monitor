# Apple App Review Guideline 2.1 Rejection Response & Operational Package

**App Name:** Net-DNS-Monitor  
**Bundle ID:** `com.mitchhudson.netdnsmonitor`  
**Version / Build:** 1.0 (3)  
**Submission ID:** `4283c533-7a50-4d5d-91ff-af3f312417de`  
**Rejection Reason:** Guideline 2.1 - Performance: App Completeness (New App Submission Information Needed)  
**Date of Rejection:** September 28, 2026 (7:16 PM)  
**Resolution Date:** September 28, 2026  

---

## 1. App Store Connect: "Reply to App Review" Response Text

*Copy and paste the exact text below into the Resolution Center reply box in App Store Connect:*

```markdown
Dear Apple App Review Team,

Thank you for reviewing Net-DNS-Monitor. We are providing the complete information requested under Guideline 2.1 to clarify the app's functionality, architecture, and operational model. We have also mirrored this information into the Notes field of the App Review Information section for future submissions.

---

### 1. Demonstration Screen Recording
We have uploaded a screen recording captured on a physical Mac running macOS Sonoma/Sequoia demonstrating the end-to-end user flow:
- Video URL: https://llms-explorer.com/net-dns-monitor/app-review-demo.mp4
  (Also attached directly to this message / uploaded to App Store Connect)
- Demonstration Steps Shown:
  1. Launching Net-DNS-Monitor from Finder / Applications.
  2. Appearance of the live status item in the macOS menu bar and live RTT latency badge on the macOS Dock tile.
  3. Clicking the menu bar item to reveal the primary menu surfaces.
  4. Opening the live Dashboard window displaying real-time interface reachability, TCP connect heartbeats, throughput counters, and read-only network service order.
  5. Clicking "Run full diagnosis" to execute the troubleshooting ladder, showing real-time checks and sandboxed safety notices.
  6. Opening the floating HUD Mini Window.
  7. Opening "Allow Claude diagnosis…" showing the granular, versioned user-consent dialog that details the exact data payload before any external AI transmission.
  8. Accessing "Privacy Policy" directly from the application menu, which opens our public privacy documentation.

*Specific Flow Confirmations:*
- Account creation, login, and deletion: Net-DNS-Monitor requires NO account, registration, or login. All monitoring operates locally on-device. No user accounts exist to delete.
- User-generated content: There is NO user-generated content, public posting, social feed, or public communication channel.
- Paid content / In-App Purchases: There are NO paid features, subscriptions, in-app purchases, or paywalls. All functionality in this edition is free and unlocked.

---

### 2. Purpose and Target Audience
- **Problem Solved:** When internet connectivity fails, macOS users and IT professionals struggle to identify whether the failure is caused by their local Wi-Fi/Ethernet link, local router/DHCP gateway, or remote upstream DNS resolution. Typical browsers simply display a generic "No Internet" screen.
- **App Purpose:** Net-DNS-Monitor is a native macOS menu bar utility that runs continuous, low-overhead connectivity probes across two tiers (a 5-second TCP heartbeat and a 30-second multi-resolver DNS matrix). When connectivity degrades, it executes an offline troubleshooting ladder and generates structured incident reports with forensic timestamps that users can inspect or hand to network administrators.
- **Target Audience:** Mac users, remote professionals, software developers, network administrators, and IT support staff who require transparent, verifiable network status and forensic evidence during outages.

---

### 3. Setup and Access Instructions
- **Credentials Required:** NONE. No login credentials, test accounts, or sample files are required.
- **Step-by-step Setup:**
  1. Open Net-DNS-Monitor.app.
  2. The app immediately initializes its passive network probes and displays a green/amber/red status item in the menu bar and latency reading on the Dock tile.
  3. Click the menu bar icon and select "Open dashboard" to view live telemetry.
  4. Click "Run full diagnosis" to run the local diagnostic checks.
  5. (Optional) Under "Credentials ▸", users may optionally store their own personal Anthropic API key, Slack webhook URL, or SMTP credentials in their secure macOS Keychain if they wish to receive remote alerts or optional AI incident diagnoses. The entire application is fully functional without setting any of these optional keys.

---

### 4. External Services, Tools, and Platforms
Net-DNS-Monitor communicates strictly with standard, publicly accessible network infrastructure and user-configured endpoints:
- **Connectivity Probes (Default):**
  - Cloudflare Public DNS (`1.1.1.1:443` via TCP, port 53 via UDP)
  - Google Public DNS (`8.8.8.8:443` via TCP, port 53 via UDP)
  - DNS control query resolving `api.anthropic.com`
  *Note:* These outbound packets contain no personal data, user identifiers, or device telemetry.
- **Local Subnet Peer Discovery (Default, Optional):**
  - Sends UDP broadcast packets on the local subnet (`255.255.255.255:51413`) allowing multiple Macs running Net-DNS-Monitor on the same LAN to compare connectivity state. Can be disabled in settings.
- **Anthropic Claude API (Optional, User-Configured):**
  - Service: Anthropic Messages API (`https://api.anthropic.com/v1/messages`).
  - Purpose: Generates plain-language diagnostic explanations of network incidents.
  - Safeguards: Strictly opt-in. Requires the user's own API key stored in macOS Keychain. Requires explicit consent via an in-app permission dialog listing all payload fields before transmission. Explicitly revocable at any time via "Withdraw Claude permission". Sensitive strings configured by the user are redacted prior to sending.
- **Slack Webhooks & SMTP (Optional, User-Configured):**
  - Delivers incident alert summaries directly to the user's private Slack channel or personal email.
- **Analytics & Tracking:**
  - NONE. No third-party SDKs, telemetry frameworks, crash reporters, or advertising networks are bundled.

---

### 5. Regional Differences
- The application functions consistently across all geographic regions and territories.
- There are no regional feature restrictions, geofences, or localized content variations. Default target IP addresses (1.1.1.1 and 8.8.8.8) utilize global anycast routing.

---

### 6. Regulatory and Third-Party Material Documentation
- Net-DNS-Monitor does not operate in a highly regulated industry (finance, banking, medical, gambling, legal).
- It contains no proprietary third-party copyrighted media, trademarks, or restricted intellectual property.
- All code is executed locally within the App Store App Sandbox using standard macOS POSIX and AppKit APIs.

Please let us know if any further clarification or demonstration is needed to finalize approval.

Sincerely,  
Mitchell Hudson  
Developer, Net-DNS-Monitor
```

---

## 2. Updated App Review Information Notes

*Paste this text into the "Notes" field under App Store Connect → App Review Information (under 4,000 characters):*

```
Net-DNS-Monitor is a native macOS menu bar utility that monitors internet and DNS connectivity.

NO ACCOUNT OR LOGIN REQUIRED:
The app requires no account registration, login credentials, or test accounts. All monitoring is passive and local.

HOW TO REVIEW:
1. Launch the app. A status item appears in the menu bar and the Dock tile displays the current round-trip time.
2. Select "Open dashboard" from the menu to inspect live interface reachability, ping statistics, and network service order.
3. Click "Run full diagnosis" in the dashboard to execute the diagnostic checks. In compliance with the App Sandbox, checks requiring root or network reconfiguration privileges safely report as unavailable.
4. Select "Toggle mini window" to see the floating HUD status display.
5. Select "Test network alert" to trigger a simulated notification banner.
6. Select "Allow Claude diagnosis…" to inspect the transparent user-consent dialog that governs optional third-party AI escalation.
7. Select "Privacy Policy" to view the privacy policy in Safari.

SANDBOX & ENTITLEMENTS:
- com.apple.security.network.client: Outbound TCP reachability probes, system DNS resolution, and optional user-configured HTTPS API calls.
- com.apple.security.network.server: Required for UDP DNS lookup responses, ICMP ping replies, and optional local subnet UDP peer status broadcasts.
- NO temporary exception entitlements are used.

EXTERNAL SERVICES & PRIVACY:
- The app contacts standard public DNS anycast servers (1.1.1.1, 8.8.8.8) solely to measure reachability and latency.
- Optional Claude diagnosis requires the user's personal Anthropic API key and explicit, versioned, revocable user consent.
- Zero analytics, zero telemetry, zero advertising, zero remote tracking.

A physical device walkthrough video is available at:
https://llms-explorer.com/net-dns-monitor/app-review-demo.mp4
```

---

## 3. Demo Screen Recording Guide

Apple requires a screen recording captured on a physical Mac showing the app launching and walking through the typical user flow.

### Required Recording Sequence (60 - 90 Seconds)

1. **Launch App (0:00 - 0:10):**
   - Double-click `Net-DNS-Monitor.app` in Finder / Applications.
   - Point cursor to menu bar showing status item `🟢 Net/DNS: healthy` and Dock icon displaying latency badge (e.g. `12ms`).
2. **Open Menu Bar Menu (0:10 - 0:25):**
   - Click status item. Show top readout items (Active service, Preferred, Backup).
   - Show menu options: Open dashboard, Toggle mini window, Open last report, Test network alert, Credentials ▸, Allow Claude diagnosis…, Privacy Policy.
3. **Open Dashboard (0:25 - 0:45):**
   - Click "Open dashboard". Show the dashboard window.
   - Show interface table with green checkmarks, latency charts, and network service order.
   - Click "Run full diagnosis". Show the troubleshooting ladder steps executing and completing cleanly.
4. **Mini Window & Alert (0:45 - 0:55):**
   - From menu bar, click "Toggle mini window". Show floating HUD status card.
   - From menu bar, click "Test network alert". Show system notification banner appearing in top right corner.
5. **AI Consent Dialog (0:55 - 1:10):**
   - Click "Allow Claude diagnosis…".
   - Show modal dialog explicitly detailing the exact data payload (classification, check results, repair outcomes) and asking for user permission.
   - Click "Deny" or "Allow" to demonstrate user control.
6. **Privacy Policy (1:10 - 1:20):**
   - Click "Privacy Policy" from menu bar.
   - Show default browser opening `https://llms-explorer.com/net-dns-monitor/privacy/`.

### Video Recording & Encoding Command
To record and convert the video to App Store Connect compatible MP4:
```bash
# Record display (press Ctrl+C when finished):
screencapture -v demo_raw.mov

# Transcode to optimized web/H.264 MP4:
ffmpeg -i demo_raw.mov -c:v libx264 -profile:v high -pix_fmt yuv420p -crf 22 -preset fast -c:a aac -b:a 128k app-review-demo.mp4
```
Host `app-review-demo.mp4` at `https://llms-explorer.com/net-dns-monitor/app-review-demo.mp4` or attach directly to App Store Connect Resolution Center.
