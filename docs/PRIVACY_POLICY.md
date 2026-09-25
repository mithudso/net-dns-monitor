# Net-DNS-Monitor Privacy Policy

> **Draft for the Mac App Store listing.** Replace every `<PLACEHOLDER>` before
> publishing, host this page at a public URL, and enter that URL in App Store
> Connect (App Information → Privacy Policy URL). Guideline 5.1.1(i) also
> requires a link to it inside the app; the App Store build shows one in its
> menu. Have it reviewed by someone qualified if you sell in regions with
> specific privacy law obligations.

**Publisher:** `<PUBLISHER NAME>`
**Contact:** `<CONTACT EMAIL>`
**Effective date:** `<EFFECTIVE DATE>`

## Summary

Net-DNS-Monitor checks your Mac's network and DNS connectivity and helps you
work out what is wrong when it breaks. The publisher does not receive,
collect, sell or track any of your data. The app has no analytics, no
advertising and no account.

Data leaves your Mac only in the cases below. Some happen with the default
settings: the connectivity checks and the announcement to nearby copies of
the app. The rest happen only after you configure them.

## What stays on your Mac

The app stores these files in its own container on your Mac:

- Settings you choose.
- Incident reports, a forensic journal and connection history. They can
  contain IP addresses, network interface names, domain names and log text.
- The permission choice described under "Claude diagnosis".

Credentials you enter (an Anthropic API key, a Slack webhook URL, an SMTP
password) are stored in your macOS Keychain.

You can delete all of this at any time by deleting the app and its container,
or by removing items from Keychain Access. The forensic journal rotates at
50 MB and keeps one older copy.

## Connectivity checks

To test your connection, the app contacts the network addresses in its
settings. By default these are Cloudflare (1.1.1.1) and Google (8.8.8.8). It
also resolves `api.anthropic.com` as a DNS control check and resolves any
domains you add. These checks send ordinary connection attempts and DNS
queries. They carry no personal information beyond what any network
connection reveals, such as your public IP address.

## Claude diagnosis (optional, off until you allow it)

If you add an Anthropic API key and **explicitly allow it in the app**, an
incident that the built-in checks cannot resolve is sent to Claude, an AI
model run by Anthropic, for a diagnosis. Each such request contains:

- the incident classification, for example "dns" or "network";
- the connectivity check results, including the domain names that were checked;
- the outcome of each troubleshooting step.

Text you list under "sensitive strings" in Settings is replaced with
`[REDACTED]` before sending.

Nothing is sent while your network is healthy. Nothing is sent before you
grant permission. You can withdraw permission at any time from the app menu,
and withdrawal applies to the next incident. The request goes directly from
your Mac to Anthropic under your own API key. Anthropic's privacy policy
governs how Anthropic handles it: <https://www.anthropic.com/legal/privacy>.

## Slack and email alerts (optional, off unless you configure them)

If you enter a Slack webhook URL or email settings, the app sends a short
alert when an incident starts. The alert goes to the Slack workspace or email
recipients you chose. It contains the incident classification, start time,
duration, whether the connection was healthy on recheck, a one-line summary,
the outcome of any repair step, the Claude diagnosis if one was made, and the
file path of the local report. The report path includes your macOS account
name. Slack's or your email provider's privacy terms govern that delivery.

## Nearby copies of the app (on by default)

Peer discovery is on by default. The app announces itself on your local
network so other copies of Net-DNS-Monitor on the same network can compare
results. The announcement stays on your local network and is not sent to the
internet. It contains:

- this Mac's name;
- the app's status;
- whether this Mac can currently reach the internet and resolve DNS.

The app accepts these announcements only from addresses on the same local
subnet, and it does not authenticate them. To stop announcing, turn peer
discovery off in Settings and restart the app.

On macOS 15 and later, macOS asks for your permission before the app can reach
your local network. If you decline, the app cannot announce itself or check
whether your router is reachable, and those checks report failures.

## Children

The app is a network utility and is not directed at children.

## Changes

If what the app sends changes, this policy will be updated and the app will
ask for permission again before sending anything new to Anthropic.

## Contact

Questions about this policy: `<CONTACT EMAIL>`.
