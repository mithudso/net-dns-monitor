# Prompt Log

Versioned record of every user request, in order.

## v1 - 2026-09-01 - Router NAT reboot recovery

Delta: 1

Prompt:

> I have a custom router setup by another process when I rebooted it stopped look in the scripts folder and get it working again. My other systems can't get to the internet

## v2 - 2026-09-14 - Deep code optimizer, repo bootstrapper, App Store preparation

Delta: 1

Prompt:

> Run the deep code optimizer on this repo and the repo bootstrapper, and then prepare the repo for becoming an appstore app and give me all of the information necessary to submit it to the store.

## v3 - 2026-09-14 - Answers to the open questions

Delta: 1

Prompt:

> 1. yes. 2. yes 3. both 4. conservative 5. I don't export anything. 6. gateway fallback 7. yes inspect.

## v4 - 2026-09-17 - App Store readiness and submission documentation

Delta: 1

Prompt:

> Get this repo ready for submitssion to the apple store and document everything necessary to submit

## v5 - 2026-10-04 - macOS networking expertise

Delta: 1

Prompt:

> become an expert in macos networking

## v6 - 2026-10-04 - Reconcile and publish pending work

Delta: 1

Prompt:

> merge commit push pr

## v7 - 2026-10-04 - Networking review, code optimizer and repo bootstrapper

Delta: 1

Prompt:

> Do a code review of this repo and identify if there are any areas that thew new facts and research you just did would impact it. Then run the deep code optimizer on it and the repo-bootstrapper.

## v8 - 2026-10-04 - Repo bootstrapper convergence pass

Delta: 1

Prompt:

> Run the repo-boostrapper skill on this repo.

## v9 - 2026-10-04 - MCP self-test and Dependabot PR #28

Delta: 1

Prompt:

> 1.Close it. 2. Add flag.

> ALso resolve all the conflicts for the https://github.com/mithudso/net-dns-monitor/pull/28 merge and

> 1. Yes do both.

## v10 - 2026-10-05 - Code deep optimizer, second run

Delta: 1

Prompt:

> run the code deep optimizer again

> I keep getting these notifications even though my network is fine: (screenshot: "Net-DNS-Monitor: network failed -- Ping to 2001:4860:4860::8888 / 8.8.8.8 / 1.1.1.1 failed -- no reply from 8.8.8.8")

## v11 - 2026-10-05 - Owner decisions on the optimizer's open questions

Delta: 1

Prompt:

> 1. I don't understand. 2. Yes. 3. It should exit with a partial status code. 4. Yes, the dhcp service should not be on by default my network issues are more resolved nowm dhcp server should be opt in. 5. (screenshot of the Settings status label: "Saved. These need a restart to take effect (62): control_domain, domain_learn_interval_seconds, domains" clipped) 6. leave it.

## v12 - 2026-10-05 - Connection refused counts as reachable

Delta: 1

Prompt:

> 1. Yes, because it received a response. 2. I ran the sudo command.

## v13 - 2026-10-17 - Apple rejection audit (TASK-417)

Delta: 1

Prompt:

> Run your full workflow on /Users/mitch/dev/net-dns-monitor (branch master). Stele task TASK-417 (project_slug net-dns-monitor-cdgnu) is already created and CLAIMED by the parent session: do not create or claim another; complete it with a detailed summary at the end and link knowledge you write to it.
>
> User's authorization (verbatim from the session): the owner asked to "create an agent whose job it is to find all the ways that apple could or would reject this app, and fix them", then answered "Yes to all three" to: run the audit now, apply corrections to older reference files (done and pushed already), and commit/push the skills and agents repos (done). Fixing repo-owned findings and committing to master is authorized. Pushing net-dns-monitor's master to origin is authorized by the owner's standing rule for personal repos (commit straight to the canonical branch and push, never force-push). Uploading, submitting, replying to Apple, altool/Transporter, and App Store Connect actions are NOT authorized.
>
> Before any edit: append the exact user request above to prompts.md and record task, constraints, plan in memory.md per CLAUDE.md "Workflow records" (next vN section, increment Delta). Git status at session start was clean on master; HEAD abc9cd2. Preserve any unrelated changes that appear.
>
> Known inputs: catalog /Users/mitch/.claude/skills/apple-platform-publishing/references/apple-reviewer-model-and-rejection-catalog.md; dossiers rabbithole-2026-10-17-*.md in that directory. Priority suspects from the catalog for this repo: (1) Guideline 2.5.19 dormant/undocumented features in the store bundle (router, shell console, privileged repairs, sudoers writer, osascript, failover, SMTP/Slack) vs Notes in docs/APP_STORE_REVIEW_RESPONSE.md; (2) `itms-services` literal in bundled stdlib; (3) network.server entitlement justification; (4) 5.1.2(i) consent text, App Privacy label and docs/PRIVACY_POLICY.md vs actual outbound flows; (5) IPv4-literal probes on an IPv6-only NAT64 review network (2.5.5); (6) deprecated NSUserNotificationCenter via rumps (2.5.1); (7) 2.4.5(iii) login item default and consent; (8) donation/funding links reachable from reviewed pages (3.1.1); (9) Notes/description/label vs binary feature diff; (10) PrivacyInfo.xcprivacy validity.
>
> Do not launch the GUI. Do not paste anything into App Store Connect. Return the ledger summary, commits made, CI gate exit codes, and the owner-only UNVERIFIED actions with exact commands.

## v14 - 2026-10-17 - Editable remediation scripts and in-app IDE (TASK-418)

Delta: 1

Prompt:

> make the auto remediation scripts editable and scriptable in Python. Make the current auto remediation logic uh, into Python scripts that you can edit from the GUI via a small Python IDE. Period. Allow for custom auto remediation scripts the ability to edit current ones. And make sure that the scripts are fully documented.

## v15 - 2026-10-17 - Liquid Glass UI, dropdowns, tooltips, full settings (TASK-422)

Delta: 1

Prompt:

> Save those steps so that I can look at them later. And then update the user interface to be more modern and utilize the new Mac liquid glass features. Period. Hide the redundant buttons or similarly categorized buttons behind dropdowns. And make sure every button and tool and setting has a tooltip. And make sure every configurable option is represented in the settings. Period.
