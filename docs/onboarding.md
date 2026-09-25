# Onboarding

A first day on this codebase, in order.

1. **Read [CLAUDE.md](../CLAUDE.md).** The ten non-negotiables are the design,
   not style advice. Most past bugs broke one of them.
2. **Set up and run the suite** ([DEVELOPMENT.md](DEVELOPMENT.md)). It runs
   offline in under 30 seconds.
3. **Read [ARCHITECTURE.md](ARCHITECTURE.md).** Follow one incident from
   `app.tick` through `state_machine`, `classifier`, `flap_gate`, `ladder`
   and `repair_executor` to `report` and `notifications`.
4. **Run the one-shot entry points in [SCRIPTS.md](SCRIPTS.md)** against your
   own machine. Real OS behaviour differs from the fakes: hostnames are masked
   in the unified log, and binding to a source address does not pin an
   interface.
5. **Skim [known-issues.md](known-issues.md)** before fixing anything, so you
   do not re-fix an accepted limitation.
6. **If you are working on the store build**, read
   [APP_STORE_SUBMISSION.md](APP_STORE_SUBMISSION.md) §1 and
   `netdnsmonitor/distribution.py`.

Good first tasks: anything under "Blocked on a decision" in known-issues.md
once the owner has decided, or a test gap named there.
