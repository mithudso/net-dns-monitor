# Testing

[Testing](../TESTING.md) defines the pinned Ruff and pytest checks, the macOS/AppKit requirement, synthetic side-effect injection and the current test census. [The script inventory](../SCRIPTS.md) maps test modules and supported commands.

Passing synthetic tests proves the exercised logic. It does not prove live network repair, Keychain authorization, notification delivery, signing, App Store approval or an installed bundle. Read [known issues](../known-issues.md) for dated evidence and unresolved operating constraints.

Local safety guards and held host-only cases are reported explicitly in the dated maintenance report. The final CI evidence must identify its commit and distinguish full fresh-runner tests from a guarded local subset.
