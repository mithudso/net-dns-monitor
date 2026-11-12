# Architecture

The [architecture guide](../ARCHITECTURE.md) describes the incident pipeline, probes, anti-flap gate, failover and user interface. The [component map](../COMPONENTS.md) names maintained modules.

[Fleet reporting](../FLEET.md) adds an optional headless reporting role and a separate UDP receiver with per-machine signed events, acknowledgements and bounded retries. [Editable remediation](../REMEDIATION_SCRIPTS.md) supplies injected-context checks and repairs, with user overrides in the direct build. The App Store capability profile limits these operations.

The two historical router stacks are documented in [integration assumptions](../integrations-and-assumptions.md). Their presence in the source tree does not authorize installing or enabling them.
