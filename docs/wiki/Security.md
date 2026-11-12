# Security

Read the [security model](../SECURITY.md), [privacy policy](../PRIVACY_POLICY.md) and [vulnerability reporting policy](../../.github/SECURITY.md). Preserve unknown probe states, injected effects, outbound redaction and verified service-order changes.

[Fleet reporting](../FLEET.md) uses one symmetric signing key per machine. The server holds enrolled keys and must protect its key file. Signatures authenticate messages; they do not encrypt the payload. The older LAN peer protocol has different trust limits.

[Editable remediation scripts](../REMEDIATION_SCRIPTS.md) are code run with the user's authority. The direct build's local override directory is a trust boundary. The App Store build uses its documented restricted capabilities.

Optional local semantic tools are development utilities, not a public Chroma service. Keep existing indexes and models separate from static audits and consult [MCP](../MCP.md) for their current dependency risks and activation requirements.
