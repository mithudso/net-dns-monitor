# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
**Report a vulnerability** button on this repository's Security tab to send a
private advisory. If that is unavailable, email the maintainer at the address
on their GitHub profile.

Include the affected file or feature, how to reproduce it, and the impact you
expect. Expect an acknowledgement within a week.

## Scope

The app runs parts of its work with elevated privileges and handles
credentials. The areas most worth reviewing are listed in
[docs/SECURITY.md](../docs/SECURITY.md):

- the sudoers grant (`privileges.py`);
- the router's administrator scripts (`router.py`, `router/scripts/`);
- the arbitrary-shell console (`console.py`);
- the unauthenticated LAN peer protocol (`peer_net.py`);
- the outbound redaction of reports sent to an LLM, Slack or email.
