"""check_resolver_overrides -- are there /etc/resolver files redirecting domains?

Lists the files in `/etc/resolver`. Each file there silently sends one domain to
a different DNS server. It reads only.

Outcomes:
  * `no /etc/resolver overrides configured` when the directory is absent or empty;
  * `/etc/resolver overrides present for: a, b` naming the files;
  * `failed: could not read /etc/resolver (...)` when listing it raised, so a
    permissions problem is never reported as "no overrides".

The directory lookup uses `ctx.listdir` so a test can supply a fake filesystem.
It lists directly because a false existence check can also mean permission denied.
"""

NAME = "check_resolver_overrides"
KIND = "check"
NEEDS_PRIVILEGE = False
REASON = (
    "/etc/resolver entries silently redirect specific domains and "
    "routinely outlive the VPN or lab network that needed them."
)
CLASSIFICATIONS = ("dns",)
ORDER = 20
ENABLED = True


def run(ctx):
    directory = ctx.tools.RESOLVER_DIR
    try:
        entries = ctx.listdir(directory)
    except FileNotFoundError:
        return f"no {directory} overrides configured"
    except OSError as exc:
        return f"failed: could not read {directory} ({type(exc).__name__})"
    if not entries:
        return f"no {directory} overrides configured"
    return f"{directory} overrides present for: {', '.join(entries)}"
