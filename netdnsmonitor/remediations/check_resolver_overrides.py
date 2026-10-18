"""check_resolver_overrides -- are there /etc/resolver files redirecting domains?

Lists the files in `/etc/resolver`. Each file there silently sends one domain to
a different DNS server. It reads only.

Outcomes:
  * `no /etc/resolver overrides configured` when the directory is absent or empty;
  * `/etc/resolver overrides present for: a, b` naming the files;
  * `failed: could not read /etc/resolver (...)` when listing it raised, so a
    permissions problem is never reported as "no overrides".

The directory lookups are `ctx.resolver_dir_exists` and `ctx.listdir` so a test
can supply a fake filesystem.
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
    if not ctx.resolver_dir_exists(directory):
        return f"no {directory} overrides configured"
    try:
        entries = ctx.listdir(directory)
    except OSError as exc:
        # os.listdir can raise PermissionError, or FileNotFoundError if the
        # directory vanished after the check above.
        return f"failed: could not read {directory} ({exc})"
    if not entries:
        return f"no {directory} overrides configured"
    return f"{directory} overrides present for: {', '.join(entries)}"
