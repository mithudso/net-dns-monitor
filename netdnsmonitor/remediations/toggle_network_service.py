"""toggle_network_service -- never automated, and says so.

Taking an interface down and back up cannot be one command. Doing it as two risks
leaving the machine offline, with no network to fix it over, if anything
interrupts the second. So this step runs nothing and returns `NOT_AUTOMATED:`.

It is its own outcome rather than NEEDS_PRIVILEGE so that granting permissions
does not leave someone waiting for a step that will never run.

If you replace this with real logic, you take on that risk: make the second half
(bringing the service back up) run even when the first half's command fails, and
return `partial:` or `unknown:` rather than `ok:` unless you read the state back.
"""

NAME = "toggle_network_service"
KIND = "repair"
NEEDS_PRIVILEGE = True
REASON = (
    "Re-initialising the interface clears driver and association "
    "state that renewing a lease cannot."
)
CLASSIFICATIONS = ("network",)
ORDER = 40
ENABLED = True


def run(ctx):
    return (
        "NOT_AUTOMATED: taking an interface down and back up cannot be done as "
        "one command, and doing it as two risks leaving this machine offline "
        "with no network to fix it over if anything interrupts the second one. "
        "Toggle Wi-Fi or the cable by hand if the other steps have not helped."
    )
