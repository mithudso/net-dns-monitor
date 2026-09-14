"""What this build of the app is allowed to do, decided once at startup.

The Mac App Store build runs inside the App Sandbox, and several features of
the direct-download build cannot work there. Not "work worse" -- cannot work:

* The sandbox forbids configuring network settings, so the failover switch
  (`networksetup -ordernetworkservices`) would be refused by the system.
* App Review Guideline 2.4.5(v) forbids asking for root, which rules out the
  sudoers grant and everything it enables: the mDNSResponder restart and the
  DHCP renewal.
* A sandboxed process cannot read the system-wide unified log. `log show`
  inherits the sandbox and returns nothing useful, and an empty evidence list
  reads exactly like "no errors were logged".
* The router stack installs root LaunchDaemons, writes /etc and rewrites pf.
* The arbitrary-shell console runs whatever is typed. Inside the sandbox every
  command inherits the container's restrictions, so diagnostics fail in ways
  that look like network faults, and executing arbitrary code is a Guideline
  2.5.2 question for App Review.
* Writing a plist into ~/Library/LaunchAgents is outside the container.

Each of these is switched off AND reported as unavailable rather than left to
fail, because a failure that looks like a network fault is exactly the
confident wrong diagnosis this app exists to prevent. Callers turn a missing
capability into `unavailable(...)` text, never into "ok" and never into a
silent no-op.

Detection reads the environment only, so it is a pure function of its input
and testable offline. The sandbox sets APP_SANDBOX_CONTAINER_ID for every
sandboxed process. NETDNS_DISTRIBUTION=appstore forces the App Store behaviour
outside the sandbox, which is how the gated paths get exercised during
development without building and signing a bundle.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

SANDBOX_ENV = "APP_SANDBOX_CONTAINER_ID"
OVERRIDE_ENV = "NETDNS_DISTRIBUTION"

APP_STORE = "appstore"
DIRECT = "direct"

UNAVAILABLE_PREFIX = "UNAVAILABLE_IN_APP_STORE_BUILD"

# One sentence per feature, phrased as the reason rather than an apology, so the
# report tells IT what was not attempted and why.
REASONS = {
    "shell_console": "the App Sandbox confines every command it would run, and App Review does not "
    "permit executing arbitrary code",
    "privileged_repairs": "Mac App Store apps may not request root privileges (Guideline 2.4.5(v))",
    "network_order_write": "the App Sandbox does not allow an app to change network settings",
    "unified_log": "the App Sandbox does not allow reading the system-wide unified log",
    "router": "the router installs system daemons and firewall rules, which Mac App Store apps "
    "may not do (Guideline 2.4.5)",
    "launch_agent_login_item": "writing a LaunchAgent is outside the app's container; use the "
    "system Login Items setting instead",
}


@dataclass(frozen=True)
class Capabilities:
    distribution: str
    sandboxed: bool
    shell_console: bool
    privileged_repairs: bool
    network_order_write: bool
    unified_log: bool
    router: bool
    launch_agent_login_item: bool
    # A sandboxed app launched by LaunchServices sees no shell environment, so
    # credentials have to come from the Keychain as well.
    credentials_from_keychain: bool
    # Guideline 5.1.2(i): explicit permission before data goes to a third-party
    # AI. The direct build keeps its existing opt-in (setting the API key).
    requires_ai_consent: bool

    @property
    def is_app_store(self) -> bool:
        return self.distribution == APP_STORE


def detect(env: Optional[Mapping[str, str]] = None) -> Capabilities:
    env = os.environ if env is None else env
    sandboxed = bool(env.get(SANDBOX_ENV))
    forced = str(env.get(OVERRIDE_ENV, "")).strip().lower()
    if forced not in ("", APP_STORE, DIRECT):
        # An unrecognised value must not silently re-enable root-requiring
        # features, and must not silently disable them on a direct build either.
        # Falling back to what the process actually is keeps both honest.
        forced = ""
    app_store = sandboxed or forced == APP_STORE
    # The override cannot turn a sandboxed process back into the direct build:
    # the sandbox would refuse the calls whatever this module said.
    full = not app_store
    return Capabilities(
        distribution=APP_STORE if app_store else DIRECT,
        sandboxed=sandboxed,
        shell_console=full,
        privileged_repairs=full,
        network_order_write=full,
        unified_log=full,
        router=full,
        launch_agent_login_item=full,
        credentials_from_keychain=True,
        requires_ai_consent=app_store,
    )


def unavailable(feature: str, detail: Optional[str] = None) -> str:
    """The outcome text for a step this build does not attempt.

    Starts with a fixed prefix so reports, the CLI and tests can tell "not
    attempted in this build" apart from "attempted and failed" without parsing
    prose. Says nothing was changed, because nothing was.
    """
    reason = REASONS.get(feature, "this build does not include it")
    what = detail or feature.replace("_", " ")
    return (
        f"{UNAVAILABLE_PREFIX}: {what} is not available in the Mac App Store build, because "
        f"{reason}. Nothing was changed."
    )


def is_unavailable(outcome: object) -> bool:
    return isinstance(outcome, str) and outcome.startswith(UNAVAILABLE_PREFIX)
