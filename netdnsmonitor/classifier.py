"""Classify a connectivity incident as network-layer, DNS-layer, healthy, or
unclassified, based on whether raw external reachability and DNS resolution
succeeded.

The split matters because it points the troubleshooting ladder at a cause:
reachable-but-can't-resolve-names means DNS is broken with the network fine;
can't-reach-anything means the network itself is down.
"""

from enum import Enum
from typing import Optional


class Classification(Enum):
    HEALTHY = "healthy"
    NETWORK = "network"
    DNS = "dns"
    UNCLASSIFIED = "unclassified"


def classify(
    external_reachable: Optional[bool], dns_ok: Optional[bool]
) -> Classification:
    if external_reachable is None or dns_ok is None:
        return Classification.UNCLASSIFIED
    if not external_reachable:
        return Classification.NETWORK
    if not dns_ok:
        return Classification.DNS
    return Classification.HEALTHY
