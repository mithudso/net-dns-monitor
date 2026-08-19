import os
import plistlib
import subprocess
import logging

log = logging.getLogger(__name__)

class Router:
    def __init__(self, wan_if, lan_if, lan_ip, lan_netmask, dhcp_start, dhcp_end):
        self.wan_if = wan_if
        self.lan_if = lan_if
        self.lan_ip = lan_ip
        self.lan_netmask = lan_netmask
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end

    def start(self):
        log.info(f"Starting router/DHCP: WAN={self.wan_if}, LAN={self.lan_if}")
        
        subnet = ".".join(self.lan_ip.split(".")[:3]) + ".0"
        plist_data = {
            "Subnets": [{
                "allocate": True,
                "lease_max": 86400,
                "lease_min": 86400,
                "name": "LAN",
                "net_address": subnet,
                "net_mask": self.lan_netmask,
                "net_range": [self.dhcp_start, self.dhcp_end],
                "routers": [self.lan_ip],
                "dhcp_domain_name_server": ["8.8.8.8", "1.1.1.1"]
            }],
            "bootp_enabled": False,
            "dhcp_enabled": [self.lan_if]
        }
        with open("/tmp/bootpd.plist", "wb") as f:
            plistlib.dump(plist_data, f)
            
        pf_rule = f"nat on {self.wan_if} from {self.lan_if}:network to any -> ({self.wan_if})\\n"
        with open("/tmp/pf_nat.conf", "w") as f:
            f.write(pf_rule)
            
        script = f"""#!/bin/sh
ifconfig {self.lan_if} {self.lan_ip} netmask {self.lan_netmask}
sysctl -w net.inet.ip.forwarding=1
pfctl -f /tmp/pf_nat.conf -e
mv /tmp/bootpd.plist /etc/bootpd.plist
/bin/launchctl unload -w /System/Library/LaunchDaemons/bootps.plist || true
/bin/launchctl load -w /System/Library/LaunchDaemons/bootps.plist
"""
        self._run_admin(script)

    def stop(self):
        log.info("Stopping router/DHCP")
        script = """#!/bin/sh
pfctl -F all -d
sysctl -w net.inet.ip.forwarding=0
/bin/launchctl unload -w /System/Library/LaunchDaemons/bootps.plist || true
"""
        self._run_admin(script)
        
    def _run_admin(self, script):
        with open("/tmp/router.sh", "w") as f:
            f.write(script)
        subprocess.run(["osascript", "-e", 'do shell script "/bin/sh /tmp/router.sh" with administrator privileges'], check=False)
