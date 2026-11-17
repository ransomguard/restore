"""Read-only plan for the team-approved WHOLE-PC firewall-manager policy.

This is never an enforcement operation. The actual backend is the independent
Ransom0_Firewall named-pipe daemon, controlled by firewall_control.py.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

from .firewall_control import FirewallProfile


def make_plan(config: dict[str, Any], *, resolve: bool = False) -> dict[str, Any]:
    if not isinstance(config, dict) or config.get("scope") != "host_outbound":
        raise ValueError("Current team-approved network scope is host_outbound")
    extras = config.get("extra_https_targets", [])
    if not isinstance(extras, list) or any(not isinstance(x, str) for x in extras):
        raise ValueError("extra_https_targets must be an array of approved HTTPS URLs")
    profile = FirewallProfile(config.get("jev_url"), tuple(extras))
    endpoints = []
    for i, url in enumerate(profile.allowlist):
        parsed = urlsplit(url)
        port = parsed.port or 443
        addresses = []
        if resolve:
            addresses = sorted({str(ipaddress.ip_address(item[4][0]))
                                for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)})
        endpoints.append({"role": "jev" if i == 0 else "approved_extra", "url": url,
                          "hostname": parsed.hostname, "port": port, "protocol": "tcp",
                          "resolved_addresses": addresses})
    return {"scope": "host_outbound", "plan_only": True, "network_changed": False,
            "live_enforcement_ready": False,
            "daemon": r"\\.\pipe\Ransom0_Firewall", "daemon_action_to_enable": "on",
            "daemon_action_to_release_last_hold": "off",
            "allowlist": profile.allowlist,
            "control_plane_endpoints": endpoints,
            "host_policy": "block new outbound connections except configured destinations",
            "unrelated_process_policy": "subject_to_same_host_outbound_rules",
            "network_hold_policy": "durable incident reference counts; off only after last verified release",
            "known_limitations_deferred": ["not_inbound_or_existing_sessions",
                                           "daemon_currently_permits_remote_dns_port_53",
                                           "allowlist_is_host_global_not_process_bound",
                                           "daemon_active_ack_not_wfp_enforcement_proof"],
            "requirements_remaining": ["Windows VM end-to-end WFP validation",
                                       "confirmed JEV HTTPS connection under policy",
                                       "host daemon lifecycle/abnormal exit reconciliation"],
            "address_lifetime": "hostname resolution is point-in-time; daemon supports explicit refresh"}
