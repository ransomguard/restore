"""Validate a suspicious-process isolation plan without changing the network.

No Windows Firewall/WFP mutation is implemented in this baseline. A returned
plan is never evidence of applied containment. DNS resolution is explicit.
"""

from __future__ import annotations

import ipaddress
import ntpath
import socket
from typing import Any
from urllib.parse import urlsplit


def make_plan(config: dict[str, Any], *, resolve: bool = False) -> dict[str, Any]:
    if config.get("scope", "process") != "process":
        raise ValueError("This project's selected policy is suspicious-process isolation")
    executable = config.get("agent_executable", "")
    readiness = ["Per-process WFP enforcement backend is not implemented in this baseline",
                 "PID plus process creation time must be validated before any live action",
                 "File containment and Windows VM validation are still required"]
    if not executable:
        readiness.append("A dedicated installed agent executable identity must be configured")
    elif not ntpath.isabs(executable) or ntpath.basename(executable).lower() in ("python.exe", "pythonw.exe"):
        raise ValueError("Use a dedicated absolute service executable, not a shared Python interpreter identity")
    endpoints = []
    for role in ("jev", "dashboard"):
        url = config.get(role + "_url", "")
        if not url:
            readiness.append(f"{role} endpoint is not configured")
            continue
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError(f"{role} must be an HTTPS URL without credentials or fragments")
        if "*" in parsed.hostname:
            raise ValueError("Wildcard destinations are not permitted")
        port = parsed.port if parsed.port is not None else 443
        if not 1 <= port <= 65535:
            raise ValueError(f"{role} endpoint port must be between 1 and 65535")
        addresses = []
        if resolve:
            addresses = sorted({str(ipaddress.ip_address(item[4][0]))
                                for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)})
        endpoints.append({"role": role, "hostname": parsed.hostname, "port": port, "protocol": "tcp",
                          "resolved_addresses": addresses, "application": executable or None,
                          "tls_hostname_verification_required": True})
    resolvers = [str(ipaddress.ip_address(value)) for value in config.get("dns_resolvers", [])]
    return {"scope": "process", "plan_only": True, "network_changed": False,
            "live_enforcement_ready": False, "requirements_remaining": readiness,
            "process_identity_fields": ["pid", "process_create_time"],
            "target_process_policy": "block all network destinations for the selected process instance",
            "unrelated_process_policy": "unchanged",
            "control_plane_endpoints": endpoints, "dns_resolvers": resolvers,
            "control_plane_policy": "JEV and dashboard are contacted by a separate service; no host-wide allow rules are installed",
            "existing_flows": "must be reauthorized and verified in IPv4 and IPv6",
            "release_policy": "remove only incident-owned holds for that exact process instance after verified decision/response",
            "address_lifetime": "resolution is a snapshot, not a permanent IP allowlist"}
