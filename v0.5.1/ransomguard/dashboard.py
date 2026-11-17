"""Proposed dashboard transport contract; adapt to the existing backend before use.

Only explicit CLI 'send-events' calls contact a server. A successful HTTP response
alone is not an ACK: the server must list the event_ids durably accepted.
"""

from __future__ import annotations

import json
import math
import os
from numbers import Real
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from .outbox import Outbox


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Dashboard redirects require explicit endpoint review")


def send_batch(outbox: Outbox, endpoint: str, *, token_env: str = "RANSOMGUARD_DASHBOARD_TOKEN",
               timeout: float = 10.0, limit: int = 100) -> int:
    try:
        parsed = urlsplit(endpoint)
        valid_endpoint = (
            parsed.scheme == "https" and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and not parsed.fragment and "*" not in parsed.hostname
            and not any(c.isspace() or ord(c) < 32 for c in endpoint)
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except (TypeError, ValueError, AttributeError):
        valid_endpoint = False
    if not valid_endpoint:
        raise ValueError("Dashboard endpoint must be unambiguous HTTPS without credentials, wildcards, or fragments")
    if isinstance(timeout, bool) or not isinstance(timeout, Real) or not 0 < timeout <= 60 or not math.isfinite(timeout):
        raise ValueError("Timeout outside supported range")
    token = os.environ.get(token_env, "").strip()
    if not token or not token.isascii() or not token.isprintable() or any(c.isspace() for c in token):
        raise ValueError("Dashboard token is missing or invalid")
    batch = outbox.pending(limit)
    if not batch:
        return 0
    body = json.dumps({"schema_version": 1, "events": batch}, ensure_ascii=False, allow_nan=False).encode("utf-8")
    request = Request(endpoint, data=body, method="POST",
                      headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    with build_opener(_NoRedirect).open(request, timeout=timeout) as response:
        # Prevent a faulty endpoint from returning unbounded output.
        data = response.read(1_048_577)
        if len(data) > 1_048_576:
            raise ValueError("Dashboard response exceeded 1 MiB")
    parsed_response = json.loads(data)
    acknowledged = parsed_response.get("acknowledged_event_ids") if isinstance(parsed_response, dict) else None
    if not isinstance(acknowledged, list) or any(not isinstance(x, str) for x in acknowledged):
        raise ValueError("Dashboard response does not match the documented ACK contract")
    outbox.acknowledge(acknowledged, sent_ids=[x["event_id"] for x in batch])
    return len(acknowledged)
