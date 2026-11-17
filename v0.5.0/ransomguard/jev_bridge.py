"""Bounded stdin/stdout adapter for the fixed-endpoint Windows JEV transport."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace


def evaluate_bridge(path: str, *, state_json: str, model: str, timeout: float):
    # Imported lazily to avoid a cycle and preserve the existing SDK-only path.
    from .jev import JevConfigurationError, JevTransportError, parse_verdict

    executable = Path(path)
    if os.name != 'nt' or not executable.is_absolute() or not executable.is_file():
        raise JevConfigurationError('An existing absolute Windows JEV bridge path is required')
    request = json.dumps({'state': json.loads(state_json), 'model': model,
                          'timeout_seconds': min(timeout, 60)}, ensure_ascii=False, allow_nan=False)
    try:
        result = subprocess.run([str(executable), '--evaluate'], input=request.encode('utf8'),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=min(timeout, 60) + 5, close_fds=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0 or len(result.stdout) > 65536:
            raise JevTransportError('JEV bridge request failed; no verdict is available')
        value = json.loads(result.stdout.decode('utf-8-sig'))
        response = SimpleNamespace(
            answers={'is_ransomware': SimpleNamespace(type='noul', noul=value['score'])},
            model=value['model'], request_id=value['request_id'])
    except JevTransportError:
        raise
    except Exception:
        raise JevTransportError('JEV bridge request failed; no verdict is available') from None
    return parse_verdict(response)
