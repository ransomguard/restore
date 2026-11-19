"""Explicit installation paths shared by the launcher and passive supervisor."""
import json
from pathlib import Path


def load_paths(script):
    base = Path(script).resolve().parent
    try:
        value = json.loads((base/'installation.json').read_text(encoding='utf8'))
    except FileNotFoundError as error:
        raise RuntimeError('Run deployment/configure.py first; no developer VM paths are assumed') from error
    if value.get('schema') != 1 or value.get('evidence_mode') != 'test':
        raise ValueError('Unsupported installation configuration; release defaults to test evidence')
    paths = {key: Path(value[key]) for key in ('recovery_root', 'python', 'ui', 'firewall')}
    for key, path in paths.items():
        if not path.is_absolute() or not (path.is_dir() if key == 'recovery_root' else path.is_file()):
            raise ValueError(f'Invalid or missing installation path: {key}')
    return base, paths
