"""Prepare a fresh VM runtime from explicitly selected builds; never starts them."""
import argparse
import json
from pathlib import Path
import shutil

TEMPLATES = Path(__file__).resolve().parents[1] / 'integration' / 'windows'
FILES = ('installation_paths.py', 'Start-RansomGuard.py', 'Start-RansomGuard.ps1',
         'Start-RansomGuard.cmd', 'Start-RansomGuardAtLogon.ps1',
         'Watch-RansomGuard.py', 'Watch-RansomGuard.ps1',
         'Install-RansomGuardSupervisor.ps1')


def configure(recovery_root, runtime, python, ui, firewall, *, check=False):
    root, base, py, dash, daemon = [Path(p).resolve() for p in
                                  (recovery_root, runtime, python, ui, firewall)]
    for file in (root/'ransomguard'/'__main__.py', root/'config'/'example.json', py, dash, daemon):
        if not file.is_file():
            raise ValueError(f'Required file missing: {file}')
    if py.name.lower() != 'python.exe' or dash.name.lower() != 'ransom0-ui.exe' or daemon.name.lower() != 'r0-fw-daemon.exe':
        raise ValueError('Use the Windows python.exe, ransom0-ui.exe and r0-fw-daemon.exe builds')
    # Runtime contains evidence and ownership state: never silently point an
    # existing installation at different executables or a new database directory.
    config = dict(schema=1, recovery_root=str(root), python=str(py), ui=str(dash),
                  firewall=str(daemon), evidence_mode='test')
    target = base/'installation.json'
    if base.exists():
        if not target.is_file() and any(base.iterdir()):
            raise ValueError('Use an empty runtime directory; existing evidence must not be overwritten')
        if target.is_file() and json.loads(target.read_text(encoding='utf8')) != config:
            raise ValueError('Existing installation differs; use the documented controlled upgrade procedure')
        for name in FILES:
            dest = base/name
            if dest.exists() and dest.read_bytes() != (TEMPLATES/name).read_bytes():
                raise ValueError(f'Existing launcher differs; controlled upgrade required: {name}')
    if not check:
        base.mkdir(parents=True, exist_ok=True)
        for name in FILES:
            shutil.copyfile(TEMPLATES/name, base/name)
        target.write_text(json.dumps(config, indent=2)+'\n', encoding='utf8')
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recovery-root', type=Path, default=TEMPLATES.parents[1])
    for name in ('runtime', 'python', 'ui', 'firewall'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='validate only; do not create files')
    args = parser.parse_args()
    configure(args.recovery_root, args.runtime, args.python, args.ui, args.firewall, check=args.check)
    print('Paths validated.' if args.check else 'Runtime prepared. No programs, drivers or tasks started. Default: observe-only, test evidence.')


if __name__ == '__main__':
    main()
