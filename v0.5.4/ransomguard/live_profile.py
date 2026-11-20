"""Explicit, finite lab authorization for unattended startup; absent means passive."""
import json
from pathlib import Path
import re


def observer_options(path, *, state_db):
    path = Path(path)
    if not path.exists():
        return [], 'observe-only'
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    internal=value.get('authorized_internal_test') is True and value.get('acknowledged_pc_wide_containment') is True
    if value.get('schema_version') != 1 or not (value.get('authorized_isolated_lab') is True or internal):
        raise ValueError('Live startup requires explicit test authorization and PC-wide containment acknowledgement')
    tracks = value.get('tracks')
    if tracks not in (['A'], ['B'], ['A', 'B']):
        raise ValueError('Live profile must select A and/or B explicitly')
    prefix = value.get('nt_path_prefix', '')
    if (not isinstance(prefix,str) or not re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+\\[^*?]+',prefix,re.IGNORECASE)
            or any(x in ('','.','..') for x in prefix.strip('\\').split('\\'))):
        raise ValueError('Live profile requires a finite NT directory scope')
    paths = []
    for field in ('config', 'manifest'):
        target = Path(value.get(field,''))
        if not target.is_absolute() or not target.is_file():
            raise ValueError('Live profile requires existing absolute config and manifest paths')
        paths.append(str(target))
    from .response_commands import profile_from_config, thresholds_from_config
    config=json.loads(Path(paths[0]).read_text(encoding='utf-8-sig'))
    profile=profile_from_config(config);thresholds_from_config(config)
    from .firewall_control import FirewallProfile
    approved = value.get('approved_extra_https_targets', [])
    if not isinstance(approved, list):
        raise ValueError('Approved HTTPS targets must be an explicit list')
    approved_profile = FirewallProfile('https://api.typesafe.ai', tuple(approved))
    if (profile.jev_url != approved_profile.jev_url
            or profile.extra_https_targets != approved_profile.extra_https_targets):
        raise ValueError('Network exceptions must match the explicitly approved startup profile')
    manifest=json.loads(Path(paths[1]).read_text(encoding='utf-8-sig'))
    if manifest.get('schema_version')!=1 or not isinstance(manifest.get('manifest'),list) or not 1<=len(manifest['manifest'])<=5000:
        raise ValueError('An approved finite recovery manifest is required')
    options=['--async-response','--authorize-live','--confirm-internal-test' if internal else '--confirm-isolated-vm','--config',paths[0],
             '--response-state-db',str(state_db),'--response-path-prefix',prefix,
             '--response-manifest-template',paths[1]]
    options += ['--live-track-'+track.lower() for track in tracks]
    return options, 'scoped-live-track-'+'-'.join(x.lower() for x in tracks)
