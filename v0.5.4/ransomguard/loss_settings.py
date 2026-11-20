"""User-requested loss display epoch; preserve lifetime evidence and intake."""
import argparse
import json
from pathlib import Path
import time
import uuid

from .counter_history import atomic_json
from .scope_settings import scope_lock
from .resident import request_reload


def reset(runtime):
    base = Path(runtime)
    ready = base / 'observer-ready.json'
    with scope_lock(base):
        before = json.loads(ready.read_text(encoding='utf-8'))
        if before.get('worker_state') != 'running' or time.time()-before.get('observed_at', 0) > 20:
            raise RuntimeError('수집기 연결을 확인한 후 다시 시도해 주세요.')
        baseline = before.get('counter_totals', {}).get('events_dropped')
        if type(baseline) is not int or baseline < 0:
            raise ValueError('유실 누적값을 확인하지 못했습니다.')
        stamp = time.time()
        record = {'events_dropped_baseline': baseline, 'at': stamp,
                  'reason': 'user_requested_display_counter_reset', 'lifetime_history_preserved': True}
        archive = base / 'counter-resets' / uuid.uuid4().hex
        archive.mkdir(parents=True)
        atomic_json(archive / 'reset.json', record)
        atomic_json(archive / 'before-health.json', before)
        atomic_json(base / 'observer-ready.counters.loss-reset.json', record)
        req = request_reload(ready, Path(__file__).resolve().parent)
        until = time.monotonic()+45
        while time.monotonic() < until:
            current = json.loads(ready.read_text(encoding='utf-8'))
            total = current.get('counter_totals', {}).get('events_dropped')
            if (current.get('reload_request_id') == req['id'] and
                    current.get('worker_state') == 'running' and type(total) is int):
                return {'baseline': baseline, 'sinceReset': max(0, total-baseline), 'resetAt': stamp}
            time.sleep(.2)
        raise RuntimeError('초기화 요청은 저장됐지만 수집기 적용 확인이 지연됩니다. 상태를 확인해 주세요.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True)
    parser.add_argument('action', choices=['loss-reset'])
    args = parser.parse_args()
    try:
        print(json.dumps(reset(args.runtime), ensure_ascii=True))
    except Exception as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=True))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
