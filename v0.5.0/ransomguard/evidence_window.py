"""Bounded, generation-scoped automatic collection of observed Track B facts.

Only kernel attempts are counted. No fabricated successful write, hash change,
malware verdict or complete coverage is implied by this collection window.
"""
import copy
import time


class EvidenceWindow:
    def __init__(self, prefix, *, seconds=2.0, max_pending=32, clock=time.monotonic):
        if not 0.1 <= seconds <= 10 or not 1 <= max_pending <= 128:
            raise ValueError('Invalid evidence window bounds')
        self.prefix = prefix.replace('/', '\\').rstrip('\\').casefold() + '\\'
        self.seconds, self.max_pending, self.clock = seconds, max_pending, clock
        self.pending = {}

    def begin(self, payload):
        key = (payload['pid'], payload['correlated_process_create_time'])
        if key in self.pending:
            return 'already_collecting'
        if len(self.pending) >= self.max_pending:
            return 'evidence_window_full'
        item = copy.deepcopy(payload)
        item['collection_window_seconds'] = self.seconds
        item['collection_source'] = 'automatic_kernel_observer'
        item['corroborating_kernel_events'] = []
        self.pending[key] = (self.clock() + self.seconds, item)
        return 'collecting'

    def observe(self, event, registry):
        if registry.loss_detected:
            return self.invalidate('sequence_or_driver_loss')
        invalid = []
        for key, (_, item) in list(self.pending.items()):
            pid, generation = key
            if registry.generation_for(pid) != generation:
                invalid.append(self.pending.pop(key)[1] | {'deferred_reason': 'process_generation_ended'})
                continue
            if (event.event_type == 3 and event.fields.get('parent_pid') == pid
                    and event.fields.get('creator_pid') == pid
                    and event.fields.get('matched_rule_id') in range(1001, 1009)
                    and event.filetime >= item['source_filetime']):
                if len(item['corroborating_kernel_events']) < 8:
                    item['corroborating_kernel_events'].append(event.to_dict())
            if event.pid != pid or event.event_type not in (4, 5):
                continue
            path = event.fields.get('path', '')
            if not isinstance(path, str) or not path.casefold().startswith(self.prefix):
                continue
            if registry.generation_for_event(event) != generation:
                continue
            counts = item['counts']
            counts['write_attempts' if event.event_type == 4 else 'rename_attempts'] += 1
            counts['high_entropy_writes'] += int(event.event_type == 4 and bool(event.fields.get('flags', 0) & 8))
            counts['retained_observations'] += 1
            item['counts_scope'] = 'initial_triage_window_plus_following_collection_window'
            item['last_source_sequence'] = event.sequence
            item['last_source_filetime'] = event.filetime
            paths = item['evidence']['sample_source_paths']
            if path not in paths and len(paths) < 32:
                paths.append(path[:1024])
        return invalid

    def due(self):
        now = self.clock()
        keys = [key for key, (deadline, _) in self.pending.items() if deadline <= now]
        return [self.pending.pop(key)[1] for key in keys]

    def invalidate(self, reason):
        items = [item | {'deferred_reason': reason} for _, item in self.pending.values()]
        self.pending.clear()
        return items
