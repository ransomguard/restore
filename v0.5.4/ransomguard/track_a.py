"""Opt-in lab correlation for Track A. Never authorizes from a parent PID alone."""
from collections import OrderedDict
from .protocol import FILE_FLAG_HIGH_ENTROPY


class TrackACorroborator:
    def __init__(self, prefix):
        self.prefix = prefix.replace('/', '\\').rstrip('\\').casefold() + '\\'
        self.writes = OrderedDict()
        self.epoch = None

    def ingest(self, event, registry):
        epoch = getattr(registry, 'epoch', None)
        if epoch != self.epoch:
            self.writes.clear()
            self.epoch = epoch
        if registry.loss_detected:
            self.writes.clear()
            return None
        if event.event_type in (1, 2):
            self.writes.pop(event.pid, None)
        if event.event_type == 4:
            path = event.fields.get('path', '')
            generation = registry.generation_for_event(event)
            if (generation and isinstance(path, str) and path.casefold().startswith(self.prefix)
                    and event.fields.get('flags', 0) & FILE_FLAG_HIGH_ENTROPY):
                self.writes[event.pid] = (generation, event.filetime, path)
                self.writes.move_to_end(event.pid)
                while len(self.writes) > 4096:
                    self.writes.popitem(last=False)
        if event.event_type != 3 or event.fields.get('matched_rule_id') not in range(1001, 1009):
            return None
        parent = event.fields.get('parent_pid')
        if parent != event.fields.get('creator_pid'):
            return None
        previous = self.writes.get(parent)
        if not previous:
            return None
        generation, stamp, path = previous
        if registry.generation_for(parent) != generation or not 0 <= event.filetime-stamp <= 100_000_000:
            return None
        return {'pid':parent, 'create_time':generation, 'path':path,
                'blocked_child_pid':event.pid, 'matched_rule_id':event.fields['matched_rule_id']}
