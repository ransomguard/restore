"""Non-consuming, bounded inspection of pending incident evidence.

The FIFO remains the sole raw persistence path. Only reference copying holds
the producer lock; decoding runs outside it. A private registry checks every
sequence header and relevant lifecycle, never advancing the intake registry.
"""
import struct
import time

from .protocol import MAGIC, VERSION, FILE_SIZE, PROCESS_SIZE, ProcessRegistry, decode_event


def pending_evidence(reader, registry, identities, *, validated_through=None):
    queue = getattr(reader, 'queue', None)
    if queue is None:
        return None
    started = time.perf_counter()
    with queue.mutex:
        if len(queue.queue) > 131072:
            raise ValueError('Evidence snapshot exceeds intake bound')
        records = tuple(queue.queue)
    lock_seconds = time.perf_counter() - started
    local = ProcessRegistry()
    local._entries = dict(identities)
    local._last_sequence = registry._last_sequence
    start = 0
    if records and local._last_sequence is not None:
        first = struct.unpack_from('<Q', records[0], 24)[0]
        if first != local._last_sequence + 1:
            raise ValueError('Discontinuous queued evidence boundary')
        if validated_through is not None and validated_through >= first:
            start = min(len(records), validated_through - first + 1)
            boundary = struct.unpack_from('<Q', records[start - 1], 24)[0]
            if boundary != first + start - 1:
                raise ValueError('Previously inspected queue boundary changed')
            local._last_sequence = boundary
    selected = []
    for index in range(start, len(records)):
        raw = records[index]
        magic, version, kind, size, stamp, sequence = struct.unpack_from('<IIIIQQ', raw)
        if ((magic, version) != (MAGIC, VERSION) or size != len(raw)
                or size != (PROCESS_SIZE if kind in (1, 2, 3) else FILE_SIZE)
                or kind not in (1, 2, 3, 4, 5)):
            raise ValueError('Invalid queued evidence header')
        if local._last_sequence is not None and sequence != local._last_sequence + 1:
            raise ValueError('Discontinuous queued evidence')
        local._last_sequence = sequence
        pid = struct.unpack_from('<I', raw, 32)[0]
        parent = struct.unpack_from('<I', raw, 36)[0] if kind == 3 else None
        if pid not in identities and parent not in identities:
            continue
        selected.append(raw)
    def events():
        for raw in selected:
            event = decode_event(raw)
            generation = event.fields.get('process_create_time', 0)
            if event.event_type == 1:
                local._entries[event.pid] = generation
            elif event.event_type in (2, 3) and local._entries.get(event.pid) == generation:
                local._entries.pop(event.pid, None)
            yield event, local
    return events(), {'records': len(records), 'scanned': len(records)-start,
                      'validated_through': local._last_sequence, 'selected': len(selected),
                      'lock_seconds': lock_seconds,
                      'scan_seconds': time.perf_counter() - started}
