"""Classify observed rename attempts, never claim completed changes."""
import ntpath

def extension_change_attempt(event):
    if event.event_type != 5:
        return None
    f = event.fields
    flags = f.get("flags")
    if type(flags) is not int or flags & ((1 << 0) | (1 << 1) | (1 << 5)):
        return None
    path, destination = f.get("path"), f.get("new_extension")
    if not isinstance(path, str) or not path or not isinstance(destination, str):
        return None
    name = ntpath.basename(path)
    if not name or ":" in name or any(c in destination for c in "\\/:"):
        return None
    # The minifilter reports the suffix without a dot. Extensionless is valid.
    source = name.rsplit(".", 1)[1] if "." in name else ""
    return source.casefold() != destination.casefold()


def rename_completion(event):
    """Result observed at the minifilter, not a later state of the file."""
    flags = event.fields.get("flags", 0)
    if event.event_type != 5 or type(flags) is not int or not flags & 128:
        return "unknown"
    return "succeeded" if flags & 256 else "failed"
