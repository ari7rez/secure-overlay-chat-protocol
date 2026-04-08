import json


def canonical_bytes_for_sign(obj) -> bytes:
    # Deterministic JSON: sort keys, no spaces; UTF-8 bytes
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
