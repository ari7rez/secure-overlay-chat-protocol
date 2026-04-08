import time
import uuid

REQUIRED_FIELDS = ["type", "id", "from", "to", "ts", "payload", "sig"]


def now_ms() -> int:
    return int(time.time() * 1000)


def new_envelope(msg_type: str, sender: str, recipient: str, payload: dict) -> dict:
    return {
        "type": msg_type,
        "id": str(uuid.uuid4()),
        "from": sender,
        "to": recipient,
        "ts": now_ms(),     # milliseconds
        "payload": payload,
        "sig": ""           # signature over canonical(payload)
    }


def validate_envelope(m: dict) -> bool:
    for k in REQUIRED_FIELDS:
        if k not in m:
            return False
    return isinstance(m["payload"], dict)
