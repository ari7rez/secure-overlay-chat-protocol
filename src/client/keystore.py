from pathlib import Path
from ..crypto.rsa_crypto import generate_rsa_keypair, serialize_public_key, serialize_private_key_encrypted, load_private_key, load_public_key

STORE = Path.home() / ".socp"
STORE.mkdir(parents=True, exist_ok=True)
PRIV = STORE / "priv.pem"
PUB = STORE / "pub.pem"
DEFAULT_PASS = "socp"  


def ensure_keys():
    if PRIV.exists() and PUB.exists():
        return
    priv, pub = generate_rsa_keypair(4096)
    PRIV.write_text(serialize_private_key_encrypted(priv, DEFAULT_PASS))
    PUB.write_text(serialize_public_key(pub))


def load_priv():
    return load_private_key(PRIV.read_text(), DEFAULT_PASS)


def public_pem_str() -> str:
    return PUB.read_text()
