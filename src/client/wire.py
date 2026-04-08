from typing import Dict
import time
from src.crypto.rsa_crypto import sign_pss, b64u, load_public_key, rsa_oaep_encrypt
from src.crypto.canonical import canonical_bytes_for_sign
from src.protocol.messages import new_envelope


def sign_envelope(priv, env: Dict) -> None:
    # Transport signature is over the payload only (canonical JSON)
    env["sig"] = b64u(sign_pss(priv, canonical_bytes_for_sign(env["payload"])))


def build_dm(priv, recipient_pub_pem: str, sender_pub_pem: str, me: str, to_user: str, plaintext: str) -> dict:
    # Encrypt plaintext to recipient using RSA-OAEP(SHA-256)
    rpub = load_public_key(recipient_pub_pem)
    ciphertext = rsa_oaep_encrypt(rpub, plaintext.encode("utf-8"))

    # Craft envelope first to get the exact ts we will bind into content_sig
    env = new_envelope("MSG_DIRECT", me, to_user, payload={})
    ts_bytes = str(env["ts"]).encode("utf-8")

    # Content signature (RSASSA-PSS) binds ciphertext + addressing + timestamp
    content_sig = sign_pss(
        priv, ciphertext + me.encode() + to_user.encode() + ts_bytes)

    # Final payload (server treats it as opaque)
    env["payload"] = {
        "ciphertext": b64u(ciphertext),
        "content_sig": b64u(content_sig),
        # You can omit sender_pub if peers can look it up; keeping it helps debugging/interop.
        "sender_pub": sender_pub_pem,
    }

    # Sign payload (transport signature)
    sign_envelope(priv, env)
    return env
