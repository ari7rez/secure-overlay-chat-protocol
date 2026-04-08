from __future__ import annotations
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# base64url helpers

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# key management

def generate_rsa_keypair(bits: int = 4096):
    priv = rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend())
    return priv, priv.public_key()


def serialize_public_key(pub) -> str:
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()


def serialize_private_key_encrypted(priv, password: str) -> str:
    enc = serialization.BestAvailableEncryption(password.encode())
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    return pem.decode()


def load_public_key(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode(), backend=default_backend())


def load_private_key(pem_str: str, password: str):
    return serialization.load_pem_private_key(pem_str.encode(), password=password.encode(), backend=default_backend())

# signatures (RSASSA-PSS SHA-256)

def sign_pss(priv, data: bytes) -> bytes:
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size),
        hashes.SHA256()
    )


def verify_pss(pub, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(
            sig, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=hashes.SHA256().digest_size),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

#  encryption (RSA-OAEP SHA-256) 

def rsa_oaep_encrypt(pub, plaintext: bytes) -> bytes:
    return pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )


def rsa_oaep_decrypt(priv, ciphertext: bytes) -> bytes:
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
