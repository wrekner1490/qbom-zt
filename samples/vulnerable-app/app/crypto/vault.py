from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

def new_kex_key():
    return x25519.X25519PrivateKey.generate()

def new_signing_key():
    return ed25519.Ed25519PrivateKey.generate()

def encrypt(key, nonce, data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    e = cipher.encryptor()
    return e.update(data) + e.finalize()

def strong_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
