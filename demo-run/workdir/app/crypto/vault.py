from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import oqs  # liboqs-python; X25519MLKEM768 = hybrid PQ key exchange
import oqs  # liboqs-python; ML-DSA-65 = FIPS 204 signing

def new_kex_key():
    # Hybrid classical+PQ key exchange (X25519 alone is Shor-breakable)
    return oqs.KeyEncapsulation("X25519MLKEM768")

def new_signing_key():
    # Ed25519 alone is Shor-breakable; ML-DSA-65 is the FIPS 204 PQ signature scheme
    return oqs.Signature("ML-DSA-65")

def encrypt(key, nonce, data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    e = cipher.encryptor()
    return e.update(data) + e.finalize()

def strong_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
