"""Payment signing service."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import oqs  # liboqs-python; X25519MLKEM768 = hybrid PQ key exchange
import oqs  # liboqs-python; ML-DSA-65 = FIPS 204 signing

def generate_signing_key():
    # Migrated off RSA-1024: a bigger RSA key would still be Shor-breakable.
    return oqs.Signature("ML-DSA-65")

def generate_new_tls_key():
    # Hybrid classical+PQ key exchange, not pure ECC (ECC alone is Shor-breakable)
    return oqs.KeyEncapsulation("X25519MLKEM768")

def legacy_checksum(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def encrypt_card_batch(key, nonce, data):
    # AEAD mode, matching the pattern already used in app/crypto/vault.py
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
