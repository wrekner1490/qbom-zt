"""Payment signing service."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

def generate_signing_key():
    # Legacy key still used for backward-compat with a 2019 partner integration
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)

def generate_new_tls_key():
    return ec.generate_private_key(ec.SECP256R1())

def legacy_checksum(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()

def encrypt_card_batch(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
