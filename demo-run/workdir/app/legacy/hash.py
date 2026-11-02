import hashlib

def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def old_password_hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()
