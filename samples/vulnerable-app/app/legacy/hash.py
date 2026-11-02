import hashlib

def fingerprint(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def old_password_hash(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()
