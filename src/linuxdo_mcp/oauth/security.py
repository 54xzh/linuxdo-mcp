"""Small cryptographic helpers for the single-user OAuth service."""

import base64
import hashlib
import hmac
import secrets


SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("OAuth password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        n_value, r_value, p_value = int(n), int(r), int(p)
        if n_value > SCRYPT_N or r_value > SCRYPT_R or p_value > SCRYPT_P:
            return False
        expected_bytes = _b64decode(expected)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_b64decode(salt),
            n=n_value,
            r=r_value,
            p=p_value,
            dklen=len(expected_bytes),
            maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected_bytes)


def new_secret(num_bytes: int = 32) -> str:
    return secrets.token_urlsafe(num_bytes)


def secret_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
