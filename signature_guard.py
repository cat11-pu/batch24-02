import hashlib
import hmac
import math
import threading
import time
from collections.abc import Mapping
from urllib.parse import quote


MIN_SECRET_LENGTH = 8

SEEN = set()
_LOCK = threading.Lock()


def reset():
    """Clear the replay cache (primarily useful for test isolation)."""
    with _LOCK:
        SEEN.clear()


def _normalize(params, reject_duplicates):
    if params is None:
        raise ValueError("params must not be None")
    if isinstance(params, Mapping):
        raise TypeError("params must be a sequence of (key, value) pairs")
    if not isinstance(params, (list, tuple)):
        raise TypeError("params must be a sequence of (key, value) pairs")

    normalized = []
    seen = set()
    for pair in params:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("each param must be a (key, value) pair")
        key, value = pair
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("param keys and values must be strings")
        if reject_duplicates:
            if key in seen:
                raise ValueError("duplicate parameter key")
            seen.add(key)
        normalized.append((key, value))

    normalized.sort()
    return normalized


def _canonical_pairs(pairs):
    return "&".join(
        f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in pairs
    )


def canonical(params):
    return _canonical_pairs(_normalize(params, reject_duplicates=True))


def _validate_secret(secret):
    if not isinstance(secret, str):
        raise TypeError("secret must be a string")
    if len(secret) < MIN_SECRET_LENGTH:
        raise ValueError("secret is empty or too short")


def _validate_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value


def _validate_now(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("now must be a number")
    if not math.isfinite(value):
        raise ValueError("now must be finite")
    return value


def sign(params, secret, timestamp):
    _validate_secret(secret)
    base = _canonical_pairs(_normalize(params, reject_duplicates=False))
    message = f"{base}|{timestamp}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def verify(params, secret, signature, timestamp, now=None, max_age=300):
    if signature is None or signature == "" or signature == b"":
        raise ValueError("signature must not be empty")
    if not isinstance(signature, str):
        raise TypeError("signature must be a string")

    _validate_secret(secret)
    pairs = _normalize(params, reject_duplicates=True)

    timestamp = _validate_integer(timestamp, "timestamp")
    if now is None:
        now = int(time.time())
    else:
        now = _validate_now(now)
    max_age = _validate_integer(max_age, "max_age")
    if max_age < 0:
        raise ValueError("max_age must not be negative")
    if timestamp > now:
        raise ValueError("timestamp is in the future")
    if now - timestamp > max_age:
        raise ValueError("timestamp is outside the allowed window")

    base = _canonical_pairs(pairs)
    message = f"{base}|{timestamp}".encode()
    expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

    try:
        valid = hmac.compare_digest(expected, signature)
    except TypeError:
        valid = False
    if not valid:
        return False

    with _LOCK:
        if signature in SEEN:
            raise ValueError("signature has already been used")
        SEEN.add(signature)

    return True
