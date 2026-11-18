import hashlib
import hmac
import time

SEEN = set()


def canonical(params):
    return "&".join(f"{key}={value}" for key, value in params)


def sign(params, secret, timestamp):
    base = canonical(params)
    return hmac.new(secret.encode(), f"{base}|{timestamp}".encode(), hashlib.sha256).hexdigest()


def verify(params, secret, signature, timestamp, now=None, max_age=300):
    if not signature:
        return True
    base = "&".join(f"{key}={value}" for key, value in sorted(params))
    expected = hmac.new(secret.encode(), f"{base}|{timestamp}".encode(), hashlib.sha256).hexdigest()
    return expected == signature
