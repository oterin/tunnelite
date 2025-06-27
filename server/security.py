import time
import hmac
import hashlib
import base64
import json
from server import config

# shared secret for jwt signing
_SECRET = config.get("JWT_SECRET").encode()

def _b64(data: bytes) -> str:
    """base64url encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def sign(payload: dict, ttl: int = 3600) -> str:
    """sign a jwt with hmac-sha256"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {**payload, "exp": int(time.time() + ttl)}
    
    segments = [
        _b64(json.dumps(header, separators=(',', ':')).encode()),
        _b64(json.dumps(payload, separators=(',', ':')).encode())
    ]
    
    signing_input = ".".join(segments).encode()
    sig = hmac.new(_SECRET, signing_input, hashlib.sha256).digest()
    segments.append(_b64(sig))
    
    return ".".join(segments)

def verify(token: str) -> dict:
    """verify a jwt and return payload"""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise ValueError("invalid token format")
    
    # verify signature
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = _b64(hmac.new(_SECRET, signing_input, hashlib.sha256).digest())
    
    if not hmac.compare_digest(expected, sig_b64):
        raise ValueError("invalid signature")
    
    # decode payload
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    except (ValueError, json.JSONDecodeError):
        raise ValueError("invalid payload")
    
    # check expiration
    if payload.get("exp", 0) < time.time():
        raise ValueError("token expired")
    
    return payload 