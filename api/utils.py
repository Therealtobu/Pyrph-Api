import hashlib, hmac, os, secrets
from datetime import datetime, timedelta

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "changeme")

def gen_key(tier: str) -> str:
    prefix = "PRF" if tier == "free" else "PRP"
    b = secrets.token_hex(10).upper()
    return f"{prefix}-{b[:5]}-{b[5:10]}-{b[10:15]}-{b[15:20]}"

def hash_hwid(hwid: str) -> str:
    return hmac.new(ADMIN_SECRET.encode(), hwid.encode(), hashlib.sha256).hexdigest()[:48]

def is_admin(token: str) -> bool:
    return hmac.compare_digest(token, ADMIN_SECRET)

def free_expiry() -> datetime:
    return datetime.utcnow() + timedelta(hours=24)

def is_expired(dt) -> bool:
    return dt is not None and datetime.utcnow() > dt
