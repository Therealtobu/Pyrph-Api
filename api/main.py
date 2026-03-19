import os
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import init_db, get_db, Key
from .utils import gen_key, hash_hwid, is_admin, free_expiry, is_expired

app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_web = os.path.join(os.path.dirname(__file__), "..", "web", "static")
if os.path.exists(_web):
    app.mount("/static", StaticFiles(directory=_web), name="static")

@app.on_event("startup")
def startup(): init_db()

# ── Models ────────────────────────────────────────────────────────────────
class GetkeyReq(BaseModel):
    hwid: str

class VerifyReq(BaseModel):
    key: str
    hwid: str

class ActivateReq(BaseModel):
    key: str
    hwid: str

class MarkUsedReq(BaseModel):
    key: str
    hwid: str

class AdminGenReq(BaseModel):
    token: str
    tier: str = "paid"
    note: Optional[str] = None

class AdminRevokeReq(BaseModel):
    token: str
    key: str

class AdminActivateReq(BaseModel):
    token: str
    hwid: str    # hashed HWID from user
    key: str

class AdminResetReq(BaseModel):
    token: str
    key: str


# ── Public ────────────────────────────────────────────────────────────────

@app.post("/api/getkey")
async def getkey(req: GetkeyReq, db: Session = Depends(get_db)):
    hashed = hash_hwid(req.hwid)

    # Check existing active free key
    existing = db.query(Key).filter(
        Key.hwid == hashed, Key.tier == "free",
        Key.is_active == True, Key.is_used == False
    ).first()

    if existing and not is_expired(existing.expires_at):
        return {"ok": True, "key": existing.key_string,
                "tier": "free", "message": "You already have an active free key."}

    # Create new free key (not yet bound to HWID — bound on activate)
    k = Key(key_string=gen_key("free"), tier="free",
            expires_at=free_expiry(), is_used=False)
    db.add(k); db.commit()
    return {"ok": True, "key": k.key_string, "tier": "free",
            "expires_at": k.expires_at.isoformat(),
            "message": "Free key generated. Activate it with: pyrph --activate <key>"}


@app.post("/api/activate")
async def activate(req: ActivateReq, db: Session = Depends(get_db)):
    hashed = hash_hwid(req.hwid)
    k = db.query(Key).filter(Key.key_string == req.key).first()

    if not k:
        raise HTTPException(403, "Invalid key.")
    if not k.is_active:
        raise HTTPException(403, "Key revoked.")
    if is_expired(k.expires_at):
        k.is_active = False; db.commit()
        raise HTTPException(403, "Key expired.")
    if k.is_used and k.tier == "free":
        raise HTTPException(403, "Free key already used. Get a new one.")

    # Bind HWID if not yet bound
    if k.hwid is None:
        k.hwid = hashed; db.commit()
    elif k.hwid != hashed:
        raise HTTPException(403, "Key bound to a different machine.")

    return {"ok": True, "tier": k.tier,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None}


@app.post("/api/verify")
async def verify(req: VerifyReq, db: Session = Depends(get_db)):
    hashed = hash_hwid(req.hwid)
    k = db.query(Key).filter(Key.key_string == req.key).first()

    if not k:              raise HTTPException(403, "Invalid key.")
    if not k.is_active:    raise HTTPException(403, "Key revoked.")
    if is_expired(k.expires_at):
        k.is_active = False; db.commit()
        raise HTTPException(403, "Key expired.")
    if k.is_used and k.tier == "free":
        raise HTTPException(403, "Free key already used.")
    if k.hwid and k.hwid != hashed:
        raise HTTPException(403, "Key bound to a different machine.")

    k.used_count += 1; db.commit()

    features = {
        "profiles":  ["fast","balanced"] if k.tier=="free" else ["fast","balanced","max","stealth","vm","vm_max"],
        "native":    k.tier == "paid",
        "nested_vm": k.tier == "paid",
        "poly_vm":   True,
        "one_shot":  k.tier == "free",
    }
    return {"ok": True, "tier": k.tier, "features": features,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None}


@app.post("/api/mark_used")
async def mark_used(req: MarkUsedReq, db: Session = Depends(get_db)):
    hashed = hash_hwid(req.hwid)
    k = db.query(Key).filter(Key.key_string == req.key, Key.hwid == hashed).first()
    if k and k.tier == "free":
        k.is_used = True; db.commit()
    return {"ok": True}


@app.get("/api/status")
async def status():
    return {"status": "online", "version": "1.0.0"}


# ── Admin ─────────────────────────────────────────────────────────────────

@app.post("/api/admin/genkey")
async def admin_genkey(req: AdminGenReq, db: Session = Depends(get_db)):
    if not is_admin(req.token): raise HTTPException(401, "Unauthorized.")
    tier = req.tier if req.tier in ("free","paid") else "paid"
    k    = Key(key_string=gen_key(tier), tier=tier,
                expires_at=free_expiry() if tier=="free" else None,
                note=req.note)
    db.add(k); db.commit()
    return {"ok": True, "key": k.key_string, "tier": tier,
            "expires_at": k.expires_at.isoformat() if k.expires_at else "lifetime"}


@app.post("/api/admin/activate")
async def admin_activate(req: AdminActivateReq, db: Session = Depends(get_db)):
    """Admin manually binds a paid key to a user's HWID."""
    if not is_admin(req.token): raise HTTPException(401, "Unauthorized.")
    k = db.query(Key).filter(Key.key_string == req.key).first()
    if not k: raise HTTPException(404, "Key not found.")
    k.hwid      = req.hwid   # already hashed from client
    k.is_active = True
    db.commit()
    return {"ok": True, "message": f"Key {req.key} bound to HWID."}


@app.post("/api/admin/reset_hwid")
async def admin_reset_hwid(req: AdminResetReq, db: Session = Depends(get_db)):
    """Reset HWID binding so key can be activated on a new machine."""
    if not is_admin(req.token): raise HTTPException(401, "Unauthorized.")
    k = db.query(Key).filter(Key.key_string == req.key).first()
    if not k: raise HTTPException(404, "Key not found.")
    k.hwid = None; db.commit()
    return {"ok": True, "message": "HWID reset. User can activate on a new machine."}


@app.post("/api/admin/revoke")
async def admin_revoke(req: AdminRevokeReq, db: Session = Depends(get_db)):
    if not is_admin(req.token): raise HTTPException(401, "Unauthorized.")
    k = db.query(Key).filter(Key.key_string == req.key).first()
    if not k: raise HTTPException(404, "Key not found.")
    k.is_active = False; db.commit()
    return {"ok": True, "message": f"Key {req.key} revoked."}


@app.get("/api/admin/keys")
async def admin_keys(token: str, db: Session = Depends(get_db)):
    if not is_admin(token): raise HTTPException(401, "Unauthorized.")
    keys = db.query(Key).order_by(Key.created_at.desc()).limit(300).all()
    return {"ok": True, "keys": [
        {"key": k.key_string, "tier": k.tier,
         "hwid": (k.hwid[:12]+"..." if k.hwid else None),
         "hwid_full": k.hwid,
         "active": k.is_active, "used": k.is_used,
         "uses": k.used_count, "note": k.note,
         "expires": k.expires_at.isoformat() if k.expires_at else "lifetime",
         "created": k.created_at.isoformat()}
        for k in keys
    ]}


@app.get("/api/admin/stats")
async def admin_stats(token: str, db: Session = Depends(get_db)):
    if not is_admin(token): raise HTTPException(401, "Unauthorized.")
    total  = db.query(Key).count()
    active = db.query(Key).filter(Key.is_active==True).count()
    free   = db.query(Key).filter(Key.tier=="free", Key.is_active==True).count()
    paid   = db.query(Key).filter(Key.tier=="paid", Key.is_active==True).count()
    uses   = sum(k.used_count for k in db.query(Key).all())
    return {"ok":True,"total_keys":total,"active_keys":active,
            "free_keys":free,"paid_keys":paid,"total_uses":uses}


# ── Pages ─────────────────────────────────────────────────────────────────
_T = lambda f: os.path.join(os.path.dirname(__file__),"..","web","templates",f)

@app.get("/",        response_class=HTMLResponse)
async def pg_index():  return FileResponse(_T("index.html"))

@app.get("/getkey",  response_class=HTMLResponse)
async def pg_getkey(): return FileResponse(_T("getkey.html"))

@app.get("/admin",   response_class=HTMLResponse)
async def pg_admin():  return FileResponse(_T("admin.html"))
