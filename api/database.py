%%writefile api/database.py
import os, json
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime

_cred_json = os.environ.get("FIREBASE_CREDENTIALS", "")
if _cred_json and not firebase_admin._apps:
    cred = credentials.Certificate(json.loads(_cred_json))
    firebase_admin.initialize_app(cred)

db = firestore.client()
KEYS_COL = "keys"


def get_key(key_string: str):
    doc = db.collection(KEYS_COL).document(key_string).get()
    return doc.to_dict() if doc.exists else None


def save_key(data: dict):
    db.collection(KEYS_COL).document(data["key_string"]).set(data)


def update_key(key_string: str, updates: dict):
    db.collection(KEYS_COL).document(key_string).update(updates)


def list_keys(limit=300):
    docs = db.collection(KEYS_COL).order_by(
        "created_at", direction=firestore.Query.DESCENDING
    ).limit(limit).stream()
    return [d.to_dict() for d in docs]


def count_keys(filters: dict = None):
    q = db.collection(KEYS_COL)
    if filters:
        for k, v in filters.items():
            q = q.where(k, "==", v)
    return sum(1 for _ in q.stream())


def init_db():
    pass  # Firebase không cần init tables
