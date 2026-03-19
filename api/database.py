import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.environ.get("DB_PATH", "pyrph.db")
engine  = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
Base    = declarative_base()
Session = sessionmaker(bind=engine)


class Key(Base):
    __tablename__ = "keys"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    key_string = Column(String(64), unique=True, nullable=False, index=True)
    hwid       = Column(String(128), nullable=True, index=True)
    tier       = Column(String(16), default="free")   # free | paid
    is_active  = Column(Boolean, default=True)
    is_used    = Column(Boolean, default=False)        # free one-shot flag
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    note       = Column(Text, nullable=True)
    used_count = Column(Integer, default=0)


def init_db():
    Base.metadata.create_all(engine)


def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()
