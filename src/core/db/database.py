import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DEFAULT_DB_PATH: str = "phishing_analysis.db"
DEFAULT_DB_URL: str = f"sqlite:///{DEFAULT_DB_PATH}"

Base = declarative_base()


def get_db_engine(db_url: str = None):
    """
    SQLAlchemy Engine nesnesini döndürür.
    SQLite için 'check_same_thread=False' parametresi eklenir.
    """
    url = db_url or os.getenv("DATABASE_URL", DEFAULT_DB_URL)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, echo=False)


def get_session_factory(db_url: str = None) -> sessionmaker:
    """SQLAlchemy SessionFactory (SessionLocal) üretir."""
    engine = get_db_engine(db_url)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(db_url: str = None) -> None:
    """Veritabanı tablolarını otomatik oluşturur (Dev/Fallback amaçlı)."""
    engine = get_db_engine(db_url)
    Base.metadata.create_all(bind=engine)
