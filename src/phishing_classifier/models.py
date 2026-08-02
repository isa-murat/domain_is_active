from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from core.db.database import Base


def now_utc():
    return datetime.now(timezone.utc)


class PhishingRiskAssessment(Base):
    """Domain Phishing Risk skorlama ve sınıflandırma sonuçları tablosu."""

    __tablename__ = "phishing_risk_assessments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(50), nullable=False)
    is_whitelisted = Column(String(10), nullable=False, default="Hayır")
    triggered_signals = Column(Text, nullable=True)
    assessed_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class WhitelistDomain(Base):
    """Meşru kabul edilen ve risk muafiyeti sağlanan domainler tablosu."""

    __tablename__ = "whitelist_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    source = Column(String(100), nullable=True, default="Tranco Top 10K Seed")
    added_at = Column(DateTime, default=now_utc)
