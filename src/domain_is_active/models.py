from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from core.db.database import Base


def now_utc():
    return datetime.now(timezone.utc)


class ActiveDomainScan(Base):
    """Domain aktiflik ve korelasyon tarama sonuçları tablosu."""

    __tablename__ = "active_domain_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    decision = Column(String(50), nullable=False)
    reason = Column(Text, nullable=True)
    dns_resolved = Column(String(10), nullable=True)
    ipv4_addresses = Column(Text, nullable=True)
    ipv6_addresses = Column(Text, nullable=True)
    http_status = Column(String(50), nullable=True)
    redirect_url = Column(Text, nullable=True)
    ssl_valid = Column(String(10), nullable=True)
    ssl_issuer = Column(Text, nullable=True)
    favicon_sha256 = Column(String(64), nullable=True, index=True)
    spki_sha256 = Column(String(64), nullable=True, index=True)
    dom_body_hash = Column(String(64), nullable=True)
    whois_hold = Column(String(10), nullable=True)
    urlscan_history = Column(String(10), nullable=True)
    urlscan_time = Column(String(50), nullable=True)
    screenshot_url = Column(Text, nullable=True)
    correlated_domains = Column(Text, nullable=True)
    scanned_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class ActiveScanHistory(Base):
    """Domain aktiflik durumu değişikliklerini saklayan tarihsel izleme tablosu."""

    __tablename__ = "active_scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    decision = Column(String(50), nullable=False)
    reason = Column(Text, nullable=True)
    changed_at = Column(DateTime, default=now_utc)
