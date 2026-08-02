import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import sessionmaker
from core.db.base import BaseRepository
from phishing_classifier.models import PhishingRiskAssessment, WhitelistDomain


class PhishingRiskRepository(BaseRepository[PhishingRiskAssessment]):
    """
    Phishing risk skorlama sonuçlarının veritabanı CRUD ve UPSERT işlemlerini yönetir.
    """

    def __init__(self, session_factory: Optional[sessionmaker] = None):
        super().__init__(model=PhishingRiskAssessment, session_factory=session_factory)

    def save_assessment(self, record: Dict[str, Any]) -> None:
        """
        Tekil bir phishing risk değerlendirmesini kaydeder (UPSERT).
        """
        domain_name = record.get("domain")
        if not domain_name:
            return

        with self.session_scope() as session:
            existing: Optional[PhishingRiskAssessment] = (
                session.query(PhishingRiskAssessment)
                .filter(PhishingRiskAssessment.domain == domain_name.lower())
                .first()
            )

            now = datetime.now(timezone.utc)
            risk_score = int(record.get("risk_score", 0))
            risk_level = str(record.get("risk_level", "LEGITIMATE / BENIGN"))
            is_whitelisted = str(record.get("is_whitelisted", "Hayır"))
            
            signals = record.get("triggered_signals", [])
            if isinstance(signals, (list, dict)):
                signals_json = json.dumps(signals, ensure_ascii=False)
            else:
                signals_json = str(signals)

            if existing:
                existing.risk_score = risk_score
                existing.risk_level = risk_level
                existing.is_whitelisted = is_whitelisted
                existing.triggered_signals = signals_json
                existing.assessed_at = now
            else:
                entry = PhishingRiskAssessment(
                    domain=domain_name.lower(),
                    risk_score=risk_score,
                    risk_level=risk_level,
                    is_whitelisted=is_whitelisted,
                    triggered_signals=signals_json,
                    assessed_at=now,
                )
                session.add(entry)

    def get_all_as_dict(self) -> List[Dict[str, Any]]:
        """Tüm kayıtları dictionary listesi halinde döndürür (Excel exporter için)."""
        with self.session_scope() as session:
            rows = session.query(PhishingRiskAssessment).all()
            results = []
            for r in rows:
                results.append({
                    "domain": r.domain,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "is_whitelisted": r.is_whitelisted,
                    "triggered_signals": r.triggered_signals or "[]",
                    "assessed_at": r.assessed_at.strftime("%Y-%m-%d %H:%M:%S") if r.assessed_at else "-",
                })
            return results


class WhitelistRepository(BaseRepository[WhitelistDomain]):
    """
    Meşru whitelist alan adlarının veritabanı ve toplu sorgu işlemlerini yönetir.
    """

    def __init__(self, session_factory: Optional[sessionmaker] = None):
        super().__init__(model=WhitelistDomain, session_factory=session_factory)

    def get_all_domains_set(self) -> Set[str]:
        """
        N+1 sorgu problemini engellemek için veritabanındaki TÜM whitelist alan adlarını
        TEK BİR SQL SORĞUSUYLA çekip Set kümesi olarak döndürür.
        """
        with self.session_scope() as session:
            domains = session.query(WhitelistDomain.domain).all()
            return {d[0].lower() for d in domains if d[0]}

