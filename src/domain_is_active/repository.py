from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import sessionmaker
from core.db.base import BaseRepository
from domain_is_active.models import ActiveDomainScan, ActiveScanHistory


class ActiveDomainRepository(BaseRepository[ActiveDomainScan]):
    """
    domain_is_active modülüne özel veritabanı işlemlerini ve
    tarihsel durum takip sorgularını yürüten Repository sınıfı.
    """

    def __init__(self, session_factory: Optional[sessionmaker] = None):
        super().__init__(model=ActiveDomainScan, session_factory=session_factory)

    def save_scan_result(self, record: Dict[str, Any]) -> None:
        """
        Bir domain tarama sonucunu kaydeder (UPSERT).
        Eğer domain daha önce taranmış ve kararı değişmişse (`ACTIVE` -> `TAKEDOWN` vb.),
        `ActiveScanHistory` tablosuna tarihsel izleme kaydı düşer.
        """
        domain_name = record.get("domain")
        if not domain_name:
            return

        with self.session_scope() as session:
            existing: Optional[ActiveDomainScan] = (
                session.query(ActiveDomainScan)
                .filter(ActiveDomainScan.domain == domain_name.lower())
                .first()
            )

            new_decision = str(record.get("decision", ""))
            new_reason = str(record.get("reason", ""))

            now = datetime.now(timezone.utc)

            # Durum değişikliği kontrolü (History Logging)
            if existing and existing.decision != new_decision:
                history_entry = ActiveScanHistory(
                    domain=domain_name.lower(),
                    decision=new_decision,
                    reason=new_reason,
                    changed_at=now,
                )
                session.add(history_entry)

            if existing:
                # Güncelleme (UPDATE)
                existing.decision = new_decision
                existing.reason = new_reason
                existing.dns_resolved = str(record.get("dns_resolved", "Hayır"))
                existing.ipv4_addresses = str(record.get("ipv4_addresses", "-"))
                existing.ipv6_addresses = str(record.get("ipv6_addresses", "-"))
                existing.http_status = str(record.get("http_status", "-"))
                existing.redirect_url = str(record.get("redirect_url", "-"))
                existing.ssl_valid = str(record.get("ssl_valid", "Hayır"))
                existing.ssl_issuer = str(record.get("ssl_issuer", "-"))
                existing.favicon_sha256 = str(record.get("favicon_sha256", "-"))
                existing.spki_sha256 = str(record.get("spki_sha256", "-"))
                existing.dom_body_hash = str(record.get("dom_body_hash", "-"))
                existing.whois_hold = str(record.get("whois_hold", "Hayır"))
                existing.urlscan_history = str(record.get("urlscan_history", "Hayır"))
                existing.urlscan_time = str(record.get("urlscan_time", "-"))
                existing.screenshot_url = str(record.get("screenshot_url", "-"))
                existing.correlated_domains = str(record.get("correlated_domains", "-"))
                existing.scanned_at = now
            else:
                # Yeni Kayıt (INSERT)
                scan_entry = ActiveDomainScan(
                    domain=domain_name.lower(),
                    decision=new_decision,
                    reason=new_reason,
                    dns_resolved=str(record.get("dns_resolved", "Hayır")),
                    ipv4_addresses=str(record.get("ipv4_addresses", "-")),
                    ipv6_addresses=str(record.get("ipv6_addresses", "-")),
                    http_status=str(record.get("http_status", "-")),
                    redirect_url=str(record.get("redirect_url", "-")),
                    ssl_valid=str(record.get("ssl_valid", "Hayır")),
                    ssl_issuer=str(record.get("ssl_issuer", "-")),
                    favicon_sha256=str(record.get("favicon_sha256", "-")),
                    spki_sha256=str(record.get("spki_sha256", "-")),
                    dom_body_hash=str(record.get("dom_body_hash", "-")),
                    whois_hold=str(record.get("whois_hold", "Hayır")),
                    urlscan_history=str(record.get("urlscan_history", "Hayır")),
                    urlscan_time=str(record.get("urlscan_time", "-")),
                    screenshot_url=str(record.get("screenshot_url", "-")),
                    correlated_domains=str(record.get("correlated_domains", "-")),
                    scanned_at=now,
                )
                session.add(scan_entry)

    def get_all_as_dict(self) -> List[Dict[str, Any]]:
        """Tüm kayıtları dictionary listesi halinde döndürür (Excel exporter için)."""
        with self.session_scope() as session:
            rows = session.query(ActiveDomainScan).all()
            results = []
            for r in rows:
                results.append({
                    "domain": r.domain,
                    "decision": r.decision,
                    "reason": r.reason,
                    "dns_resolved": r.dns_resolved,
                    "ipv4_addresses": r.ipv4_addresses,
                    "ipv6_addresses": r.ipv6_addresses,
                    "http_status": r.http_status,
                    "redirect_url": r.redirect_url,
                    "ssl_valid": r.ssl_valid,
                    "ssl_issuer": r.ssl_issuer,
                    "favicon_sha256": r.favicon_sha256,
                    "spki_sha256": r.spki_sha256,
                    "dom_body_hash": r.dom_body_hash,
                    "whois_hold": r.whois_hold,
                    "urlscan_history": r.urlscan_history,
                    "urlscan_time": r.urlscan_time,
                    "screenshot_url": r.screenshot_url,
                    "correlated_domains": r.correlated_domains,
                })
            return results

    def clear_all_scans(self) -> None:
        """Veritabanındaki tüm aktif domain tarama verilerini temizler."""
        with self.session_scope() as session:
            session.query(ActiveDomainScan).delete()
