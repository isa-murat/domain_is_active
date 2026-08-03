import datetime
import os
import re
from typing import List, Dict, Any, Optional
import pandas as pd

from domain_is_active.constants.enums import ScanDecision, RiskLevel
from domain_is_active.hunting.brand_hunter import TARGET_INSTITUTIONS


class CSVExporter:
    """
    Batuhan Aydos özel formatına uygun 6 sütunlu CSV rapor üreticisi:
    Sütunlar: ["Şirket", "Domain", "Durum", "Sunucu IP", "Son görülme", "Kötü niyetli işaret"]
    """

    def __init__(
        self,
        results: List[Dict[str, Any]],
        phishing_results: Optional[List[Dict[str, Any]]] = None,
        domain_company_map: Optional[Dict[str, str]] = None,
    ):
        self.results = results
        self.phishing_results = phishing_results or []
        self.domain_company_map = domain_company_map or {}

        # Domain -> Phishing Risk Result Hızlı Erişim Haritası
        self.phishing_map: Dict[str, Dict[str, Any]] = {}
        for p in self.phishing_results:
            d = p.get("domain", "").lower()
            if d:
                self.phishing_map[d] = p

    def _resolve_company(self, domain: str, raw_record: Dict[str, Any]) -> str:
        """Domain için hedef kurum adını tespit eder."""
        domain_clean = domain.lower()

        # 1. Önceden Haritalanmış Marka Avcısı Bilgisi
        if domain_clean in self.domain_company_map:
            return self.domain_company_map[domain_clean]

        # 2. Kayıtta Varsa
        if raw_record.get("company"):
            return raw_record["company"]
        if raw_record.get("Şirket"):
            return raw_record["Şirket"]

        # 3. Target Institutions Kurum Taraması ile Eşleştirme
        for target in TARGET_INSTITUTIONS:
            for kw in target.keywords:
                if kw in domain_clean:
                    return target.name

        return "Bilinmiyor / Genel"

    def _determine_status(self, raw_record: Dict[str, Any]) -> str:
        """Canlılık durumunu 'AKTİF' veya 'PASİF' olarak belirler."""
        decision = str(raw_record.get("decision", "")).upper()
        dns_resolved = str(raw_record.get("dns_resolved", "")).lower() in ["evet", "true"]
        http_status = str(raw_record.get("http_status", ""))

        if "INACTIVE" in decision or "TAKEDOWN" in decision or "PASİF" in decision:
            return "PASİF"

        if "ACTIVE" in decision or "AKTİF" in decision or (dns_resolved and http_status in ["200", "301", "302", "307", "308"]):
            return "AKTİF"

        return "PASİF"

    def _determine_malicious(self, domain: str, raw_record: Dict[str, Any]) -> str:
        """Kötü niyetli işaret durumunu 'Evet' veya 'Hayır' olarak belirler."""
        phishing_info = self.phishing_map.get(domain.lower(), {})
        risk_score = int(phishing_info.get("risk_score", 0))
        risk_level = str(phishing_info.get("risk_level", "")).upper()

        has_password = str(raw_record.get("has_password_input", "")).lower() == "evet"
        has_login = str(raw_record.get("has_login_form", "")).lower() == "evet"

        if risk_score >= 55 or risk_level in ["CRITICAL", "HIGH"] or has_password or has_login:
            return "Evet"
        return "Hayır"

    def export(self, output_path: str = None, silent: bool = False) -> str:
        """
        Batuhan Aydos özel CSV formatındaki raporu üretir ve `utf-8-sig` (UTF-8 BOM) ile kaydeder.
        """
        if not output_path:
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join("reports", f"phishing_analysis_report_{timestamp_str}.csv")

        # Uzantının .csv olmasını garanti et
        if not output_path.lower().endswith(".csv"):
            output_path = os.path.splitext(output_path)[0] + ".csv"

        abs_output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output_path), exist_ok=True)

        if not silent:
            print(f"[*] CSV raporu oluşturuluyor: {abs_output_path}")

        rows = []
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for rec in self.results:
            domain = rec.get("domain", "")
            if not domain:
                continue

            company = self._resolve_company(domain, rec)
            status = self._determine_status(rec)
            ip_addr = rec.get("ipv4_addresses") or rec.get("Sunucu IP") or "-"
            if not ip_addr or ip_addr == "":
                ip_addr = "-"

            last_seen = rec.get("urlscan_time") or rec.get("Son görülme") or now_str
            if last_seen == "-":
                last_seen = now_str

            malicious = self._determine_malicious(domain, rec)

            rows.append({
                "Şirket": company,
                "Domain": domain,
                "Durum": status,
                "Sunucu IP": ip_addr,
                "Son görülme": last_seen,
                "Kötü niyetli işaret": malicious,
            })

        df = pd.DataFrame(rows)
        if df.empty:
            df = pd.DataFrame(columns=["Şirket", "Domain", "Durum", "Sunucu IP", "Son görülme", "Kötü niyetli işaret"])

        # UTF-8 BOM (utf-8-sig) ile kaydet ki Excel Türkçe karakterleri kusursuz açsın
        df.to_csv(abs_output_path, index=False, encoding="utf-8-sig")

        if not silent:
            print(f"[+] CSV raporu başarıyla kaydedildi: {abs_output_path}")

        return abs_output_path
