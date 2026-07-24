from typing import Dict, Any, List
from phishing_classifier.enums import RiskSignalCategory
from phishing_classifier.classifier.analyzers.base import BaseAnalyzer, AnalysisResult


class WhoisRiskAnalyzer(BaseAnalyzer):
    """
    WHOIS hold durumlarını, domain tescil kısıtlamalarını (TAKEDOWN),
    domain yaşını ve Gizlilik Koruması sinyallerini analiz eder.
    """

    def analyze(self, domain: str, data: Dict[str, Any]) -> AnalysisResult:
        score = 0
        signals: List[str] = []

        whois_hold = str(data.get("whois_hold", "Hayır")).strip().lower()
        decision = str(data.get("decision") or "").strip().upper()
        domain_age_days = data.get("domain_age_days")
        has_privacy_guard = data.get("has_privacy_guard", False)

        # 1. WHOIS Hold & TAKEDOWN Durumu (+40 Puan)
        if whois_hold in ["evet", "true", "hold"] or "TAKEDOWN" in decision:
            score += 40
            signals.append("WHOIS tescil kısıtlaması / Kapatılma Kararı (TAKEDOWN / clientHold / serverHold) tespiti (+40 Puan)")

        # 2. Alan Adı Yaşı Sinyalleri (+25 veya +15 Puan)
        if domain_age_days is not None and isinstance(domain_age_days, (int, float)):
            if domain_age_days < 30:
                score += 25
                signals.append(f"Çok yeni kaydedilmiş alan adı ({int(domain_age_days)} günlük < 30 gün) (+25 Puan)")
            elif domain_age_days < 90:
                score += 15
                signals.append(f"Yeni kaydedilmiş alan adı ({int(domain_age_days)} günlük < 90 gün) (+15 Puan)")

        # 3. Privacy Proxy / Privacy Guard Varlığı (+10 Puan)
        if has_privacy_guard:
            score += 10
            signals.append("WHOIS verilerinde Gizlilik Koruması (Privacy Protection / Proxy) kullanımı (+10 Puan)")

        return AnalysisResult(
            score=score,
            signals=signals,
            category=RiskSignalCategory.WHOIS,
        )
