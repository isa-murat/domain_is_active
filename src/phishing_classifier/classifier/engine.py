from typing import Dict, Any, List, Optional
from phishing_classifier.enums import RiskLevel
from phishing_classifier.whitelist import WhitelistManager
from phishing_classifier.repository import PhishingRiskRepository
from phishing_classifier.classifier.analyzers import (
    BaseAnalyzer,
    HTMLRiskAnalyzer,
    LexicalRiskAnalyzer,
    WhoisRiskAnalyzer,
    SSLNetworkRiskAnalyzer,
)


class PhishingRiskClassifier:
    """
    Phishing Risk Sınıflandırma ve Skorlama Facade Motoru.
    Girdi olarak toplanan domain veri vektörlerini işler, Whitelist kontrolü yapar,
    0-100 Ağırlıklı Risk Puanı hesaplar ve RiskLevel belirler.
    """

    def __init__(
        self,
        whitelist_manager: Optional[WhitelistManager] = None,
        repository: Optional[PhishingRiskRepository] = None,
        analyzers: Optional[List[BaseAnalyzer]] = None,
    ):
        self.whitelist_manager = whitelist_manager or WhitelistManager()
        self.repo = repository or PhishingRiskRepository()
        self.analyzers = analyzers or [
            LexicalRiskAnalyzer(),
            HTMLRiskAnalyzer(),
            WhoisRiskAnalyzer(),
            SSLNetworkRiskAnalyzer(),
        ]

    def _determine_risk_level(self, score: int) -> RiskLevel:
        """Risk puanını RiskLevel Enum seviyesine eşler."""
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 55:
            return RiskLevel.HIGH
        elif score >= 30:
            return RiskLevel.MEDIUM
        elif score >= 10:
            return RiskLevel.LOW
        else:
            return RiskLevel.BENIGN

    def classify(self, domain: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Tekil bir alan adı için risk analizini gerçekleştirir.
        """
        if data is None:
            data = {}

        clean_domain = domain.strip().lower()

        # 1. Whitelist Muafiyet Kontrolü
        if self.whitelist_manager.is_whitelisted(clean_domain):
            assessment = {
                "domain": clean_domain,
                "risk_score": 0,
                "risk_level": RiskLevel.BENIGN.value,
                "is_whitelisted": "Evet",
                "triggered_signals": [
                    "Alan adı meşru Whitelist (Top 10K / Veritabanı) tablosunda kayıtlıdır (Risk Muafiyeti)."
                ],
            }
            self.repo.save_assessment(assessment)
            return assessment

        # 2. Vektör Analizörlerinin Çalıştırılması
        total_score = 0
        all_signals: List[str] = []

        for analyzer in self.analyzers:
            try:
                res = analyzer.analyze(clean_domain, data)
                total_score += res.score
                all_signals.extend(res.signals)
            except Exception as e:
                all_signals.append(f"Analizör hatası ({analyzer.__class__.__name__}): {str(e)}")

        # 3. Puan Sınırlama (0 - 100)
        final_score = min(100, max(0, total_score))
        risk_level = self._determine_risk_level(final_score)

        if not all_signals:
            all_signals.append("Herhangi bir belirgin phishing tehdit sinyali tespit edilmedi.")

        assessment = {
            "domain": clean_domain,
            "risk_score": final_score,
            "risk_level": risk_level.value,
            "is_whitelisted": "Hayır",
            "triggered_signals": all_signals,
        }

        # 4. Veritabanına Kaydetme (UPSERT)
        self.repo.save_assessment(assessment)
        return assessment

    def classify_batch(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Toplu domain veri listesi üzerinde N+1 DB sorgu problemi olmaksızın
        hızlı risk analizi yapar.
        """
        # Whitelist'i tek sorguda RAM'e yükle
        self.whitelist_manager.load_whitelist()

        results: List[Dict[str, Any]] = []
        for rec in records:
            domain = rec.get("domain", "")
            if not domain:
                continue
            assessment = self.classify(domain=domain, data=rec)
            results.append(assessment)

        return results
