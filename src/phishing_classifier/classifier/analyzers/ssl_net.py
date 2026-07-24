from typing import Dict, Any, List
from phishing_classifier.enums import RiskSignalCategory
from phishing_classifier.classifier.analyzers.base import BaseAnalyzer, AnalysisResult

FREE_DV_ISSUERS = [
    "let's encrypt",
    "zerossl",
    "cpanel",
    "buypass",
    "r3",
    "r10",
    "r11",
    "e1",
    "e2",
    "google trust services",
]


class SSLNetworkRiskAnalyzer(BaseAnalyzer):
    """
    SSL sertifikasının geçerliliğini, yayıncı türünü (DV vs OV/EV),
    SPKI hash durumunu ve ağ yönlendirme şüphelerini analiz eder.
    """

    def analyze(self, domain: str, data: Dict[str, Any]) -> AnalysisResult:
        score = 0
        signals: List[str] = []

        ssl_valid = str(data.get("ssl_valid", "Hayır")).strip().lower()
        ssl_issuer = str(data.get("ssl_issuer") or "").strip().lower()
        spki_sha256 = str(data.get("spki_sha256") or "").strip().lower()
        http_status = str(data.get("http_status") or "").strip()

        # 1. SSL Geçersizliği / Self-signed Sertifika (+15 Puan)
        if ssl_valid in ["hayır", "no", "false", "invalid"]:
            score += 15
            signals.append("SSL sertifikası geçersiz, doğrulanamadı veya kendinden imzalı (self-signed) (+15 Puan)")

        # 2. Ücretsiz Kısa Süreli DV SSL Kullanımı (+15 Puan)
        if ssl_issuer and ssl_issuer != "-":
            for issuer_kw in FREE_DV_ISSUERS:
                if issuer_kw in ssl_issuer:
                    score += 15
                    signals.append(f"Ücretsiz kısa süreli DV SSL yayıncısı kullanımı ('{ssl_issuer}') (+15 Puan)")
                    break

        # 3. HTTP Bağlantı Hatası / Şüpheli Durum Kodu (+10 Puan)
        if http_status in ["CONNECTION_FAILED", "500", "502", "503"]:
            score += 10
            signals.append(f"Şüpheli HTTP ağ yanıtı tespiti ('{http_status}') (+10 Puan)")

        return AnalysisResult(
            score=score,
            signals=signals,
            category=RiskSignalCategory.SSL_NETWORK,
        )
