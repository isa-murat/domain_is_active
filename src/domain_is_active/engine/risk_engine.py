from typing import Dict, Any
from domain_is_active.constants.enums import ScanDecision, RiskLevel
from domain_is_active.constants.defaults import PARKING_NS_KEYWORDS


class RiskEngine:
    """
    Toplanan tüm sinyallere (DNS, WHOIS, SSL, HTTP, DOM, Visual) dayanarak
    0 ile 100 arasında Phishing Risk Skoru hesaplayan ve nihai kararı veren motor.
    """

    @staticmethod
    def calculate_risk_score(collected_data: Dict[str, Any]) -> int:
        """
        Toplanan verilerden 0-100 arası risk skoru hesaplar.
        """
        score = 0

        # DNS Çözümlenemiyorsa risk düşüktür
        if not collected_data.get("dns_resolved"):
            return 0

        # 1. SSL Sinyalleri
        if not collected_data.get("ssl_valid") and collected_data.get("spki_sha256"):
            score += 15  # Self-signed veya geçersiz SSL kullanıyor

        # 2. WHOIS Sinyalleri
        if collected_data.get("whois_hold"):
            score += 10

        # 3. HTTP & HTML/DOM Sinyalleri
        http_status = collected_data.get("http_status")
        if isinstance(http_status, int) and http_status < 400:
            score += 10  # Canlı web sitesi

        if collected_data.get("has_password_input"):
            score += 25  # HTML içinde şifre kutusu var (Phishing şüphesi yüksek)

        if collected_data.get("has_login_form"):
            score += 15  # Login/Giriş formu var

        # 4. Görsel Benzerlik Sinyalleri (pHash)
        visual_match = collected_data.get("visual_match_ratio", 0)
        if visual_match >= 85:
            score += 35  # Hedef marka ile görsel klon eşleşmesi!

        # Park sayfaları düşürülür
        if collected_data.get("parking_signature"):
            score -= 30

        return max(0, min(100, score))

    def evaluate(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Risk skoruna ve sinyallere göre nihai kararı (ScanDecision) ve risk seviyesini döner.
        """
        # 1. WHOIS Hold Kontrolü
        if collected_data.get("whois_hold"):
            return {
                "decision": ScanDecision.TAKEDOWN,
                "risk_level": RiskLevel.LOW,
                "risk_score": 0,
                "reason": "WHOIS kaydında clientHold/serverHold statüsü mevcut (Site Kapatılmış).",
            }

        # 2. DNS Kontrolü
        if not collected_data.get("dns_resolved"):
            return {
                "decision": ScanDecision.INACTIVE,
                "risk_level": RiskLevel.BENIGN,
                "risk_score": 0,
                "reason": "DNS çözümlenemiyor (A/AAAA kaydı bulunamadı).",
            }

        # 3. Park Durumu Kontrolü
        ns_servers = collected_data.get("ns_servers", [])
        is_park_ns = any(
            any(p in str(ns).lower() for p in PARKING_NS_KEYWORDS)
            for ns in ns_servers
        )
        if collected_data.get("parking_signature") or is_park_ns:
            return {
                "decision": ScanDecision.PARKED,
                "risk_level": RiskLevel.LOW,
                "risk_score": 10,
                "reason": "Alan adı park firmasını (NS) işaret ediyor veya satılık sayfası içeriyor.",
            }

        # 4. Risk Skoru ve Aktif Durum Kontrolü
        risk_score = self.calculate_risk_score(collected_data)
        http_status = collected_data.get("http_status")

        if risk_score >= 70:
            return {
                "decision": ScanDecision.ACTIVE,
                "risk_level": RiskLevel.CRITICAL,
                "risk_score": risk_score,
                "reason": f"Yüksek riskli aktif phishing sinyalleri tespit edildi (Risk Skoru: {risk_score}/100).",
            }

        if isinstance(http_status, int) and http_status < 400:
            return {
                "decision": ScanDecision.ACTIVE,
                "risk_level": RiskLevel.HIGH if risk_score >= 40 else RiskLevel.MEDIUM,
                "risk_score": risk_score,
                "reason": f"HTTP {http_status} başarılı yanıt alındı, site canlı (Risk Skoru: {risk_score}/100).",
            }

        # 5. Belirsiz / Şüpheli Durum
        return {
            "decision": ScanDecision.SUSPICIOUS,
            "risk_level": RiskLevel.MEDIUM,
            "risk_score": risk_score,
            "reason": f"DNS aktif ancak web erişiminde sorun var (HTTP Status: {http_status}).",
        }
