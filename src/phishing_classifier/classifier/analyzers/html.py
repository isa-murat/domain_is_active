import re
from typing import Dict, Any, List
from phishing_classifier.enums import RiskSignalCategory
from phishing_classifier.classifier.analyzers.base import BaseAnalyzer, AnalysisResult

SUSPICIOUS_TITLE_KEYWORDS = [
    "login",
    "sign in",
    "signin",
    "giriş",
    "giris",
    "hesap doğrulama",
    "güvenlik doğrulaması",
    "account verification",
    "banka",
    "kredi kartı",
    "cüzdan",
    "wallet",
]


class HTMLRiskAnalyzer(BaseAnalyzer):
    """
    HTML DOM yapısını, Şifre kutularını, Login form varlığını ve
    Cross-Domain form action hedeflerini analiz eder.
    """

    def analyze(self, domain: str, data: Dict[str, Any]) -> AnalysisResult:
        score = 0
        signals: List[str] = []

        has_password_input = data.get("has_password_input", False)
        has_login_form = data.get("has_login_form", False)
        page_title = str(data.get("page_title") or "").strip().lower()
        redirect_url = str(data.get("redirect_url") or "").strip().lower()

        # 1. Password Input Varlığı (+30 Puan)
        if has_password_input:
            score += 30
            signals.append("HTML sayfasında Şifre Giriş Kutusu (input type=password) bulundu (+30 Puan)")

        # 2. Login Form Varlığı (+15 Puan)
        if has_login_form:
            score += 15
            signals.append("HTML sayfasında Oturum Açma Formu (<form login/signin>) tespit edildi (+15 Puan)")

        # 3. Sayfa Başlığı (Title) Duyarlı Kelime Kontrolü (+10 Puan)
        if page_title:
            for kw in SUSPICIOUS_TITLE_KEYWORDS:
                if kw in page_title:
                    score += 10
                    signals.append(f"Sayfa başlığında şüpheli kimlik avı terimi bulundu ('{kw}') (+10 Puan)")
                    break

        # 4. Cross-Domain Yönlendirme Varlığı (+15 Puan)
        if redirect_url and not redirect_url.startswith("-"):
            try:
                # Redirect URL içinde orijinal domain yoksa
                clean_domain = domain.lower().replace("www.", "")
                if clean_domain not in redirect_url:
                    score += 15
                    signals.append(f"Sayfa harici farklı bir adrese yönlendiriliyor ('{redirect_url}') (+15 Puan)")
            except Exception:
                pass

        return AnalysisResult(
            score=score,
            signals=signals,
            category=RiskSignalCategory.HTML_FORM,
        )
