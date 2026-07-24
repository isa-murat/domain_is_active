import re
from typing import Dict, Any, List
from domain_is_active.hunting.similarity import similarity_ratio
from phishing_classifier.enums import RiskSignalCategory
from phishing_classifier.classifier.analyzers.base import BaseAnalyzer, AnalysisResult

TARGET_BRANDS: List[str] = [
    "google",
    "binance",
    "garanti",
    "isbank",
    "akbank",
    "yapikredi",
    "ziraatbank",
    "halkbank",
    "vakifbank",
    "qnbfinansbank",
    "enpara",
    "btcturk",
    "paribu",
    "turkiyegovtr",
    "facebook",
    "instagram",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "spotify",
]

SUSPICIOUS_DOMAIN_KEYWORDS: List[str] = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "banking",
    "destek",
    "guncelleme",
    "musteri",
    "giris",
    "sifre",
    "wallet",
    "support",
    "service",
    "auth",
]

HIGH_RISK_TLDS: List[str] = [
    "xyz",
    "top",
    "work",
    "site",
    "click",
    "support",
    "live",
    "cc",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "buzz",
    "fit",
    "info",
]


class LexicalRiskAnalyzer(BaseAnalyzer):
    """
    Domain adı metinsel özelliklerini (Typosquatting, Levenshtein mesafe/oranı,
    şüpheli kelime eklemeleri, tire sayıları ve TLD riskleri) analiz eder.
    """

    def _extract_sld(self, domain: str) -> str:
        """Domain adının SLD (Second-Level Domain) kısmını ayıklar (Örn: 'g00gle-login.com' -> 'g00gle-login')."""
        clean = domain.strip().lower().replace("www.", "")
        parts = clean.split(".")
        if len(parts) >= 2:
            return parts[0]
        return clean

    def analyze(self, domain: str, data: Dict[str, Any]) -> AnalysisResult:
        score = 0
        signals: List[str] = []

        clean_domain = domain.strip().lower().replace("www.", "")
        sld = self._extract_sld(clean_domain)

        # Homoglyph karakter dönüşüm haritası (g00gle -> google, b1nance -> binance)
        homoglyph_map = str.maketrans("03458", "oeasb")

        # 1. Typosquatting & Levenshtein Marka Benzerliği (+35 Puan)
        sld_tokens = sld.split("-")
        matched_brand = False

        for brand in TARGET_BRANDS:
            if matched_brand:
                break
            # 1a. Tüm SLD ve alt kelimeler (tokens) üzerinden Levenshtein & Homoglyph kontrolü
            candidates = [sld] + sld_tokens
            for cand in candidates:
                if not cand:
                    continue
                
                # Homoglyph temizlenmiş versiyon (g00gle -> google)
                cand_homo = cand.translate(homoglyph_map).replace("1", "i").replace("1", "l")

                ratio_raw = similarity_ratio(cand, brand)
                ratio_homo = similarity_ratio(cand_homo, brand)
                effective_ratio = max(ratio_raw, ratio_homo)

                if (effective_ratio >= 0.65 and effective_ratio < 1.0) or (cand != brand and cand_homo == brand):
                    score += 35
                    signals.append(
                        f"Typosquatting / Görsel Homoglyph tespiti: Domain bileşeni ('{cand}') hedef marka ('{brand}') ile %{int(effective_ratio * 100)} benzer (+35 Puan)"
                    )
                    matched_brand = True
                    break
                elif brand in cand and cand != brand:
                    score += 25
                    signals.append(
                        f"Marka Taklidi: Domain adı içerisinde hedef marka ('{brand}') geçiyor (+25 Puan)"
                    )
                    matched_brand = True
                    break

        # 2. Şüpheli Phishing Kelimeleri (+20 Puan)
        for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
            if kw in sld:
                score += 20
                signals.append(f"Domain adında şüpheli kimlik avı anahtar kelimesi bulundu ('{kw}') (+20 Puan)")
                break

        # 3. Aşırı Tire (-) Kullanımı (+10 Puan)
        if sld.count("-") >= 2:
            score += 10
            signals.append(f"Domain adında aşırı tire (-) kullanımı tespit edildi ({sld.count('-')} adet) (+10 Puan)")

        # 4. Yüksek Riskli TLD Kontrolü (+10 Puan)
        parts = clean_domain.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in HIGH_RISK_TLDS:
                score += 10
                signals.append(f"Yüksek riskli TLD uzantısı kullanımı ('.{tld}') (+10 Puan)")

        return AnalysisResult(
            score=score,
            signals=signals,
            category=RiskSignalCategory.LEXICAL,
        )
