import re
from typing import Dict, Any, List
from domain_is_active.hunting.similarity import similarity_ratio
from phishing_classifier.enums import RiskSignalCategory
from phishing_classifier.classifier.analyzers.base import BaseAnalyzer, AnalysisResult

TARGET_BRANDS: List[str] = [
    # Finans / Bankacılık / Kripto
    "google",
    "binance",
    "garanti",
    "isbank",
    "akbank",
    "yapikredi",
    "ziraatbank",
    "ziraat",
    "halkbank",
    "vakifbank",
    "vakif",
    "qnbfinansbank",
    "finansbank",
    "enpara",
    "ingbank",
    "ing",
    "denizbank",
    "teb",
    "sekerbank",
    "fibabanka",
    "odeabank",
    "kuveytturk",
    "albaraka",
    "papara",
    "payfix",
    "btcturk",
    "paribu",
    "troy",
    "gratis",
    "bybit",
    "gateio",
    "mexc",
    "okx",
    "metamask",
    "phantom",
    "ledger",
    "paypal",
    # E-Devlet & Kamu
    "turkiyegovtr",
    "turkiye",
    "edevlet",
    "gib",
    "sgk",
    "mhrs",
    # Telekom & Kargo
    "turkcell",
    "vodafone",
    "turktelekom",
    "ptt",
    "pttkargo",
    "araskargo",
    "yurticikargo",
    # E-Ticaret & Portal
    "sahibinden",
    "trendyol",
    "hepsiburada",
    "n11",
    "getir",
    "ciceksepeti",
    "togg",
    # Global Markalar
    "facebook",
    "instagram",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "spotify",
    "outlook",
]

DYNDNS_PROVIDERS: List[str] = [
    "duckdns.org",
    "ngrok-free.app",
    "ngrok.io",
    "myonlineportal.ch",
    "serveo.net",
    "trycloudflare.com",
    "firebaseapp.com",
    "vercel.app",
    "github.io",
    "pages.dev",
    "000webhostapp.com",
    "webnode.page",
    "wixsite.com",
]

SUSPICIOUS_DOMAIN_KEYWORDS: List[str] = [
    # Oltalama & Kimlik Avı Terimleri
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
    "onlinegir",
    "gir",
    "sifre",
    "wallet",
    "support",
    "service",
    "auth",
    "promosyon",
    "prmsyn",
    "entry",
    "kapisi",
    "mobil",
    "esube",
    "sube",
    "yatirim",
    "iletisim",
    "yardim",
    "hesap",
    # Bahis & Kumar Terimleri
    "bet",
    "slot",
    "casino",
    "poker",
    "bonus",
    "bahis",
    "rulet",
    "jackpot",
    # Hediye & Çekiliş Terimleri
    "kupon",
    "hediye",
    "cekilis",
    "indirim",
    "firsat",
    "kampanya",
    "fatura",
    "odeme",
    "paket",
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
    "casa",
    "cfd",
    "online",
    "vip",
    "pro",
    "life",
    "today",
    "sbs",
    "gifts",
    "moe",
    "fun",
    "tech",
    "club",
    "app",
]


def strip_vowels(s: str) -> str:
    """Metindeki tüm sesli harfleri düşürür (Ünsüz İskeleti). Örn: 'garanti' -> 'grnt'."""
    return re.sub(r"[aeıioöuü]", "", s.lower())


class LexicalRiskAnalyzer(BaseAnalyzer):
    """
    Domain adı metinsel özelliklerini (Typosquatting, Levenshtein, Homoglyph,
    Ünsüz İskeleti, DynDNS tünelleri ve TLD riskleri) analiz eder.
    """

    def _extract_sld(self, domain: str) -> str:
        """Domain adının SLD (Second-Level Domain) kısmını ayıklar."""
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

        # 0. DynDNS / Ücretsiz Tünel Sağlayıcı Alt Domain Kontrolü (+30 Puan)
        for provider in DYNDNS_PROVIDERS:
            if clean_domain.endswith("." + provider) or clean_domain == provider:
                score += 30
                signals.append(f"İstismar edilen Ücretsiz Dinamik DNS / Tünel Sağlayıcı kullanımı ('{provider}') (+30 Puan)")
                break

        # Homoglyph karakter dönüşüm haritası (g00gle -> google, b1nance -> binance)
        homoglyph_map = str.maketrans("03458", "oeasb")

        # 1. Typosquatting & Levenshtein & Ünsüz İskeleti Kontrolü (+35 / +30 / +25 Puan)
        sld_tokens = sld.split("-")
        matched_brand = False

        for brand in TARGET_BRANDS:
            if matched_brand:
                break

            brand_skeleton = strip_vowels(brand)

            candidates = [sld] + sld_tokens
            for cand in candidates:
                if not cand or len(cand) < 2:
                    continue

                # Homoglyph temizlenmiş versiyon
                cand_homo = cand.translate(homoglyph_map).replace("1", "i").replace("1", "l")

                ratio_raw = similarity_ratio(cand, brand)
                ratio_homo = similarity_ratio(cand_homo, brand)
                effective_ratio = max(ratio_raw, ratio_homo)

                # 1a. Levenshtein / Homoglyph Eşleşmesi
                if (effective_ratio >= 0.65 and effective_ratio < 1.0) or (cand != brand and cand_homo == brand):
                    score += 35
                    signals.append(
                        f"Typosquatting / Görsel Homoglyph tespiti: Domain bileşeni ('{cand}') hedef marka ('{brand}') ile %{int(effective_ratio * 100)} benzer (+35 Puan)"
                    )
                    matched_brand = True
                    break

                # 1b. Birebir Marka İçerme (3 harfli kısa markalarda kelime içi -ing eki gibi yanlış eşleşmeleri engelle)
                elif brand in cand and cand != brand:
                    if len(brand) <= 3 and not (cand.startswith(brand + "-") or cand.endswith("-" + brand) or f"-{brand}-" in f"-{cand}-"):
                        # 'voting', 'notebook' gibi kelimelerin içindeki 3 harfli kısa marka alt dizelerini atla!
                        continue
                    if len(brand) >= 3:
                        score += 25
                        signals.append(
                            f"Marka Taklidi: Domain adı içerisinde hedef marka ('{brand}') geçiyor (+25 Puan)"
                        )
                        matched_brand = True
                        break

                # 1c. Ünsüz İskeleti (Consonant Skeleton) Eşleşmesi (Örn: 'grnt' vs 'grnt')
                elif len(brand_skeleton) >= 3:
                    cand_skeleton = strip_vowels(cand)
                    if cand_skeleton == brand_skeleton and cand != brand:
                        score += 30
                        signals.append(
                            f"Sesli Harf Düşürme (Consonant Skeleton) Typosquatting: '{cand}' bileşeni '{brand}' markasının ünsüz iskeletini ('{brand_skeleton}') taklit ediyor (+30 Puan)"
                        )
                        matched_brand = True
                        break

        # 2. Şüpheli Phishing & Bahis Kelimeleri (+20 Puan)
        for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
            if kw in sld:
                score += 20
                signals.append(f"Domain adında şüpheli kimlik avı / bahis anahtar kelimesi bulundu ('{kw}') (+20 Puan)")
                break

        # 3. Aşırı Tire (-) Kullanımı (+10 Puan)
        if sld.count("-") >= 2:
            score += 10
            signals.append(f"Domain adında aşırı tire (-) kullanımı tespit edildi ({sld.count('-')} adet) (+10 Puan)")

        # 4. Yüksek Riskli TLD Kontrolü (+15 Puan)
        parts = clean_domain.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in HIGH_RISK_TLDS:
                score += 15
                signals.append(f"Yüksek riskli TLD uzantısı kullanımı ('.{tld}') (+15 Puan)")

        # 5. Pasif / Erişilemeyen Phishing Domain Risk Takviyesi (+20 Puan)
        http_status = str(data.get("http_status") or "").strip()
        if matched_brand and http_status in ["CONNECTION_FAILED", "INACTIVE (PASIF)"]:
            score += 20
            signals.append("Erişilemeyen / Pasif Kapanmış Phishing Kampanyası Ek Risk Takviyesi (+20 Puan)")

        return AnalysisResult(
            score=score,
            signals=signals,
            category=RiskSignalCategory.LEXICAL,
        )
