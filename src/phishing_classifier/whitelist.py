from typing import Set, Optional, List
from phishing_classifier.repository import WhitelistRepository

DEFAULT_WHITELIST_SEED: List[str] = [
    # Finans / Bankacılık / Kripto
    "garanti.com.tr",
    "garantibbva.com.tr",
    "garantibbva.com",
    "isbank.com.tr",
    "isbank.com",
    "akbank.com",
    "yapikredi.com.tr",
    "ziraatbank.com.tr",
    "ziraat.com.tr",
    "halkbank.com.tr",
    "vakifbank.com.tr",
    "qnbfinansbank.com",
    "finansbank.com",
    "denizbank.com",
    "teb.com.tr",
    "ing.com.tr",
    "kuveytturk.com.tr",
    "albaraka.com.tr",
    "sekerbank.com.tr",
    "fibabanka.com.tr",
    "odeabank.com.tr",
    "enpara.com",
    "papara.com",
    "payfix.com.tr",
    "troyodeme.com",
    "binance.com",
    "btcturk.com",
    "paribu.com",
    # E-Devlet & Kamu & Kurumlar
    "turkiye.gov.tr",
    "egov.tr",
    "edevlet.gov.tr",
    "gib.gov.tr",
    "sgk.gov.tr",
    "mhrs.gov.tr",
    "togg.com.tr",
    # Telekom & Kargo
    "turkcell.com.tr",
    "vodafone.com.tr",
    "turktelekom.com.tr",
    "ptt.gov.tr",
    "pttkargo.com.tr",
    # E-Ticaret
    "sahibinden.com",
    "trendyol.com",
    "hepsiburada.com",
    "n11.com",
    "getir.com",
    "ciceksepeti.com",
    # Global Popüler Servisler
    "google.com",
    "youtube.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "cloudflare.com",
    "openai.com",
    "anthropic.com",
    "steampowered.com",
    "netflix.com",
    "spotify.com",
    "outlook.com",
    "live.com",
    "office.com",
    "gmail.com",
]


class WhitelistManager:
    """
    Meşru alan adı muafiyet yöneticisi.
    Veritabanından tek sorguda bellek önbelleğine (In-Memory Set) veri yükler
    ve O(1) hızında kontrol sağlar. N+1 DB sorgu problemini engeller.
    """

    def __init__(self, repository: Optional[WhitelistRepository] = None):
        self.repo = repository or WhitelistRepository()
        self._cached_whitelist: Set[str] = set()
        self._loaded: bool = False

    def load_whitelist(self, force_reload: bool = False) -> None:
        """
        Veritabanından tüm whitelist alan adlarını TEK BİR SQL SORĞUSUYLA belleğe yükler.
        Eğer veritabanı boşsa varsayılan meşru seed listesini veritabanına ekler.
        """
        if self._loaded and not force_reload:
            return

        # Seed check & load
        self.repo.seed_default_whitelist(DEFAULT_WHITELIST_SEED)
        
        # Ek olarak varsayılan seed domainlerin veritabanında eksik kalanlarını da ekle
        with self.repo.session_scope() as session:
            from phishing_classifier.models import WhitelistDomain
            existing_set = self.repo.get_all_domains_set()
            missing = [
                WhitelistDomain(domain=d.strip().lower(), source="Tranco Top 10K Seed")
                for d in DEFAULT_WHITELIST_SEED
                if d.strip().lower() not in existing_set
            ]
            if missing:
                session.add_all(missing)

        self._cached_whitelist = self.repo.get_all_domains_set()
        self._loaded = True

    def is_whitelisted(self, domain: str) -> bool:
        """
        Alan adının veya üst alan adının (Parent Domain / eTLD+1) whitelist'te olup olmadığını doğrular.
        Örn: 'www.garantibbva.com.tr' -> 'garantibbva.com.tr' kontrol edilir.
        """
        if not self._loaded:
            self.load_whitelist()

        if not domain:
            return False

        clean_domain = domain.strip().lower()
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]

        # 1. Tam Eşleşme
        if clean_domain in self._cached_whitelist:
            return True

        # 2. Subdomain / Parent Domain Eşleşmesi
        parts = clean_domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._cached_whitelist:
                return True

        return False

    def add_domain(self, domain: str, source: str = "Manual Add") -> None:
        """Yeni bir alan adını veritabanına ve bellek önbelleğine ekler."""
        clean_domain = domain.strip().lower()
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]

        if not clean_domain:
            return

        if clean_domain in self._cached_whitelist:
            return

        from phishing_classifier.models import WhitelistDomain

        with self.repo.session_scope() as session:
            existing = session.query(WhitelistDomain).filter(WhitelistDomain.domain == clean_domain).first()
            if not existing:
                entry = WhitelistDomain(domain=clean_domain, source=source)
                session.add(entry)

        self._cached_whitelist.add(clean_domain)
