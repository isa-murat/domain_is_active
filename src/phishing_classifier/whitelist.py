from typing import Set, Optional, List
from phishing_classifier.repository import WhitelistRepository

DEFAULT_WHITELIST_SEED: List[str] = [
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
    "turkiye.gov.tr",
    "egov.tr",
    "garanti.com.tr",
    "isbank.com.tr",
    "akbank.com",
    "yapikredi.com.tr",
    "ziraatbank.com.tr",
    "halkbank.com.tr",
    "vakifbank.com.tr",
    "qnbfinansbank.com",
    "enpara.com",
    "binance.com",
    "btcturk.com",
    "paribu.com",
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

        # Seed check
        self.repo.seed_default_whitelist(DEFAULT_WHITELIST_SEED)
        self._cached_whitelist = self.repo.get_all_domains_set()
        self._loaded = True

    def is_whitelisted(self, domain: str) -> bool:
        """
        Alan adının veya üst alan adının (Parent Domain / eTLD+1) whitelist'te olup olmadığını doğrular.
        Örn: 'subdomain.garanti.com.tr' -> 'garanti.com.tr' veya 'google.com' kontrol edilir.
        """
        if not self._loaded:
            self.load_whitelist()

        if not domain:
            return False

        clean_domain = domain.strip().lower()

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
