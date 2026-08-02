from typing import Set, Optional, List
from phishing_classifier.repository import WhitelistRepository


class WhitelistManager:
    """
    Meşru alan adı muafiyet yöneticisi.
    SADECE veritabanı (SQLite 'whitelist_domains' tablosu) ile çalışır.
    Veritabanından tek sorguda bellek önbelleğine (In-Memory Set) veri yükler
    ve O(1) hızında kontrol sağlar. N+1 DB sorgu problemini engeller.
    """

    def __init__(self, repository: Optional[WhitelistRepository] = None):
        self.repo = repository or WhitelistRepository()
        self._cached_whitelist: Set[str] = set()
        self._loaded: bool = False

    def load_whitelist(self, force_reload: bool = False) -> None:
        """
        Veritabanı tablosundaki tüm whitelist alan adlarını TEK BİR SQL SORĞUSUYLA belleğe yükler.
        """
        if self._loaded and not force_reload:
            return

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
        """Yeni bir alan adını doğrudan veritabanına ve bellek önbelleğine ekler."""
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
