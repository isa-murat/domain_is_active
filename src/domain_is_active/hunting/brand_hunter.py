import os
import time
import requests
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional
from domain_is_active.hunting.urlscan_hunter import URLScanHunter, load_env_file
from phishing_classifier.whitelist import WhitelistManager


@dataclass
class BrandTarget:
    """Hedef kurum/marka arama konfigürasyonu."""

    name: str
    keywords: List[str]
    official_domains: List[str]
    search_query: str


# Marka avcılığı kapsamındaki 11 Hedef Kurum
TARGET_INSTITUTIONS: List[BrandTarget] = [
    BrandTarget(
        name="A101",
        keywords=["a101", "a-101"],
        official_domains=["a101.com.tr", "a101.com"],
        search_query='page.domain:*a101* OR page.title:"A101"',
    ),
    BrandTarget(
        name="Togg",
        keywords=["togg", "trumore"],
        official_domains=["togg.com.tr", "togg.com"],
        search_query='page.domain:*togg* OR page.title:"Togg" OR page.title:"Trumore"',
    ),
    BrandTarget(
        name="Borsa İstanbul",
        keywords=["borsaistanbul", "bist"],
        official_domains=["borsaistanbul.com", "borsaistanbul.com.tr", "bist.com.tr"],
        search_query='page.domain:*borsaistanbul* OR page.title:"Borsa İstanbul" OR page.title:"Borsa Istanbul"',
    ),
    BrandTarget(
        name="Garanti Bankası",
        keywords=["garanti", "garantibbva"],
        official_domains=["garanti.com.tr", "garantibbva.com.tr", "garanti.com"],
        search_query='page.domain:*garanti* OR page.title:"Garanti BBVA" OR page.title:"Garanti Bankası"',
    ),
    BrandTarget(
        name="Vakıfbank",
        keywords=["vakifbank", "vakıfbank"],
        official_domains=["vakifbank.com.tr", "vakifbank.com"],
        search_query='page.domain:*vakifbank* OR page.title:"VakıfBank" OR page.title:"Vakifbank"',
    ),
    BrandTarget(
        name="İş Bankası",
        keywords=["isbank", "isbankasi"],
        official_domains=["isbank.com.tr", "isbank.com"],
        search_query='page.domain:*isbank* OR page.title:"İş Bankası" OR page.title:"Is Bankasi"',
    ),
    BrandTarget(
        name="Takasbank",
        keywords=["takasbank"],
        official_domains=["takasbank.com.tr"],
        search_query='page.domain:*takasbank* OR page.title:"Takasbank"',
    ),
    BrandTarget(
        name="Otokoç",
        keywords=["otokoc"],
        official_domains=["otokoc.com.tr", "otokocotomotiv.com.tr"],
        search_query='page.domain:*otokoc* OR page.title:"Otokoç" OR page.title:"Otokoc"',
    ),
    BrandTarget(
        name="Azercell",
        keywords=["azercell"],
        official_domains=["azercell.com"],
        search_query='page.domain:*azercell* OR page.title:"Azercell"',
    ),
    BrandTarget(
        name="BIDV",
        keywords=["bidv"],
        official_domains=["bidv.com.vn", "bidv.com"],
        search_query='page.domain:*bidv* OR page.title:"BIDV"',
    ),
    BrandTarget(
        name="THE BODY SHOP",
        keywords=["thebodyshop"],
        official_domains=["thebodyshop.com.tr", "thebodyshop.com"],
        search_query='page.domain:*thebodyshop* OR page.title:"The Body Shop"',
    ),
]


class URLScanBrandHunter:
    """
    Belirlenen kurum/markalar için URLScan.io arama API'si üzerinden
    şüpheli ve yeni taranmış alan adlarını otomatik keşfeden tehdit avcısı.
    """

    def __init__(self, api_key: Optional[str] = None, whitelist_manager: Optional[WhitelistManager] = None):
        self.hunter = URLScanHunter(api_key=api_key)
        self.whitelist_manager = whitelist_manager or WhitelistManager()
        self.whitelist_manager.load_whitelist()

    def search_brand(self, target: BrandTarget, hours: int = 48) -> List[str]:
        """
        Tek bir marka için URLScan arama API'sinden son 'hours' saat içinde taranan
        şüpheli alan adlarını çeker.
        """
        # Sorguya zaman filtresi ekle
        date_filter = f"date:>now-{hours}h"
        query = f"({target.search_query}) AND {date_filter}"

        print(f"  [*] {target.name} markası için URLScan aranıyor (Son {hours} saat)... Query: {query}")
        raw_domains = self.hunter._execute_query(query)

        cleaned_domains: Set[str] = set()
        for d in raw_domains:
            clean_d = d.strip().lower()
            if clean_d.startswith("www."):
                clean_d = clean_d[4:]

            # 1. Whitelist (Resmi Kurum & Meşru Servisler) kontrolü
            if self.whitelist_manager.is_whitelisted(clean_d):
                continue

            # 2. Kurumun resmi domainleri ile birebir veya parent domain eşleşme kontrolü
            is_official = False
            for off_d in target.official_domains:
                if clean_d == off_d or clean_d.endswith("." + off_d):
                    is_official = True
                    break

            if not is_official:
                cleaned_domains.add(clean_d)

        print(f"  [+] {target.name} için {len(cleaned_domains)} adet şüpheli aday domain bulundu.")
        return list(cleaned_domains)

    def hunt_all(self, hours: int = 48) -> Dict[str, List[str]]:
        """
        11 kurumun tamamı için URLScan üzerinde avcılık yapar.
        Dönüş: { "Garanti Bankası": ["sahte-garanti.com", ...], ... }
        """
        print(f"\n[*] 11 Kurum İçin URLScan Marka Bazlı Tehdit Avcılığı Başlatıldı (Son {hours} saat)...")
        results: Dict[str, List[str]] = {}
        total_discovered = 0

        for target in TARGET_INSTITUTIONS:
            domains = self.search_brand(target, hours=hours)
            results[target.name] = domains
            total_discovered += len(domains)
            time.sleep(1)  # API rate limit saygısı

        print(f"\n[+] URLScan Marka Avcılığı Tamamlandı! Toplam {total_discovered} adet benzersiz şüpheli domain keşfedildi.\n")
        return results
