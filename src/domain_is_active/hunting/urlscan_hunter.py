import os
import time
import requests
from typing import Dict, Any, List, Set
from domain_is_active.constants.defaults import (
    DEFAULT_TIMEOUT_SECONDS,
    GENERIC_FAVICON_HASH_IGNORELIST,
    GENERIC_SPKI_HASH_IGNORELIST,
)


def load_env_file(env_path: str = ".env"):
    """.env dosyasını ortam değişkenlerine yükler."""
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


class URLScanHunter:
    """
    URLScan.io API üzerinden Multi-Vector (Çok Vektörlü) tehdit avcılığı ve
    geçmiş tarama sorgulama sınıfı.
    """

    _rate_limit_warned = False

    def __init__(self, api_key: str = None, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        load_env_file()
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json"}
        if self.api_key:
            self.headers["API-Key"] = self.api_key

    def get_historical_data(self, domain: str) -> Dict[str, Any]:
        """Belirtilen alan adı için URLScan.io üzerindeki geçmiş taramayı sorgular."""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])

                if results:
                    latest_scan = results[0]
                    uuid = latest_scan.get("task", {}).get("uuid")
                    scan_time = latest_scan.get("task", {}).get("time")

                    if uuid:
                        return {
                            "has_history": True,
                            "uuid": uuid,
                            "scan_time": scan_time,
                            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
                        }
            elif response.status_code == 429:
                if not URLScanHunter._rate_limit_warned:
                    print("\n[!] UYARI: URLScan.io API Rate Limit Aşıldı (HTTP 429)! Anonymous limitten dolayı arama durduruldu. Yüksek hacim için .env dosyasına URLSCAN_API_KEY ekleyin.")
                    URLScanHunter._rate_limit_warned = True
        except Exception:
            pass

        return {"has_history": False}

    def _execute_query(self, query: str) -> Set[str]:
        """Verilen URLScan arama sorgusunu çalıştırıp benzersiz domainleri döner."""
        domains = set()
        if not query:
            return domains

        url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                for item in results:
                    d = item.get("page", {}).get("domain")
                    if d:
                        domains.add(d.lower())
            elif response.status_code == 429:
                if not URLScanHunter._rate_limit_warned:
                    print("\n[!] UYARI: URLScan.io API Rate Limit Aşıldı (HTTP 429)! Anonymous limit saatlik 100 arama ile sınırlıdır. .env dosyasına URLSCAN_API_KEY ekleyin.")
                    URLScanHunter._rate_limit_warned = True
        except Exception:
            pass
        return domains

    def correlate_multi_vector(
        self,
        favicon_sha256: str = None,
        spki_hash: str = None,
        ip_address: str = None,
        dom_hash: str = None,
    ) -> List[str]:
        """
        Favicon, SPKI, IP Adresi ve DOM Body Hash parametrelerini kullanarak
        URLScan üzerinde çok vektörlü (Multi-Vector) avcılık yapar.
        """
        correlated = set()

        # 1. Favicon Avcılığı
        if favicon_sha256 and favicon_sha256 not in GENERIC_FAVICON_HASH_IGNORELIST:
            found = self._execute_query(f'hash:"{favicon_sha256}"')
            correlated.update(found)

        # 2. SSL SPKI Avcılığı
        if spki_hash and spki_hash not in GENERIC_SPKI_HASH_IGNORELIST:
            found = self._execute_query(f'ssl.cert.subject_public_key_info.sha256:"{spki_hash}"')
            correlated.update(found)

        # 3. IP Adresi Avcılığı
        if ip_address:
            found = self._execute_query(f'page.ip:"{ip_address}"')
            correlated.update(found)

        # 4. DOM Body Hash Avcılığı
        if dom_hash:
            found = self._execute_query(f'response.body.hash:"{dom_hash}"')
            correlated.update(found)

        return list(correlated)
