import os
import requests
from typing import Dict, Any, List

def load_env_file(env_path: str = ".env"):
    """.env dosyasını otomatik okur ve ortam değişkenlerine yükler."""
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
    def __init__(self, api_key: str = None):
        """
        URLScan.io API ile haberleşen tehdit avcılığı ve geçmiş sorgulama sınıfı.
        .env dosyasında veya ortam değişkeninde API Key yoksa anonim tarama yapar.
        """
        load_env_file()
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")
        self.headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            self.headers["API-Key"] = self.api_key

    def get_historical_data(self, domain: str) -> Dict[str, Any]:
        """
        Belirtilen alan adı için URLScan.io üzerindeki geçmiş tarama verilerini sorgular.
        
        Args:
            domain (str): Geçmişi sorgulanacak alan adı.
            
        Returns:
            dict: Tarama geçmişi varsa detayları, yoksa {"has_history": False} döner.
        """
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        
        try:
            # AGENTS.md: Sadece GET isteği, 5 saniye timeout
            response = requests.get(url, headers=self.headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                
                if results:
                    # En son yapılan başarılı taramayı alıyoruz (listenin ilk elemanı)
                    latest_scan = results[0]
                    uuid = latest_scan.get("task", {}).get("uuid")
                    scan_time = latest_scan.get("task", {}).get("time")
                    
                    if uuid:
                        return {
                            "has_history": True,
                            "uuid": uuid,
                            "scan_time": scan_time,
                            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png"
                        }
        except Exception:
            pass
            
        return {"has_history": False}

    def correlate_fingerprints(self, favicon_sha256: str = None, spki_hash: str = None) -> List[str]:
        """
        Favicon veya SPKI parmak izlerini kullanarak URLScan.io üzerinde ters arama (reverse search) yapar.
        Aynı parmak izini paylaşan ilişkili domainleri tespit eder.
        
        Args:
            favicon_sha256 (str, optional): Favicon SHA-256 değeri.
            spki_hash (str, optional): SSL SPKI SHA256 değeri.
            
        Returns:
            list[str]: Aynı parmak izini kullanan benzersiz domainlerin listesi.
        """
        query = ""
        if favicon_sha256:
            query = f'hash:"{favicon_sha256}"'
        elif spki_hash:
            query = f'ssl.cert.subject_public_key_info.sha256:"{spki_hash}"'
        
        if not query:
            return []

        # En fazla 100 sonuç çekmek için size parametresini ekliyoruz
        url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
        correlated_domains = set()

        try:
            # AGENTS.md: Sadece GET isteği, 5 saniye timeout
            response = requests.get(url, headers=self.headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                
                for item in results:
                    domain = item.get("page", {}).get("domain")
                    if domain:
                        correlated_domains.add(domain)
        except Exception:
            pass

        return list(correlated_domains)

if __name__ == "__main__":
    # Test bloğu
    hunter = URLScanHunter()
    
    # Test 1: Geçmiş Tarama Sorgulama
    test_domain = "serce101hizmeti.duckdns.org"
    print(f"[*] {test_domain} için URLScan geçmişi sorgulanıyor...")
    history = hunter.get_historical_data(test_domain)
    print("Geçmiş Tarama Sonucu:", history)
    
    # Test 2: Favicon ile Tersine Arama (Threat Hunting)
    # Google'ın favicon SHA-256 hash'ini sorgulayalım (biliyoruz ki sonuç dönüyor)
    test_favicon_sha256 = "6da5620880159634213e197fafca1dde0272153be3e4590818533fab8d040770"
    print(f"\n[*] Favicon SHA-256 ({test_favicon_sha256}) ile ilişkili domainler aranıyor...")
    related_domains = hunter.correlate_fingerprints(favicon_sha256=test_favicon_sha256)
    print(f"Bulunan İlişkili Domain Sayısı: {len(related_domains)}")
    print("İlişkili Domainler:", related_domains[:10], "..." if len(related_domains) > 10 else "")