import re
import requests
import base64
import mmh3
import whois
import socket
import dns.resolver
import ssl
import hashlib
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Suppress insecure request warnings from requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PhishingDomainChecker:
    def __init__(self, domain: str):
        self.domain = domain
        self.results = {
            "domain": domain,
            "dns_resolved": False,
            "ipv4_addresses": [],
            "ipv6_adressess": [],
            "ns_servers": [],
            "mx_servers": [],
            "whois_hold": False,
            "whois_status": [],
            "favicon_hash": None,
            "http_status": None,
            "redirect_url": None,
            "page_title": None,
            "parking_signature": False,
            "ssl_sha256": None,
            "ssl_sha1": None,
            "spki_sha256": None,
            "ssl_valid": False,
            "ssl_issuer": None,
            "decision": "UNKNOWN",
            "reason": ""
        }
    
    def check_dns(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # DNS A Query
        try:
            answer_a = resolver.resolve(self.domain, "A")
            for rdata in answer_a:
                self.results["ipv4_addresses"].append(rdata.address)
        except Exception:
            pass
            
        # DNS AAAA Query
        try:
            answer_aaaa = resolver.resolve(self.domain, "AAAA")
            for rdata in answer_aaaa:
                self.results["ipv6_adressess"].append(rdata.address)
        except Exception:
            pass
        
        # DNS NS Query
        try: 
            answer_ns = resolver.resolve(self.domain, "NS")
            for rdata in answer_ns:
                self.results["ns_servers"].append(rdata.target.to_text().rstrip("."))
        except Exception:
            pass

        # DNS MX Query
        try:
            answer_mx = resolver.resolve(self.domain, "MX")
            for rdata in answer_mx:
                self.results["mx_servers"].append(rdata.exchange.to_text().rstrip("."))
        except Exception:
            pass
            
        if self.results["ipv4_addresses"] or self.results["ipv6_adressess"]:
            self.results["dns_resolved"] = True

    def check_whois_status(self):
        socket.setdefaulttimeout(5.0)
        try:
            w = whois.whois(self.domain)
            raw_status = w.status
            if raw_status is None:
                status_list = []
            elif isinstance(raw_status, list):
                status_list = raw_status
            else:
                status_list = [raw_status]
            self.results["whois_status"] = status_list

            for status in status_list:
                if "hold" in status.lower():
                    self.results["whois_hold"] = True
                    break
        except Exception:
            pass

    def check_ssl_fingerprints(self):
        if not self.results["dns_resolved"]:
            return
        try:
            with socket.create_connection((self.domain, 443), timeout=5.0) as sock:
                with ssl.create_default_context().wrap_socket(
                    sock,
                    server_hostname=self.domain
                ) as ssl_sock:
                    der_cert = ssl_sock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert)

                    self.results["ssl_sha256"] = hashlib.sha256(der_cert).hexdigest()
                    self.results["ssl_sha1"] = hashlib.sha1(der_cert).hexdigest()

                    public_key = cert.public_key()
                    spki_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    self.results["spki_sha256"] = hashlib.sha256(spki_bytes).hexdigest()

                    common_names = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    if common_names:
                        self.results["ssl_issuer"] = common_names[0].value
                    self.results["ssl_valid"] = True
        except Exception:
            pass

    def check_favicon(self):
        if not self.results["dns_resolved"]:
            return
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        url = f"https://{self.domain}/favicon.ico"
        try:
            response = requests.get(url, headers=headers, timeout=5.0, verify=False)
            if response.status_code == 200:
                encoded_favicon = base64.encodebytes(response.content)
                self.results["favicon_hash"] = mmh3.hash(encoded_favicon)
        except Exception:
            pass            

    def check_http(self):
        if not self.results["dns_resolved"]:
            return
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        try:
            url = f"https://{self.domain}"
            response = requests.get(url, headers=headers, timeout=5.0, verify=False)
            
            self.results["http_status"] = response.status_code
            self.results["redirect_url"] = response.url
            
            title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
            if title_match:
                self.results["page_title"] = title_match.group(1).strip()

            parking_keywords = [
                "for sale", 
                "satiliktir", 
                "satılıktır", 
                "buy this domain", 
                "under construction", 
                "bu alan adı satılıktır"
            ]
            
            html_lower = response.text.lower()
            title_lower = (self.results["page_title"] or "").lower()
            
            for keyword in parking_keywords:
                if keyword in html_lower or keyword in title_lower:
                    self.results["parking_signature"] = True
                    break
        except Exception:
            self.results["http_status"] = "CONNECTION_FAILED"
    
    def evaluate_decision(self) -> str:
        """
        Toplanan sinyallere göre alan adının durumunu belirler.
        Dönebilecek durumlar: TAKEN_DOWN, INACTIVE, PARKED, ACTIVE, SUSPICIOUS
        """
        # 1. WHOIS Hold Kontrolü (Takedown durumunu yakalamak için)
        if self.results["whois_hold"]:
            self.results["decision"] = "TAKEDOWN (KAPATILDI)"
            self.results["reason"] = "WHOIS kaydında clientHold/serverHold statüsü mevcut."
            return "TAKEDOWN (KAPATILDI)"

        # 2. DNS Çözümlenmeme Kontrolü (Pasif durumları yakalamak için)
        if not self.results["dns_resolved"]:
            self.results["decision"] = "INACTIVE (PASIF)"
            self.results["reason"] = "DNS çözümlenemiyor (A/AAAA kaydı bulunamadı)."
            return "INACTIVE (PASIF)"

        # 3. Park Durumu Kontrolü (İçerik veya NS sunucularına göre)
        is_park_ns = any(
            any(p in ns.lower() for p in ["parking", "sedo", "bodis", "parkingcrew"])
            for ns in self.results["ns_servers"]
        )
        if self.results["parking_signature"] or is_park_ns:
            self.results["decision"] = "PARKED (PARK EDILMIS)"
            self.results["reason"] = "Alan adı park firmasını (NS) işaret ediyor veya satılık sayfası içeriyor."
            return "PARKED (PARK EDILMIS)"

        # 4. Aktif Durum Kontrolü (HTTP Başarılı ise)
        status = self.results["http_status"]
        if isinstance(status, int) and status < 400:
            self.results["decision"] = "ACTIVE (AKTIF)"
            self.results["reason"] = f"HTTP {status} başarılı yanıt alındı, site canlı."
            return "ACTIVE (AKTIF)"

        # 5. Erişim Hataları veya Diğer Belirsiz Durumlar
        self.results["decision"] = "SUSPICIOUS / UNSTABLE"
        self.results["reason"] = f"DNS aktif ancak web erişiminde sorun var (HTTP Status: {status})."
        return "SUSPICIOUS / UNSTABLE"

    def run(self) -> Dict[str, Any]:
        """
        Tüm analiz adımlarını sırayla tetikler ve nihai kararla birlikte sonuçları döner.
        """
        self.check_dns()
        self.check_whois_status()
        self.check_ssl_fingerprints()
        self.check_favicon()
        self.check_http()
        self.evaluate_decision()
        return self.results

if __name__ == "__main__":
    # Test 1: Aktif bir domain
    checker = PhishingDomainChecker("wyiqm-gyaaa-aaaad-qgt6q-cai.icp0.io")
    report = checker.run()
    print("Google Testi Raporu:", report)