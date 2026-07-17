from dns.dnssecalgs import base
from base64 import encode
import requests
import base64
import mmh3
import whois
import socket
import dns.resolver
import ssl
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
        #DNS A Save Query
        try:
            answer_a = resolver.resolve(self.domain, "A")
            for rdata in answer_a:
                self.results["ipv4_addresses"].append(rdata.address)
        except Exception:
            pass
            
        #DNS AAAA Save Query
        try:
            answer_aaaa = resolver.resolve(self.domain, "AAAA")
            for rdata in answer_aaaa:
                self.results["ipv6_adressess"].append(rdata.address)
        except Exception:
            pass
        
        #DNS NS Save Query
        try: 
            answer_ns = resolver.resolve(self.domain, "NS")
            for rdata in answer_ns:
                self.results["ns_servers"].append(rdata.target.to_text().rstrip("."))
        except Exception:
            pass

        #DNS MX Save Query
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
            with socket.create_connection((self.domain, 443),timeout=5.0) as sock:
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
                        encoding = serialization.Encoding.DER,
                        format = serialization.PublicFormat.SubjectPublicKeyInfo
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

if __name__ == "__main__":
    # Test 1: Aktif bir domain
    checker = PhishingDomainChecker("google.com")
    checker.check_dns()
    checker.check_whois_status()
    checker.check_ssl_fingerprints() 
    checker.check_favicon()
    print("Google Testi Sonucu:", checker.results)

    # Test 2: Var olmayan bir domain (Hata kontrolü için)
    checker_fake = PhishingDomainChecker("bu-domain-kesinlikle-yoktur-123.com")
    checker_fake.check_dns()
    checker_fake.check_whois_status()
    checker_fake.check_ssl_fingerprints() 
    checker_fake.check_favicon()
    print("Sahte Domain Testi Sonucu:", checker_fake.results)
