from typing import Dict, Any, Tuple
from domain_is_active.collectors.dns_col import DNSCollector
from domain_is_active.collectors.whois_col import WhoisCollector
from domain_is_active.collectors.ssl_col import SSLCollector
from domain_is_active.collectors.http_col import HTTPCollector
from domain_is_active.constants.enums import ScanDecision
from domain_is_active.constants.defaults import DEFAULT_TIMEOUT_SECONDS, PARKING_NS_KEYWORDS


class PhishingDomainChecker:
    """
    Bir alan adının (domain) aktiflik durumunu, SSL, DNS, WHOIS ve HTTP sinyallerini
    toplayıp nihai karar durumunu (ScanDecision) belirleyen kontrolcü sınıf.
    """

    def __init__(self, domain: str, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.domain = domain
        self.timeout = timeout

    def evaluate_decision(self, data: Dict[str, Any]) -> Tuple[ScanDecision, str]:
        """
        Toplanan sinyallere göre alan adının nihai aktiflik kararını belirler.
        """
        # 1. WHOIS Hold Kontrolü
        if data.get("whois_hold"):
            return (
                ScanDecision.TAKEDOWN,
                "WHOIS kaydında clientHold/serverHold statüsü mevcut.",
            )

        # 2. DNS Çözümlenmeme Kontrolü
        if not data.get("dns_resolved"):
            return (
                ScanDecision.INACTIVE,
                "DNS çözümlenemiyor (A/AAAA kaydı bulunamadı).",
            )

        # 3. Park Durumu Kontrolü
        ns_servers = data.get("ns_servers", [])
        is_park_ns = any(
            any(p in str(ns).lower() for p in PARKING_NS_KEYWORDS)
            for ns in ns_servers
        )
        if data.get("parking_signature") or is_park_ns:
            return (
                ScanDecision.PARKED,
                "Alan adı park firmasını (NS) işaret ediyor veya satılık sayfası içeriyor.",
            )

        # 4. Aktif Durum Kontrolü
        http_status = data.get("http_status")
        if isinstance(http_status, int) and http_status < 400:
            return (
                ScanDecision.ACTIVE,
                f"HTTP {http_status} başarılı yanıt alındı, site canlı.",
            )

        # 5. Erişim Hataları / Belirsiz Durum
        return (
            ScanDecision.SUSPICIOUS,
            f"DNS aktif ancak web erişiminde sorun var (HTTP Status: {http_status}).",
        )

    def run(self) -> Dict[str, Any]:
        """
        Tüm toplayıcı modülleri sırayla çalıştırır ve kararla birlikte sonuçları döner.
        """
        data: Dict[str, Any] = {"domain": self.domain}

        # 1. DNS Toplama
        dns_res = DNSCollector(self.domain, timeout=self.timeout).collect()
        data.update(dns_res)

        # 2. WHOIS Toplama
        whois_res = WhoisCollector(self.domain, timeout=self.timeout).collect()
        data.update(whois_res)

        # 3. SSL Toplama
        if data.get("dns_resolved"):
            ssl_res = SSLCollector(self.domain, timeout=self.timeout).collect()
            data.update(ssl_res)
        else:
            data.update({
                "ssl_sha256": None,
                "ssl_sha1": None,
                "spki_sha256": None,
                "ssl_valid": False,
                "ssl_issuer": None,
            })

        # 4. HTTP Toplama
        if data.get("dns_resolved"):
            http_res = HTTPCollector(self.domain, timeout=self.timeout).collect()
            data.update(http_res)
        else:
            data.update({
                "http_status": None,
                "redirect_url": None,
                "page_title": None,
                "favicon_sha256": None,
                "dom_body_hash": None,
                "parking_signature": False,
            })

        # 5. Aktiflik Kararı Verme
        decision, reason = self.evaluate_decision(data)
        data["decision"] = decision
        data["reason"] = reason

        return data
