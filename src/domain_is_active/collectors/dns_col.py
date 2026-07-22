import dns.resolver
from typing import Dict, Any, List
from domain_is_active.constants.defaults import DEFAULT_TIMEOUT_SECONDS


class DNSCollector:
    """DNS kayıtlarını (A, AAAA, NS, MX) sorgulayan toplayıcı modül."""

    def __init__(self, domain: str, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.domain = domain
        self.timeout = timeout

    def collect(self) -> Dict[str, Any]:
        """
        DNS A, AAAA, NS ve MX kayıtlarını sorgular.
        
        Returns:
            dict: DNS sorgu sonuçları.
        """
        results = {
            "dns_resolved": False,
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "ns_servers": [],
            "mx_servers": [],
        }

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # DNS A Query
        try:
            answer_a = resolver.resolve(self.domain, "A")
            for rdata in answer_a:
                results["ipv4_addresses"].append(rdata.address)
        except Exception:
            pass

        # DNS AAAA Query
        try:
            answer_aaaa = resolver.resolve(self.domain, "AAAA")
            for rdata in answer_aaaa:
                results["ipv6_addresses"].append(rdata.address)
        except Exception:
            pass

        # DNS NS Query
        try:
            answer_ns = resolver.resolve(self.domain, "NS")
            for rdata in answer_ns:
                results["ns_servers"].append(rdata.target.to_text().rstrip("."))
        except Exception:
            pass

        # DNS MX Query
        try:
            answer_mx = resolver.resolve(self.domain, "MX")
            for rdata in answer_mx:
                results["mx_servers"].append(rdata.exchange.to_text().rstrip("."))
        except Exception:
            pass

        if results["ipv4_addresses"] or results["ipv6_addresses"]:
            results["dns_resolved"] = True

        return results
