import io
import socket
import sys
import contextlib
import whois
from typing import Dict, Any
from domain_is_active.constants.defaults import DEFAULT_TIMEOUT_SECONDS


class WhoisCollector:
    """WHOIS durum ve kayıt bilgilerini sorgulayan toplayıcı modül."""

    def __init__(self, domain: str, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.domain = domain
        self.timeout = timeout

    def collect(self) -> Dict[str, Any]:
        """
        WHOIS sunucusundan domain durum bilgilerini sorgular.
        Soket hatalarını ve python-whois kütüphanesinin konsola bastığı gürültülü
        stderr mesajlarını tam yönlendirme ile bastırır.

        Returns:
            dict: whois_hold ve whois_status sonuçları.
        """
        results = {
            "whois_hold": False,
            "whois_status": [],
            "creation_date": None,
        }

        socket.setdefaulttimeout(self.timeout)
        try:
            # python-whois kütüphanesinin WinError 10054 gibi soket hatalarını
            # doğrudan stderr/stdout'a basmasını engellemek için yönlendiriyoruz.
            buffer = io.StringIO()
            with contextlib.redirect_stderr(buffer), contextlib.redirect_stdout(buffer):
                w = whois.whois(self.domain)

            raw_status = getattr(w, "status", None)
            if raw_status is None:
                status_list = []
            elif isinstance(raw_status, list):
                status_list = [str(s) for s in raw_status]
            else:
                status_list = [str(raw_status)]

            results["whois_status"] = status_list

            for status in status_list:
                if "hold" in status.lower():
                    results["whois_hold"] = True
                    break

            if hasattr(w, "creation_date") and w.creation_date:
                c_date = w.creation_date
                if isinstance(c_date, list):
                    c_date = c_date[0]
                results["creation_date"] = str(c_date)

        except Exception:
            pass

        return results
