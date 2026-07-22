import hashlib
import re
import requests
import urllib3
from typing import Dict, Any
from domain_is_active.constants.defaults import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_USER_AGENT,
    PARKING_CONTENT_KEYWORDS,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPCollector:
    """
    HTTP/HTTPS web sayfası verilerini, başlığı, favicon hash'ini,
    DOM hash'ini ve park/login imzalarını toplayan modül.
    """

    def __init__(self, domain: str, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.domain = domain
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT}

    def _fetch_favicon(self, html_text: str) -> str:
        """Favicon SHA256 hash'ini hem varsayılan yoldan hem de HTML icon etiketinden dener."""
        favicon_sha256 = None

        # 1. Varsayılan https://domain/favicon.ico
        for proto in ["https", "http"]:
            try:
                url = f"{proto}://{self.domain}/favicon.ico"
                res = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                if res.status_code == 200 and len(res.content) > 0:
                    return hashlib.sha256(res.content).hexdigest()
            except Exception:
                pass

        # 2. HTML içindeki <link rel="icon" href="..."> etiketi
        try:
            icon_match = re.search(
                r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                html_text,
                re.IGNORECASE,
            )
            if icon_match:
                icon_href = icon_match.group(1).strip()
                if icon_href.startswith("//"):
                    icon_url = f"https:{icon_href}"
                elif icon_href.startswith("http"):
                    icon_url = icon_href
                else:
                    icon_url = f"https://{self.domain}/{icon_href.lstrip('/')}"

                res = requests.get(icon_url, headers=self.headers, timeout=self.timeout, verify=False)
                if res.status_code == 200 and len(res.content) > 0:
                    return hashlib.sha256(res.content).hexdigest()
        except Exception:
            pass

        return favicon_sha256

    def collect(self) -> Dict[str, Any]:
        results = {
            "http_status": None,
            "redirect_url": None,
            "page_title": None,
            "favicon_sha256": None,
            "dom_body_hash": None,
            "parking_signature": False,
            "has_login_form": False,
            "has_password_input": False,
        }

        response = None
        # HTTPS dene, başaramazsa HTTP fallback yap
        for proto in ["https", "http"]:
            try:
                url = f"{proto}://{self.domain}"
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if response:
                    break
            except Exception:
                continue

        if not response:
            results["http_status"] = "CONNECTION_FAILED"
            return results

        results["http_status"] = response.status_code
        results["redirect_url"] = response.url

        html_text = response.text or ""
        html_lower = html_text.lower()

        # DOM Body Hash (Korelasyon için)
        results["dom_body_hash"] = hashlib.sha256(response.content).hexdigest()

        # Page Title
        title_match = re.search(r"<title>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
        if title_match:
            results["page_title"] = title_match.group(1).strip()

        title_lower = (results["page_title"] or "").lower()

        # Park İmzası Kontrolü
        for keyword in PARKING_CONTENT_KEYWORDS:
            if keyword in html_lower or keyword in title_lower:
                results["parking_signature"] = True
                break

        # Phishing Sınıflandırma Sinyalleri (Login formu & Password input var mı?)
        if "type=\"password\"" in html_lower or "type='password'" in html_lower:
            results["has_password_input"] = True
        if "<form" in html_lower and ("login" in html_lower or "sign in" in html_lower or "giriş" in html_lower):
            results["has_login_form"] = True

        # Favicon Toplama
        results["favicon_sha256"] = self._fetch_favicon(html_text)

        return results
