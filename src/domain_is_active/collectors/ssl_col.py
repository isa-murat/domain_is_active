import hashlib
import socket
import ssl
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from domain_is_active.constants.defaults import DEFAULT_TIMEOUT_SECONDS


class SSLCollector:
    """
    SSL parmak izi ve SPKI hash bilgilerini çıkaran toplayıcı modül.
    Geçersiz veya self-signed SSL sertifikalarında bile (CERT_NONE ile)
    SPKI hash değerini sorunsuz bir şekilde elde eder.
    """

    def __init__(self, domain: str, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.domain = domain
        self.timeout = timeout

    def collect(self) -> Dict[str, Any]:
        results = {
            "ssl_sha256": None,
            "ssl_sha1": None,
            "spki_sha256": None,
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_error": None,
        }

        # Öncelik 1: Doğrulanmamış (Unverified) SSL Bağlantısı
        # Phishing sitelerinde self-signed veya süresi dolmuş cert'ler yaygın olduğundan
        # CERT_NONE kullanarak DER sertifikasını ve SPKI hash'ini her durumda çıkartıyoruz.
        try:
            unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=self.domain) as ssl_sock:
                    der_cert = ssl_sock.getpeercert(binary_form=True)
                    if der_cert:
                        cert = x509.load_der_x509_certificate(der_cert)

                        results["ssl_sha256"] = hashlib.sha256(der_cert).hexdigest()
                        results["ssl_sha1"] = hashlib.sha1(der_cert).hexdigest()

                        public_key = cert.public_key()
                        spki_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                        results["spki_sha256"] = hashlib.sha256(spki_bytes).hexdigest()

                        common_names = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                        if common_names:
                            results["ssl_issuer"] = common_names[0].value

        except Exception as e:
            results["ssl_error"] = str(e)
            return results

        # Öncelik 2: SSL'in Güvenilir/Geçerli olup olmadığını doğrulama testi
        try:
            default_ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with default_ctx.wrap_socket(sock, server_hostname=self.domain):
                    results["ssl_valid"] = True
        except Exception:
            results["ssl_valid"] = False

        return results
