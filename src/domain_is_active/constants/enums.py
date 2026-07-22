from enum import Enum


class BaseTextChoices(str, Enum):
    """Django TextChoices mantığında çalışan temel string Enum sınıfı."""

    def __str__(self) -> str:
        return str(self.value)


class ScanDecision(BaseTextChoices):
    """Domain tarama nihai karar durumları."""

    ACTIVE = "ACTIVE (AKTIF)"
    TAKEDOWN = "TAKEDOWN (KAPATILDI)"
    INACTIVE = "INACTIVE (PASIF)"
    PARKED = "PARK EDILMIS"
    SUSPICIOUS = "SUSPICIOUS / UNSTABLE"


class RiskLevel(BaseTextChoices):
    """Phishing risk sınıflandırma seviyeleri."""

    CRITICAL = "CRITICAL PHISHING"
    HIGH = "HIGH RISK"
    MEDIUM = "SUSPICIOUS"
    LOW = "LOW RISK"
    BENIGN = "LEGITIMATE / BENIGN"


class HuntingVector(BaseTextChoices):
    """URLScan tehdit avcılığı ve korelasyon türleri."""

    FAVICON = "favicon_sha256"
    SPKI = "spki_sha256"
    IP = "page.ip"
    ASN = "page.asn"
    DOM_HASH = "response.body.hash"
    TITLE = "page.title"


class DNSStatus(BaseTextChoices):
    RESOLVED = "Evet"
    UNRESOLVED = "Hayır"


class SSLStatus(BaseTextChoices):
    VALID = "Evet"
    INVALID = "Hayır"


class ReportColors(BaseTextChoices):
    """Excel raporu için hex renk kodları."""

    TITLE_BG = "1F4E79"
    HEADER_BG = "2F5597"
    ACTIVE_BG = "C6EFCE"
    TAKEDOWN_BG = "FFEB9C"
    INACTIVE_BG = "E2EFDA"
    SUSPICIOUS_BG = "FFC7CE"
    PARKED_BG = "D9E1F2"
