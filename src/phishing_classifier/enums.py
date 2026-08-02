from enum import Enum
from domain_is_active.constants.enums import RiskLevel, BaseTextChoices


class RiskSignalCategory(BaseTextChoices):
    """Phishing risk sinyal kategorileri."""

    WHITELIST = "WHITELIST"
    HTML_FORM = "HTML_FORM"
    LEXICAL = "LEXICAL_TYPOSQUATTING"
    WHOIS = "WHOIS_SIGNAL"
    SSL_NETWORK = "SSL_NETWORK_SIGNAL"
    VISUAL_CLONE = "VISUAL_CLONE_SIGNAL"


__all__ = ["RiskLevel", "RiskSignalCategory"]

