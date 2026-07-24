import os
import pytest
from phishing_classifier.enums import RiskLevel
from phishing_classifier.whitelist import WhitelistManager
from phishing_classifier.models import PhishingRiskAssessment, WhitelistDomain
from phishing_classifier.repository import PhishingRiskRepository, WhitelistRepository
from phishing_classifier.classifier.analyzers import (
    HTMLRiskAnalyzer,
    LexicalRiskAnalyzer,
    WhoisRiskAnalyzer,
    SSLNetworkRiskAnalyzer,
)
from phishing_classifier.classifier.engine import PhishingRiskClassifier
from domain_is_active.exporters.excel import ExcelExporter


def test_whitelist_manager():
    wm = WhitelistManager()
    wm.load_whitelist()

    assert wm.is_whitelisted("google.com") is True
    assert wm.is_whitelisted("subdomain.garanti.com.tr") is True
    assert wm.is_whitelisted("totally-unknown-suspicious-domain-123.xyz") is False

    wm.add_domain("custom-whitelisted-domain.com")
    assert wm.is_whitelisted("custom-whitelisted-domain.com") is True


def test_html_risk_analyzer():
    analyzer = HTMLRiskAnalyzer()
    data = {
        "has_password_input": True,
        "has_login_form": True,
        "page_title": "Hesap Doğrulama ve Giriş Yap",
        "redirect_url": "https://external-phishing-host.com/login",
    }
    result = analyzer.analyze("fake-banka.com", data)
    assert result.score >= 50
    assert len(result.signals) >= 3


def test_lexical_risk_analyzer():
    analyzer = LexicalRiskAnalyzer()
    
    # Typosquatting + keyword + high risk TLD
    data = {}
    res = analyzer.analyze("g00gle-login-verify.xyz", data)
    assert res.score >= 50
    assert any("Typosquatting" in s for s in res.signals)
    assert any("TLD" in s for s in res.signals)


def test_whois_risk_analyzer():
    analyzer = WhoisRiskAnalyzer()
    data = {
        "whois_hold": "Evet",
        "domain_age_days": 10,
        "has_privacy_guard": True,
    }
    res = analyzer.analyze("new-domain.com", data)
    assert res.score == 60  # 25 + 25 + 10


def test_ssl_network_risk_analyzer():
    analyzer = SSLNetworkRiskAnalyzer()
    data = {
        "ssl_valid": "Hayır",
        "ssl_issuer": "Let's Encrypt Authority X3",
        "http_status": "500",
    }
    res = analyzer.analyze("bad-ssl-domain.com", data)
    assert res.score == 35  # 15 + 10 + 10


def test_phishing_risk_classifier_whitelisted():
    classifier = PhishingRiskClassifier()
    res = classifier.classify("google.com", {})
    assert res["risk_score"] == 0
    assert res["risk_level"] == RiskLevel.BENIGN.value
    assert res["is_whitelisted"] == "Evet"


def test_phishing_risk_classifier_critical():
    classifier = PhishingRiskClassifier()
    data = {
        "has_password_input": True,
        "has_login_form": True,
        "page_title": "Garanti Bankası Mobil Giriş",
        "whois_hold": "Evet",
        "domain_age_days": 5,
        "ssl_valid": "Hayır",
        "ssl_issuer": "Let's Encrypt",
    }
    res = classifier.classify("garanti-mobil-giris.xyz", data)
    assert res["risk_score"] >= 85
    assert res["risk_level"] == RiskLevel.CRITICAL.value
    assert res["is_whitelisted"] == "Hayır"


def test_excel_exporter_with_phishing_results(tmp_path):
    active_results = [
        {
            "domain": "garanti-mobil-giris.xyz",
            "decision": "ACTIVE (AKTIF)",
            "reason": "DNS Resolved",
            "dns_resolved": "Evet",
            "ipv4_addresses": "1.2.3.4",
            "ipv6_addresses": "-",
            "http_status": "200",
            "redirect_url": "-",
            "ssl_valid": "Hayır",
            "ssl_issuer": "Let's Encrypt",
            "favicon_sha256": "-",
            "spki_sha256": "abc123hash",
            "whois_hold": "Evet",
            "urlscan_history": "Hayır",
            "urlscan_time": "-",
            "screenshot_url": "-",
            "correlated_domains": "-",
        }
    ]
    phishing_results = [
        {
            "domain": "garanti-mobil-giris.xyz",
            "risk_score": 95,
            "risk_level": RiskLevel.CRITICAL.value,
            "is_whitelisted": "Hayır",
            "triggered_signals": [
                "HTML sayfasında Şifre Giriş Kutusu bulundu (+30 Puan)",
                "Typosquatting tespiti: Garanti markası taklidi (+35 Puan)",
                "Domain yaşı 5 günlük (+25 Puan)",
            ],
            "assessed_at": "2026-07-24 14:00:00",
        }
    ]

    out_file = os.path.join(tmp_path, "test_phishing_report.xlsx")
    exporter = ExcelExporter(results=active_results, phishing_results=phishing_results)
    saved_path = exporter.export(output_path=out_file, silent=True)

    assert os.path.exists(saved_path)
