import os
import pandas as pd
import pytest
from domain_is_active.exporters.csv_exporter import CSVExporter


def test_csv_exporter_columns_and_formatting(tmp_path):
    output_file = tmp_path / "test_report.csv"

    results = [
        {
            "domain": "sahte-garanti-online.xyz",
            "decision": "ACTIVE (AKTİF)",
            "dns_resolved": "Evet",
            "ipv4_addresses": "192.0.2.1",
            "http_status": "200",
            "urlscan_time": "2026-08-03 12:00:00",
            "has_password_input": "Evet",
        },
        {
            "domain": "pasif-site.com",
            "decision": "INACTIVE (PASİF)",
            "dns_resolved": "Hayır",
            "ipv4_addresses": "-",
            "http_status": "-",
            "urlscan_time": "-",
            "has_password_input": "Hayır",
        },
    ]

    phishing_results = [
        {
            "domain": "sahte-garanti-online.xyz",
            "risk_score": 85,
            "risk_level": "CRITICAL",
        },
        {
            "domain": "pasif-site.com",
            "risk_score": 0,
            "risk_level": "BENIGN",
        },
    ]

    domain_company_map = {
        "sahte-garanti-online.xyz": "Garanti Bankası",
        "pasif-site.com": "A101",
    }

    exporter = CSVExporter(results, phishing_results=phishing_results, domain_company_map=domain_company_map)
    exported_path = exporter.export(str(output_file))

    assert os.path.exists(exported_path)

    df = pd.read_csv(exported_path, encoding="utf-8-sig")

    # Check 6 columns match Batuhan Aydos exact spec
    expected_cols = ["Şirket", "Domain", "Durum", "Sunucu IP", "Son görülme", "Kötü niyetli işaret"]
    assert list(df.columns) == expected_cols

    # Check Row 1 values
    row0 = df.iloc[0]
    assert row0["Şirket"] == "Garanti Bankası"
    assert row0["Domain"] == "sahte-garanti-online.xyz"
    assert row0["Durum"] == "AKTİF"
    assert row0["Sunucu IP"] == "192.0.2.1"
    assert row0["Son görülme"] == "2026-08-03 12:00:00"
    assert row0["Kötü niyetli işaret"] == "Evet"

    # Check Row 2 values
    row1 = df.iloc[1]
    assert row1["Şirket"] == "A101"
    assert row1["Domain"] == "pasif-site.com"
    assert row1["Durum"] == "PASİF"
    assert row1["Sunucu IP"] == "-"
    assert row1["Kötü niyetli işaret"] == "Hayır"


def test_csv_exporter_utf8_sig_encoding(tmp_path):
    output_file = tmp_path / "encoding_test.csv"
    results = [{"domain": "test.com", "decision": "ACTIVE"}]
    exporter = CSVExporter(results)
    exported_path = exporter.export(str(output_file))

    with open(exported_path, "rb") as f:
        content = f.read()
        # UTF-8 BOM starts with bytes b'\xef\xbb\xbf'
        assert content.startswith(b"\xef\xbb\xbf")
