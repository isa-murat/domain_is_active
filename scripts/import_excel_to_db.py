import os
import sys
import pandas as pd

# Ensure src directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from domain_is_active.repository import ActiveDomainRepository

EXCEL_PATH = r"D:\domain_is_active\reports\phishing_analysis_report_20260723_154612.xlsx"


def import_excel_to_db():
    if not os.path.exists(EXCEL_PATH):
        print(f"[!] Hata: Excel raporu bulunamadı: {EXCEL_PATH}")
        sys.exit(1)

    print(f"[*] Excel raporu okunuyor: {EXCEL_PATH}")
    df = pd.read_excel(EXCEL_PATH, sheet_name="Detayli Analiz")

    repo = ActiveDomainRepository()
    print("[*] Veritabanı temizleniyor (Mevcut eski test kayıtları siliniyor)...")
    repo.clear_all_scans()

    records_added = 0
    for _, row in df.iterrows():
        domain_name = str(row.get("Domain", "")).strip()
        if not domain_name or domain_name == "nan":
            continue

        record = {
            "domain": domain_name,
            "decision": str(row.get("Nihai Karar", "-")),
            "reason": str(row.get("Karar Gerekçesi", "-")),
            "dns_resolved": str(row.get("DNS Status", "Hayır")),
            "ipv4_addresses": str(row.get("IPv4 Adresleri", "-")),
            "ipv6_addresses": str(row.get("IPv6 Adresleri", "-")),
            "http_status": str(row.get("HTTP Status", "-")),
            "redirect_url": str(row.get("Yönlendirme URL", "-")),
            "ssl_valid": str(row.get("SSL Geçerli", "Hayır")),
            "ssl_issuer": str(row.get("SSL Issuer", "-")),
            "favicon_sha256": str(row.get("Favicon SHA256", "-")),
            "spki_sha256": str(row.get("SPKI SHA256", "-")),
            "whois_hold": str(row.get("WHOIS Hold", "Hayır")),
            "urlscan_history": str(row.get("URLScan Geçmiş", "Hayır")),
            "urlscan_time": str(row.get("URLScan Tarih", "-")),
            "screenshot_url": str(row.get("Ekran Görüntüsü", "-")),
            "correlated_domains": str(row.get("İlişkili Avlanan Domainler", "-")),
        }

        repo.save_scan_result(record)
        records_added += 1

    print(f"[+] Başarılı! Toplam {records_added} adet domain Excel'den veritabanına aktarıldı.")


if __name__ == "__main__":
    import_excel_to_db()
