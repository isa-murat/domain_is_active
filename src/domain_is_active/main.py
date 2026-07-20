import os
import sys
import time

# Add src directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List

import pandas as pd
import openpyxl
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Local module imports
from domain_is_active.checker import PhishingDomainChecker
from domain_is_active.hunter import URLScanHunter

# Suppress warnings
import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CSV_FILE_PATH = r"C:\Users\isamu\Desktop\staj\2.hafta\docs\aktiflik-odevi-stajyer-listesi.csv"

# Time-stamped output path so previous reports are never overwritten
timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_EXCEL_PATH = rf"D:\domain_is_active\reports\phishing_analysis_report_{timestamp_str}.xlsx"

MAX_THREADS = 10
MAX_TOTAL_SCANS = 100  # Güvenlik sınırı (Sonsuz döngü engellemek için)
MAX_CORRELATED_PER_DOMAIN = 3  # Domain başı kuyruğa eklenecek max ilişkili domain

class PhishingPipelineOrchestrator:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.queue = deque()
        self.visited_domains = set()
        self.results = []
        self.hunter = URLScanHunter()
        
    def load_initial_domains(self):
        """CSV dosyasındaki ilk domainleri okur ve kuyruğa atar."""
        if not os.path.exists(self.csv_path):
            print(f"[!] Hata: CSV dosyası bulunamadı: {self.csv_path}")
            sys.exit(1)
            
        df = pd.read_csv(self.csv_path)
        for domain in df["domain"]:
            domain_clean = str(domain).strip().lower()
            if domain_clean and domain_clean not in self.visited_domains:
                self.visited_domains.add(domain_clean)
                self.queue.append(domain_clean)
                
        print(f"[*] CSV'den {len(self.queue)} adet başlangıç domaini kuyruğa yüklendi.")

    def process_single_domain(self, domain: str) -> Dict[str, Any]:
        """
        Bir domain için 5 aşamalı tüm Pipeline adımlarını çalıştırır:
        1. Lokal Checker Analizi
        2. URLScan Geçmiş Sorgusu (Geçmiş & Ekran Görüntüsü)
        3. URLScan Parmak İzi Korelasyonu (Tehdit Avcılığı)
        """
        print(f"[->] Taranıyor: {domain}")
        
        # 1. Aşama: Lokal Analiz Motoru
        checker = PhishingDomainChecker(domain)
        local_res = checker.run()
        
        # 2. Aşama: URLScan Geçmiş Sorgusu
        history = self.hunter.get_historical_data(domain)
        
        # 3. Aşama: Tehdit Avcılığı (Favicon veya SPKI ile Tersine Arama)
        favicon_sha256 = local_res.get("favicon_sha256")
        spki_sha256 = local_res.get("spki_sha256")
        
        correlated_domains = []
        if favicon_sha256:
            correlated_domains = self.hunter.correlate_fingerprints(favicon_sha256=favicon_sha256)
        elif spki_sha256:
            correlated_domains = self.hunter.correlate_fingerprints(spki_hash=spki_sha256)
            
        # Kendi kendini ilişkili listeden çıkar
        correlated_domains = [d for d in correlated_domains if d.lower() != domain.lower()]

        # 4. Aşama: Dinamik Geri Besleme (Kuyruğa Yeni Domain Ekleme)
        added_count = 0
        for corr_domain in correlated_domains[:MAX_CORRELATED_PER_DOMAIN]:
            corr_clean = corr_domain.strip().lower()
            if corr_clean not in self.visited_domains and len(self.visited_domains) < MAX_TOTAL_SCANS:
                self.visited_domains.add(corr_clean)
                self.queue.append(corr_clean)
                added_count += 1

        if added_count > 0:
            print(f"  [+] Tehdit Avcılığı: {domain} üzerinden {added_count} yeni ilişkili domain kuyruğa eklendi.")

        # Zenginleştirilmiş tekil veri kaydı oluşturma
        record = {
            "domain": domain,
            "decision": local_res["decision"],
            "reason": local_res["reason"],
            "dns_resolved": "Evet" if local_res["dns_resolved"] else "Hayır",
            "ipv4_addresses": ", ".join(local_res["ipv4_addresses"]) or "-",
            "ipv6_addresses": ", ".join(local_res["ipv6_adressess"]) or "-",
            "http_status": str(local_res["http_status"]) if local_res["http_status"] else "-",
            "redirect_url": local_res["redirect_url"] or "-",
            "ssl_valid": "Evet" if local_res["ssl_valid"] else "Hayır",
            "ssl_issuer": local_res["ssl_issuer"] or "-",
            "favicon_sha256": favicon_sha256 or "-",
            "spki_sha256": spki_sha256 or "-",
            "whois_hold": "Evet" if local_res["whois_hold"] else "Hayır",
            "urlscan_history": "Evet" if history.get("has_history") else "Hayır",
            "urlscan_time": history.get("scan_time") or "-",
            "screenshot_url": history.get("screenshot_url") or "-",
            "correlated_domains": ", ".join(correlated_domains) if correlated_domains else "-"
        }
        return record

    def run_pipeline(self):
        """Dinamik kuyruk boşalana kadar parallel işçilerle taramayı yürütür."""
        self.load_initial_domains()
        
        start_time = time.time()
        print(f"\n[*] Pipeline Başlatıldı ({MAX_THREADS} Thread)...")
        
        while self.queue and len(self.results) < MAX_TOTAL_SCANS:
            # O anki kuyruk elemanlarını alıp batch olarak çalıştırıyoruz
            batch = []
            while self.queue and len(batch) < MAX_THREADS:
                batch.append(self.queue.popleft())
                
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                batch_results = list(executor.map(self.process_single_domain, batch))
                self.results.extend(batch_results)
                
        elapsed = time.time() - start_time
        print(f"\n[+] Pipeline Tamamlandı! Toplam {len(self.results)} domain {elapsed:.2f} saniyede analiz edildi.")

    def export_excel_report(self, output_path: str):
        """
        Sonuçları Yönetici Özeti ve Detaylı Analiz sayfaları içeren tıklanabilir Excel raporuna dönüştürür.
        """
        print(f"[*] Excel raporu oluşturuluyor: {output_path}")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        df = pd.DataFrame(self.results)
        
        # Excel Workbook oluşturma
        wb = openpyxl.Workbook()
        
        # -------------------------------------------------------------
        # SAYFA 1: Yönetici Özeti (Executive Dashboard)
        # -------------------------------------------------------------
        ws_summary = wb.active
        ws_summary.title = "Yonetici Ozet"
        ws_summary.views.sheetView[0].showGridLines = True
        
        # Başlık
        ws_summary.merge_cells("A1:D1")
        title_cell = ws_summary["A1"]
        title_cell.value = "PHISHING DOMAIN AKTIFLIK VE TEHDIT AVCILIGI OZET RAPORU"
        title_cell.font = Font(name="Calibri", size=14, bold=True, color="FFFFFF")
        title_cell.fill = PatternFill(start_color="1F4E79", end_color="1F4E79", fill_type="solid")
        title_cell.alignment = Alignment(horizontal="center", vertical="center")
        ws_summary.row_dimensions[1].height = 35
        
        # İstatistikler
        total_count = len(df)
        decision_counts = df["decision"].value_counts().to_dict()
        
        ws_summary["A3"] = "Metrik / Durum"
        ws_summary["B3"] = "Domain Sayısı"
        ws_summary["C3"] = "Oran (%)"
        
        for col in ["A3", "B3", "C3"]:
            cell = ws_summary[col]
            cell.font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="2F5597", end_color="2F5597", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")

        stats_rows = [
            ("Toplam Taranan Domain", total_count),
            ("ACTIVE (Aktif / Canlı)", decision_counts.get("ACTIVE (AKTIF)", 0)),
            ("TAKEDOWN (Kapatılmış)", decision_counts.get("TAKEDOWN (KAPATILDI)", 0)),
            ("INACTIVE (Pasif / Ölü)", decision_counts.get("INACTIVE (PASIF)", 0)),
            ("SUSPICIOUS / UNSTABLE (Şüpheli)", decision_counts.get("SUSPICIOUS / UNSTABLE", 0)),
            ("PARKED (Park Edilmiş)", decision_counts.get("PARKED (PARK EDILMIS)", 0)),
        ]
        
        for r_idx, (label, val) in enumerate(stats_rows, start=4):
            ws_summary.cell(row=r_idx, column=1, value=label).font = Font(bold=(r_idx==4))
            ws_summary.cell(row=r_idx, column=2, value=val).alignment = Alignment(horizontal="center")
            pct = (val / total_count * 100) if total_count > 0 else 0
            ws_summary.cell(row=r_idx, column=3, value=f"{pct:.1f}%").alignment = Alignment(horizontal="center")
            
        # -------------------------------------------------------------
        # SAYFA 2: Detaylı Analiz (Detailed Data Table)
        # -------------------------------------------------------------
        ws_detail = wb.create_sheet(title="Detayli Analiz")
        ws_detail.views.sheetView[0].showGridLines = True
        
        headers = [
            "Domain", "Nihai Karar", "Karar Gerekçesi", "DNS Status", 
            "IPv4 Adresleri", "IPv6 Adresleri", "HTTP Status", "Yönlendirme URL", "SSL Geçerli", 
            "SSL Issuer", "Favicon SHA256", "SPKI SHA256", "WHOIS Hold", 
            "URLScan Geçmiş", "URLScan Tarih", "Ekran Görüntüsü", "İlişkili Avlanan Domainler"
        ]
        
        ws_detail.append(headers)
        
        # Header Stili
        for col_num, header in enumerate(headers, 1):
            cell = ws_detail.cell(row=1, column=col_num)
            cell.font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="1F4E79", end_color="1F4E79", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws_detail.row_dimensions[1].height = 28

        # Domainlerin satır indeks haritası (İç Linkler İçin)
        domain_to_row = {}
        for idx, item in enumerate(self.results, start=2):
            domain_to_row[item["domain"].lower()] = idx

        # Durum Renk Dolguları
        color_map = {
            "ACTIVE (AKTIF)": PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid"),       # Yeşil
            "TAKEDOWN (KAPATILDI)": PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"), # Sarı/Turuncu
            "INACTIVE (PASIF)": PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid"),     # Açık Gri/Yeşil
            "SUSPICIOUS / UNSTABLE": PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),# Açık Kırmızı
            "PARKED (PARK EDILMIS)": PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")  # Mavi/Gri
        }

        # Veri Satırlarını Ekleme ve Linkleme
        for row_idx, item in enumerate(self.results, start=2):
            row_data = [
                item["domain"],
                item["decision"],
                item["reason"],
                item["dns_resolved"],
                item["ipv4_addresses"],
                item["ipv6_addresses"],
                item["http_status"],
                item["redirect_url"],
                item["ssl_valid"],
                item["ssl_issuer"],
                item["favicon_sha256"],
                item["spki_sha256"],
                item["whois_hold"],
                item["urlscan_history"],
                item["urlscan_time"],
                "", # Ekran görüntüsü link alanı
                ""  # İlişkili domainler link alanı
            ]
            ws_detail.append(row_data)
            
            # Karar sütunu renklendirme
            decision_val = item["decision"]
            if decision_val in color_map:
                ws_detail.cell(row=row_idx, column=2).fill = color_map[decision_val]
                ws_detail.cell(row=row_idx, column=2).font = Font(bold=True)
                
            # 1. Dış Link: Ekran Görüntüsü URLScan Linki
            ss_url = item["screenshot_url"]
            ss_cell = ws_detail.cell(row=row_idx, column=16)
            if ss_url and ss_url != "-":
                ss_cell.value = f'=HYPERLINK("{ss_url}", "Görseli Aç 🔗")'
                ss_cell.font = Font(color="0000FF", underline="single")
            else:
                ss_cell.value = "-"
                
            # 2. İç Link (Workbook Internal Hyperlink): İlişkili Avlanan Domainler
            corr_str = item["correlated_domains"]
            corr_cell = ws_detail.cell(row=row_idx, column=17)
            
            if corr_str and corr_str != "-":
                first_corr = corr_str.split(",")[0].strip().lower()
                # Eğer avlanan domain de tablomuzda taranmışsa, tıklayınca O DOMAİNİN SATIRINA İŞINLANIR!
                if first_corr in domain_to_row:
                    target_row = domain_to_row[first_corr]
                    corr_cell.value = f'=HYPERLINK("#\'Detayli Analiz\'!A{target_row}", "{corr_str}")'
                    corr_cell.font = Font(color="0000FF", underline="single", bold=True)
                else:
                    corr_cell.value = corr_str
            else:
                corr_cell.value = "-"

        # Otomatik Sütun Genişliği Ayarlama
        for col in ws_detail.columns:
            max_len = max(len(str(cell.value or '')) for cell in col)
            col_letter = get_column_letter(col[0].column)
            ws_detail.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 45)
            
        for col in ws_summary.columns:
            max_len = max(len(str(cell.value or '')) for cell in col)
            col_letter = get_column_letter(col[0].column)
            ws_summary.column_dimensions[col_letter].width = max(max_len + 4, 18)

        # Kaydetme
        wb.save(output_path)
        print(f"[+] Excel raporu başarıyla kaydedildi: {output_path}")

if __name__ == "__main__":
    orchestrator = PhishingPipelineOrchestrator(CSV_FILE_PATH)
    orchestrator.run_pipeline()
    orchestrator.export_excel_report(OUTPUT_EXCEL_PATH)
