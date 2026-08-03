import argparse
import datetime
import os
import re
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List

import pandas as pd
import urllib3

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure src directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from domain_is_active.checker.domain_checker import PhishingDomainChecker
from domain_is_active.hunting.urlscan_hunter import URLScanHunter
from domain_is_active.exporters.excel import ExcelExporter
from domain_is_active.repository import ActiveDomainRepository
from domain_is_active.constants.defaults import (
    DEFAULT_MAX_THREADS,
    DEFAULT_MAX_CORRELATED_PER_DOMAIN,
)


def sanitize_domain(raw_domain: str) -> str:
    """Domain adını temizler (protokol, port veya path ifadelerini kaldırır)."""
    if not raw_domain or not isinstance(raw_domain, str):
        return ""
    d = raw_domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip()
    return d


from phishing_classifier.classifier.engine import PhishingRiskClassifier
from phishing_classifier.repository import PhishingRiskRepository


from domain_is_active.exporters import ExcelExporter, CSVExporter


class PhishingPipelineOrchestrator:
    """
    Tüm domain aktiflik tarama, tehdit avcılığı ve Phishing Risk Skorlama pipeline'ını yöneten orkestratör sınıf.
    """

    def __init__(
        self,
        input_path: str,
        max_threads: int = DEFAULT_MAX_THREADS,
        max_correlated_per_domain: int = DEFAULT_MAX_CORRELATED_PER_DOMAIN,
        output_excel_path: str = None,
    ):
        self.input_path = input_path
        self.max_threads = max_threads
        self.max_correlated_per_domain = max_correlated_per_domain

        if not output_excel_path:
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_excel_path = os.path.join("reports", f"phishing_analysis_report_{timestamp_str}.xlsx")
        self.output_excel_path = output_excel_path

        self.queue = deque()
        self.visited_domains = set()
        self.domain_company_map: Dict[str, str] = {}
        self.results: List[Dict[str, Any]] = []
        self.phishing_results: List[Dict[str, Any]] = []
        self.hunter = URLScanHunter()
        self.repo = ActiveDomainRepository()
        self.classifier = PhishingRiskClassifier()
        self.processed_count = 0

    def _extract_domains_from_dataframe(self, df: pd.DataFrame) -> List[Any]:
        """Dataframe içerisinden muhtemel domain sütununu bulup verileri döndürür."""
        target_col = None
        company_col = None

        for col in df.columns:
            col_str = str(col).lower()
            if any(keyword in col_str for keyword in ["domain", "url", "site", "host"]):
                target_col = col
            if any(keyword in col_str for keyword in ["şirket", "sirket", "company", "org", "kurum"]):
                company_col = col

        if target_col is None and not df.empty:
            target_col = df.columns[0]

        if target_col is not None:
            if company_col is not None:
                for _, row in df.iterrows():
                    d = sanitize_domain(str(row[target_col]))
                    c = str(row[company_col]).strip()
                    if d and c and c.lower() != "nan":
                        self.domain_company_map[d] = c
            return df[target_col].dropna().tolist()
        return []

    def load_initial_domains(self):
        """Girdi dosyasından (.csv, .tsv, .xlsx, .txt) domainleri okur ve kuyruğa ekler."""
        if not os.path.exists(self.input_path):
            print(f"[!] Hata: Girdi dosyası bulunamadı: {self.input_path}")
            sys.exit(1)

        ext = os.path.splitext(self.input_path)[1].lower()
        raw_domains: List[Any] = []

        try:
            if ext in [".csv", ".tsv"]:
                sep = "\t" if ext == ".tsv" else ","
                df = pd.read_csv(self.input_path, sep=sep)
                raw_domains = self._extract_domains_from_dataframe(df)

            elif ext in [".xlsx", ".xls"]:
                df = pd.read_excel(self.input_path)
                raw_domains = self._extract_domains_from_dataframe(df)

            else:
                with open(self.input_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_domains = [line.strip() for line in f if line.strip()]

        except Exception as e:
            print(f"[!] Girdi dosyası okunurken hata oluştu: {e}")
            sys.exit(1)

        for raw in raw_domains:
            domain_clean = sanitize_domain(str(raw))
            if domain_clean and domain_clean not in self.visited_domains:
                self.visited_domains.add(domain_clean)
                self.queue.append(domain_clean)

        print(f"[*] Girdi dosyasından ({self.input_path}) {len(self.queue)} adet başlangıç domaini yüklendi.")

    def process_single_domain(self, domain: str) -> Dict[str, Any]:
        """
        Bir domain için Pipeline adımlarını çalıştırır:
        1. Lokal Checker Analizi
        2. URLScan Geçmiş Sorgusu
        3. Multi-Vector URLScan Tehdit Avcılığı (Favicon, SPKI, IP, DOM Hash)
        """
        self.processed_count += 1
        total_discovered = len(self.visited_domains)
        remaining_in_queue = len(self.queue)

        print(f"[{self.processed_count}/{total_discovered}] [Kuyrukta Kalan: {remaining_in_queue}] [->] Taranıyor: {domain}", flush=True)

        # 1. Lokal Analiz Motoru
        checker = PhishingDomainChecker(domain)
        local_res = checker.run()

        # 2. URLScan Geçmiş Sorgusu (Sadece DNS çözüldüyse veya canlıysa)
        history = {}
        correlated_domains = []
        if local_res.get("dns_resolved"):
            history = self.hunter.get_historical_data(domain)

            # 3. Multi-Vector Tehdit Avcılığı (Sadece max_correlated_per_domain > 0 ise)
            if self.max_correlated_per_domain > 0:
                first_ip = local_res.get("ipv4_addresses", [None])[0] if local_res.get("ipv4_addresses") else None
                correlated_domains = self.hunter.correlate_multi_vector(
                    favicon_sha256=local_res.get("favicon_sha256"),
                    spki_hash=local_res.get("spki_sha256"),
                    ip_address=first_ip,
                    dom_hash=local_res.get("dom_body_hash"),
                )
                correlated_domains = [d for d in correlated_domains if d.lower() != domain.lower()]

        # 4. Dinamik Geri Besleme (Kuyruğa Yeni Domain Ekleme)
        if self.max_correlated_per_domain > 0 and correlated_domains:
            target_correlated = correlated_domains[: self.max_correlated_per_domain]
            added_count = 0
            for corr_domain in target_correlated:
                corr_clean = sanitize_domain(corr_domain)
                if corr_clean and corr_clean not in self.visited_domains:
                    self.visited_domains.add(corr_clean)
                    self.queue.append(corr_clean)
                    added_count += 1

            if added_count > 0:
                print(f"  [+] Tehdit Avcılığı: {domain} üzerinden {added_count} yeni ilişkili domain kuyruğa eklendi. (Toplam Keşfedilen: {len(self.visited_domains)})", flush=True)

        record = {
            "domain": domain,
            "decision": str(local_res["decision"]),
            "reason": local_res["reason"],
            "dns_resolved": "Evet" if local_res["dns_resolved"] else "Hayır",
            "ipv4_addresses": ", ".join(local_res["ipv4_addresses"]) or "-",
            "ipv6_addresses": ", ".join(local_res["ipv6_addresses"]) or "-",
            "http_status": str(local_res["http_status"]) if local_res["http_status"] else "-",
            "redirect_url": local_res["redirect_url"] or "-",
            "ssl_valid": "Evet" if local_res["ssl_valid"] else "Hayır",
            "ssl_issuer": local_res["ssl_issuer"] or "-",
            "favicon_sha256": local_res["favicon_sha256"] or "-",
            "spki_sha256": local_res["spki_sha256"] or "-",
            "whois_hold": "Evet" if local_res["whois_hold"] else "Hayır",
            "urlscan_history": "Evet" if history.get("has_history") else "Hayır",
            "urlscan_time": history.get("scan_time") or "-",
            "screenshot_url": history.get("screenshot_url") or "-",
            "correlated_domains": ", ".join(correlated_domains) if correlated_domains else "-",
            "page_title": local_res.get("page_title") or "-",
            "has_password_input": "Evet" if local_res.get("has_password_input") else "Hayır",
            "has_login_form": "Evet" if local_res.get("has_login_form") else "Hayır",
            "company": self.domain_company_map.get(domain, ""),
        }

        # Veritabanına kaydet
        try:
            self.repo.save_scan_result(record)
        except Exception as e:
            print(f"[!] DB Kayıt Hatası ({domain}): {e}", flush=True)

        # 5. Phishing Risk Sınıflandırma ve Skorlama Motoru
        risk_level_str = "BENIGN"
        risk_score = 0
        try:
            feature_data = {
                "decision": record.get("decision"),
                "has_password_input": local_res.get("has_password_input", False),
                "has_login_form": local_res.get("has_login_form", False),
                "page_title": local_res.get("page_title", ""),
                "redirect_url": local_res.get("redirect_url", ""),
                "ssl_valid": record.get("ssl_valid"),
                "ssl_issuer": record.get("ssl_issuer"),
                "spki_sha256": record.get("spki_sha256"),
                "http_status": record.get("http_status"),
                "whois_hold": record.get("whois_hold"),
                "screenshot_url": history.get("screenshot_url"),
            }
            risk_assessment = self.classifier.classify(domain, feature_data)
            self.phishing_results.append(risk_assessment)
            risk_level_str = risk_assessment.get("risk_level", "BENIGN")
            risk_score = risk_assessment.get("risk_score", 0)
        except Exception as e:
            print(f"[!] Risk Skorlama Hatası ({domain}): {e}", flush=True)

        print(f"  [✓] Tamamlandı: {domain} -> Karar: {record['decision']}, Risk: {risk_level_str} ({risk_score}/100)", flush=True)
        return record

    def run_pipeline(self, reset_db: bool = False):
        """Kuyruktaki tüm domainler bitene kadar tek bir ThreadPoolExecutor ile eşzamanlı çalışır."""
        if reset_db:
            print("[*] Veritabanı temizleniyor (--reset-db aktif)... Eski kayıtlar silindi.")
            self.repo.clear_all_scans()

        if not self.queue:
            self.load_initial_domains()

        if not self.queue:
            print("[!] Tarama kuyruğunda domain bulunamadı.")
            return

        start_time = time.time()
        print(f"\n[*] Pipeline Başlatıldı ({self.max_threads} eşzamanlı işçi ile)...")

        try:
            from concurrent.futures import as_completed

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures_map = {}

                # Başlangıçta thread kapasitesi kadar iş yükle
                while self.queue and len(futures_map) < self.max_threads:
                    d = self.queue.popleft()
                    f = executor.submit(self.process_single_domain, d)
                    futures_map[f] = d

                while futures_map:
                    # Biten ilk görevi al
                    done_futures = []
                    for f in list(futures_map.keys()):
                        if f.done():
                            done_futures.append(f)

                    if not done_futures:
                        time.sleep(0.05)
                        continue

                    for f in done_futures:
                        domain_name = futures_map.pop(f)
                        try:
                            res = f.result()
                            if res:
                                self.results.append(res)
                        except Exception as e:
                            print(f"[!] Hata ({domain_name}): {e}")

                        # Her 20 sonuçta bir ara raporu Excel'e yaz
                        if len(self.results) % 20 == 0:
                            self.export_excel_report(self.output_excel_path, silent=True)

                        # Kuyrukta yeni elemanlar varsa veya avcılıktan geldiyse yeni işçi başlat
                        while self.queue and len(futures_map) < self.max_threads:
                            next_d = self.queue.popleft()
                            next_f = executor.submit(self.process_single_domain, next_d)
                            futures_map[next_f] = next_d

        except KeyboardInterrupt:
            print("\n[!] Kullanıcı Tarafından İptal Edildi (Ctrl+C). Şu ana kadarki veriler Excel'e aktarılıyor...")
        finally:
            elapsed = time.time() - start_time
            print(f"\n[+] Pipeline Tamamlandı / Durduruldu! Toplam {len(self.results)} domain {elapsed:.2f} saniyede analiz edildi.")
            self.export_all_reports(self.output_excel_path)

    def reclassify_db_domains(self) -> str:
        """
        Yeniden canlılık taraması yapmaksızın, veritabanındaki tüm 'ActiveDomainScan'
        kayıtlarını okur, 'PhishingRiskClassifier' motorundan geçirir, sonuçları
        DB'ye kaydeder ve güncel çok sayfalı Excel raporunu üretir.
        """
        db_records = self.repo.get_all_as_dict()
        if not db_records:
            print("[!] Veritabanında sınıflandırılacak aktif domain kaydı bulunamadı.")
            return ""

        print(f"[*] Veritabanındaki {len(db_records)} adet domain Phishing Risk Classifier motorundan geçiriliyor...", flush=True)

        self.results = db_records
        self.phishing_results = self.classifier.classify_batch(db_records)

        output_path = self.export_all_reports(self.output_excel_path)
        print(f"[+] Re-classification tamamlandı! Toplam {len(self.phishing_results)} domain sınıflandırıldı.", flush=True)
        return output_path

    def export_excel_report(self, output_path: str = None, silent: bool = False) -> str:
        """Sonuçları Excel raporuna aktarır."""
        exporter = ExcelExporter(self.results, phishing_results=self.phishing_results)
        return exporter.export(output_path, silent=silent)

    def export_csv_report(self, output_path: str = None, silent: bool = False) -> str:
        """Sonuçları özel 6 sütunlu CSV raporuna aktarır."""
        if not output_path:
            output_path = self.output_excel_path.replace(".xlsx", ".csv")
        elif not output_path.lower().endswith(".csv"):
            output_path = os.path.splitext(output_path)[0] + ".csv"

        exporter = CSVExporter(
            self.results,
            phishing_results=self.phishing_results,
            domain_company_map=self.domain_company_map,
        )
        return exporter.export(output_path, silent=silent)

    def export_all_reports(self, output_path: str = None, silent: bool = False) -> str:
        """Hem Excel hem de 6 sütunlu CSV raporlarını üretir."""
        excel_path = self.export_excel_report(output_path, silent=silent)
        csv_path = self.export_csv_report(output_path, silent=silent)
        return excel_path


from domain_is_active.hunting.brand_hunter import URLScanBrandHunter
from phishing_classifier.whitelist import WhitelistManager


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Active & Correlation Tool - Alan Adı Aktiflik ve Tehdit Avcılığı Analizi"
    )
    parser.add_argument(
        "-p", "--path",
        type=str,
        default=None,
        help="Girdi dosyası yolu (.csv, .tsv, .xlsx, .txt)"
    )
    parser.add_argument(
        "-bh", "--brand-hunt",
        action="store_true",
        help="11 Hedef Kurum (A101, Togg, Garanti, Vakıfbank, İş Bankası, Borsa İst vb.) için URLScan marka avcılığı yapar."
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=48,
        help="Marka avcılığında son kaç saatin URLScan verisinin çekileceği (Varsayılan: 48 saat)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Rapor çıktısının kaydedileceği yol (Varsayılan: reports/phishing_analysis_report_<timestamp>.xlsx)"
    )
    parser.add_argument(
        "-c", "--max-correlated",
        type=int,
        default=DEFAULT_MAX_CORRELATED_PER_DOMAIN,
        help="Domain başı kuyruğa eklenecek max ilişkili domain sayısı (Varsayılan: 3, Sınırsız için 0)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_MAX_THREADS,
        help="Eşzamanlı çalışacak thread sayısı (Varsayılan: 10)"
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Tarama öncesi veritabanını temizler ve sadece bu taramanın (ve avlanan ilişkili domainlerinin) sonuçlarını saklar."
    )
    parser.add_argument(
        "--reclassify-db",
        action="store_true",
        help="Ağ taraması yapmadan veritabanındaki mevcut domainleri Phishing Risk Classifier motorundan geçirir ve Excel/CSV raporu üretir."
    )
    parser.add_argument(
        "--add-whitelist",
        type=str,
        default=None,
        help="Veritabanı Whitelist tablosuna yeni meşru bir domain ekler."
    )
    parser.add_argument(
        "--list-whitelist",
        action="store_true",
        help="Veritabanındaki tüm Whitelist kayıtlarını listeler."
    )

    args = parser.parse_args()

    # Whitelist Yönetim Komutları
    if args.add_whitelist:
        wm = WhitelistManager()
        wm.add_domain(args.add_whitelist, source="CLI User Add")
        print(f"[+] '{args.add_whitelist}' alanı veritabanı Whitelist tablosuna başarıyla eklendi.")
        return

    if args.list_whitelist:
        wm = WhitelistManager()
        wm.load_whitelist()
        print(f"[*] Veritabanı Whitelist Tablosundaki Domainler ({len(wm._cached_whitelist)} adet):")
        for d in sorted(wm._cached_whitelist):
            print(f"  - {d}")
        return

    if not args.path and not args.brand_hunt and not args.reclassify_db:
        parser.error("Lütfen bir girdi dosyası (-p / --path), Marka Avcılığı (-bh / --brand-hunt) veya DB sınıflandırma parametresi (--reclassify-db) belirtin.")

    # Brand hunt modunda kullanıcı -c / --max-correlated belirtmediyse ilişkili avcılığı kapalı tut (0)
    max_corr = args.max_correlated if "-c" in sys.argv or "--max-correlated" in sys.argv else (0 if args.brand_hunt else args.max_correlated)

    orchestrator = PhishingPipelineOrchestrator(
        input_path=args.path or "",
        max_threads=args.threads,
        max_correlated_per_domain=max_corr,
        output_excel_path=args.output,
    )

    if args.reclassify_db:
        orchestrator.reclassify_db_domains()
    elif args.brand_hunt:
        if args.reset_db:
            print("[*] Veritabanı temizleniyor (--reset-db aktif)... Eski kayıtlar silindi.")
            orchestrator.repo.clear_all_scans()

        brand_hunter = URLScanBrandHunter()
        brand_results = brand_hunter.hunt_all(hours=args.hours)

        # Tüm şüpheli domainleri kuyruğa ekle ve marka eşleştirmesini sakla
        total_queued = 0
        for brand_name, domains in brand_results.items():
            for d in domains:
                clean_d = sanitize_domain(d)
                if clean_d:
                    orchestrator.domain_company_map[clean_d] = brand_name
                    if clean_d not in orchestrator.visited_domains:
                        orchestrator.visited_domains.add(clean_d)
                        orchestrator.queue.append(clean_d)
                        total_queued += 1

        print(f"[*] Marka avcılığından {total_queued} adet şüpheli aday domain tarama kuyruğuna eklendi.")

        if orchestrator.queue:
            orchestrator.run_pipeline(reset_db=False)
        else:
            print("[!] URLScan üzerinde son saatlerde taranan yeni bir şüpheli domain bulunamadı.")
    else:
        orchestrator.run_pipeline(reset_db=args.reset_db)


if __name__ == "__main__":
    main()

