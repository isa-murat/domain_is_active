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
        self.results: List[Dict[str, Any]] = []
        self.phishing_results: List[Dict[str, Any]] = []
        self.hunter = URLScanHunter()
        self.repo = ActiveDomainRepository()
        self.classifier = PhishingRiskClassifier()
        self.processed_count = 0

    def _extract_domains_from_dataframe(self, df: pd.DataFrame) -> List[Any]:
        """Dataframe içerisinden muhtemel domain sütununu bulup verileri döndürür."""
        target_col = None
        for col in df.columns:
            if any(keyword in str(col).lower() for keyword in ["domain", "url", "site", "host"]):
                target_col = col
                break
        if target_col is None and not df.empty:
            target_col = df.columns[0]
        return df[target_col].dropna().tolist() if target_col is not None else []

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

        print(f"[{self.processed_count}/{total_discovered}] [Kuyrukta Kalan: {remaining_in_queue}] [->] Taranıyor: {domain}")

        # 1. Lokal Analiz Motoru
        checker = PhishingDomainChecker(domain)
        local_res = checker.run()

        # 2. URLScan Geçmiş Sorgusu
        history = self.hunter.get_historical_data(domain)

        # 3. Multi-Vector Tehdit Avcılığı
        first_ip = local_res.get("ipv4_addresses", [None])[0] if local_res.get("ipv4_addresses") else None
        correlated_domains = self.hunter.correlate_multi_vector(
            favicon_sha256=local_res.get("favicon_sha256"),
            spki_hash=local_res.get("spki_sha256"),
            ip_address=first_ip,
            dom_hash=local_res.get("dom_body_hash"),
        )

        # Kendi kendini çıkar
        correlated_domains = [d for d in correlated_domains if d.lower() != domain.lower()]

        # 4. Dinamik Geri Besleme (Kuyruğa Yeni Domain Ekleme)
        if self.max_correlated_per_domain > 0:
            target_correlated = correlated_domains[: self.max_correlated_per_domain]
        else:
            target_correlated = correlated_domains  # Sınırsız / Limitsiz avcılık

        added_count = 0
        for corr_domain in target_correlated:
            corr_clean = sanitize_domain(corr_domain)
            if corr_clean and corr_clean not in self.visited_domains:
                self.visited_domains.add(corr_clean)
                self.queue.append(corr_clean)
                added_count += 1

        if added_count > 0:
            print(f"  [+] Tehdit Avcılığı: {domain} üzerinden {added_count} yeni ilişkili domain kuyruğa eklendi. (Toplam Keşfedilen: {len(self.visited_domains)})")

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
        }

        # Veritabanına kaydet
        try:
            self.repo.save_scan_result(record)
        except Exception as e:
            print(f"[!] DB Kayıt Hatası ({domain}): {e}")

        # 5. Phishing Risk Sınıflandırma ve Skorlama Motoru
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
            }
            risk_assessment = self.classifier.classify(domain, feature_data)
            self.phishing_results.append(risk_assessment)
        except Exception as e:
            print(f"[!] Risk Skorlama Hatası ({domain}): {e}")

        return record

    def run_pipeline(self, reset_db: bool = False):
        """Kuyruktaki tüm domainler bitene kadar tek bir ThreadPoolExecutor ile eşzamanlı çalışır."""
        if reset_db:
            print("[*] Veritabanı temizleniyor (--reset-db aktif)... Eski kayıtlar silindi.")
            self.repo.clear_all_scans()

        self.load_initial_domains()

        start_time = time.time()
        print(f"\n[*] Pipeline Başlatıldı ({self.max_threads} eşzamanlı işçi ile)...")

        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                while self.queue:
                    batch = []
                    while self.queue and len(batch) < self.max_threads:
                        batch.append(self.queue.popleft())

                    if batch:
                        batch_results = list(executor.map(self.process_single_domain, batch))
                        self.results.extend(batch_results)

                        # Her 20 taranan domainde bir Excel raporunu otomatik kaydet
                        if len(self.results) % 20 == 0:
                            self.export_excel_report(self.output_excel_path, silent=True)

        except KeyboardInterrupt:
            print("\n[!] Kullanıcı Tarafından İptal Edildi (Ctrl+C). Şu ana kadarki veriler Excel'e aktarılıyor...")
        finally:
            elapsed = time.time() - start_time
            print(f"\n[+] Pipeline Tamamlandı / Durduruldu! Toplam {len(self.results)} domain {elapsed:.2f} saniyede analiz edildi.")
            self.export_excel_report(self.output_excel_path)

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

        print(f"[*] Veritabanındaki {len(db_records)} adet domain Phishing Risk Classifier motorundan geçiriliyor...")

        self.results = db_records
        self.phishing_results = self.classifier.classify_batch(db_records)

        output_path = self.export_excel_report(self.output_excel_path)
        print(f"[+] Re-classification tamamlandı! Toplam {len(self.phishing_results)} domain sınıflandırıldı.")
        return output_path

    def export_excel_report(self, output_path: str = None, silent: bool = False) -> str:
        """Sonuçları Excel raporuna aktarır."""
        exporter = ExcelExporter(self.results, phishing_results=self.phishing_results)
        return exporter.export(output_path, silent=silent)


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Active & Correlation Tool - Alan Adı Aktiflik ve Tehdit Avcılığı Analizi"
    )
    parser.add_argument(
        "-p", "--path",
        type=str,
        default=None,
        help="Girdi dosyası yolu (.csv, .txt, .xlsx)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Rapor Excel çıktısının kaydedileceği yol (Varsayılan: reports/phishing_analysis_report_<timestamp>.xlsx)"
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
        help="Ağ taraması yapmadan veritabanındaki mevcut domainleri Phishing Risk Classifier motorundan geçirir ve Excel raporu üretir."
    )

    args = parser.parse_args()

    if not args.path and not getattr(args, "reclassify_db", False):
        parser.error("Lütfen bir girdi dosyası (-p / --path) veya DB sınıflandırma parametresi (--reclassify-db) belirtin.")

    orchestrator = PhishingPipelineOrchestrator(
        input_path=args.path or "",
        max_threads=args.threads,
        max_correlated_per_domain=args.max_correlated,
        output_excel_path=args.output,
    )

    if args.reclassify_db:
        orchestrator.reclassify_db_domains()
    else:
        orchestrator.run_pipeline(reset_db=args.reset_db)


if __name__ == "__main__":
    main()
