# Memory Bank - Proje Mevcut Durumu (projectState.md)

## 📌 Genel Özet
`domain_is_active` projesi, phishing/şüpheli alan adlarının canlılık durumlarını (DNS, WHOIS, SSL, HTTP) analiz eden ve URLScan.io üzerinden Multi-Vector (Favicon, SSL SPKI, IP, DOM Hash) tehdit avcılığı yapan modüler bir Python aracıdır.

- **Mevcut Sürüm:** v0.1.0 (Refactored & Modularized)
- **Aktif Branch:** `feat/sqlite-alembic-db`
- **CLI Kısayolu:** `dia -p <girdi> -o <cikti>`

---

## 🎯 Tamamlanan Modüller ve Özellikler

### 1. Merkezi Enum ve Sabitler Katmanı (`domain_is_active/constants/`)
- `enums.py`: `ScanDecision` (`ACTIVE`, `TAKEDOWN`, `INACTIVE`, `PARKED`, `SUSPICIOUS`), `HuntingVector`, `ReportColors` Enum sınıfları kuruldu.
- `defaults.py`: Zaman aşımı, varsayılan User-Agent ve jenerik hash ignorelist tanımları.

### 2. Veri Toplayıcılar (`domain_is_active/collectors/`)
- `dns_col.py`: A, AAAA, NS, MX DNS sorguları.
- `whois_col.py`: WHOIS hold ve status sorguları.
- `ssl_col.py`: Unverified SSL (`CERT_NONE`) ile bozuk sertifikalı phishing sitelerinden SPKI hash çıkarılması sağlandı.
- `http_col.py`: HTTP status, title, favicon SHA256, DOM body hash ve login formu tespitleri.
- `visual_col.py`: Ekran görüntüsü indirme ve dHash/pHash hesaplayıcı.

### 3. Tehdit Avcılığı Engine (`domain_is_active/hunting/`)
- `urlscan_hunter.py`: Favicon + SPKI + IP + DOM Hash vektörlerini birleştiren Multi-Vector URLScan Hunter.
- `similarity.py`: Levenshtein string benzerlik algoritması.

### 4. Karar Facade & Raporlayıcı (`domain_is_active/checker/` & `exporters/`)
- `domain_checker.py`: Toplayıcıları sırayla çalıştırıp `ScanDecision` üreten Facade sınıfı.
- `excel.py`: openpyxl biçimlendirmeli tıklanabilir Excel rapor üretici.

---

## 🔄 Aktif Geliştirme Durumu
- **Şu an yapılan iş:** Aşama 1 - Merkezi Veritabanı (`src/core/db/`), Alembic Migrasyonları ve `ActiveDomainRepository` altyapısının kurulması (`feat/sqlite-alembic-db`).
