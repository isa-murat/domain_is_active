# Memory Bank - Proje Mevcut Durumu (projectState.md)

## 📌 Genel Özet
`domain_is_active` projesi, phishing/şüpheli alan adlarının canlılık durumlarını (DNS, WHOIS, SSL, HTTP) analiz eden ve URLScan.io üzerinden Multi-Vector (Favicon, SSL SPKI, IP, DOM Hash) tehdit avcılığı yapan modüler bir Python aracıdır.

- **Mevcut Sürüm:** v0.4.0 (Özel 6 Sütunlu CSV Exporter Tamamlandı)
- **Aktif Branch:** `feat/custom-csv-exporter`
- **CLI Kısayolu:** `dia -bh [--hours 24] [--reset-db]` / `dia -p <girdi>`

---

## 🎯 Tamamlanan Modüller ve Özellikler

### 1. Shared Core Veritabanı ve Migrasyon Katmanı (`src/core/db/`)
- `database.py`: SQLite SQLAlchemy Engine, `SessionLocal` ve `Base` declarative tanımı.
- `base.py`: Jenerik CRUD ve transaction yöneticisi `BaseRepository` soyut temel sınıfı.
- `alembic`: Alembic migrasyon altyapısı kuruldu (`alembic upgrade head`).

### 2. Domain ORM & Repository Katmanı (`src/domain_is_active/`)
- `models.py`: `ActiveDomainScan` (Tarama sonuçları) ve `ActiveScanHistory` (Tarihsel durum değişim logu) ORM modelleri.
- `repository.py`: `BaseRepository` türevi `ActiveDomainRepository` (UPSERT & History Logging).
- CLI `--reset-db` parametresi eklendi.

### 3. Merkezi Enum ve Sabitler Katmanı (`domain_is_active/constants/`)
- `enums.py`: `ScanDecision`, `RiskLevel` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`), `HuntingVector`, `ReportColors` Enum sınıfları.
- `defaults.py`: Zaman aşımı, varsayılan User-Agent ve jenerik hash ignorelist tanımları.

### 4. Veri Toplayıcılar (`domain_is_active/collectors/`)
- `dns_col.py`: A, AAAA, NS, MX DNS sorguları.
- `whois_col.py`: WHOIS hold ve status sorguları.
- `ssl_col.py`: Unverified SSL (`CERT_NONE`) ile bozuk sertifikalı phishing sitelerinden SPKI hash çıkarılması sağlandı.
- `http_col.py`: HTTP status, title, favicon SHA256, DOM body hash ve login/password formu tespitleri.
- `visual_col.py`: Ekran görüntüsü indirme ve dHash/pHash hesaplayıcı.

### 5. Tehdit Avcılığı Engine (`domain_is_active/hunting/`)
- `urlscan_hunter.py`: Favicon + SPKI + IP + DOM Hash vektörlerini birleştiren Multi-Vector URLScan Hunter.
- `brand_hunter.py`: 11 Hedef Kurum (A101, Togg, Garanti, Vakıfbank, İş Bankası, Borsa İstanbul, Takasbank, Otokoç, Azercell, BIDV, The Body Shop) için otomatik URLScan zaman filtreli marka avcısı (`URLScanBrandHunter`).
- `similarity.py`: Levenshtein string benzerlik algoritması.

### 6. Görsel Klon Tespiti (`phishing_classifier/visual/`)
- `visual_analyzer.py`: `assets/reference_screenshots/` klasöründeki resmi kurum ekran görüntüleri ile aday siteleri dHash Hamming mesafesi ile karşılaştıran `VisualRiskAnalyzer` (%85+ benzerlikte sahte klon uyarısı).

### 7. Karar Facade & Raporlayıcılar (`domain_is_active/checker/` & `exporters/`)
- `domain_checker.py`: Toplayıcıları sırayla çalıştırıp `ScanDecision` üreten Facade sınıfı.
- `excel.py`: openpyxl biçimlendirmeli tıklanabilir Excel rapor üretici.
- `csv_exporter.py`: Özel formatına uygun 6 sütunlu (`Şirket`, `Domain`, `Durum`, `Sunucu IP`, `Son görülme`, `Kötü niyetli işaret`) `utf-8-sig` CSV rapor üretici (`CSVExporter`).

---

## 🔄 Aktif Geliştirme Durumu
- **Tamamlanan Aşamalar:** 
  - **Aşama 1:** Shared Core DB (`src/core/db/`), Alembic Migrasyonları ve `ActiveDomainRepository` tamamlandı.
  - **Aşama 2:** Phishing Risk Sınıflandırma Motoru (`feat/phishing-risk-classifier`) tamamlandı. `src/phishing_classifier/` paketi (0-100 Ağırlıklı Risk Puanlama, Whitelist DB Tablosu & Set önbellekleme, HTML/Lexical/WHOIS/SSL analizörleri, Alembic migrasyonu ve çok sayfalı Excel rapor entegrasyonu) başarıyla geliştirildi.
  - **Aşama 3:** 11 Kurum İçin URLScan Marka Avcılığı (`URLScanBrandHunter`), Veritabanı Tabanlı Whitelist Seeding & Yönetimi ve Görsel pHash Klon Tespiti (`VisualRiskAnalyzer`) geliştirildi.
  - **Aşama 4:** Özel 6 Sütunlu `utf-8-sig` CSV Exporter (`CSVExporter`) ve `--export-csv` entegrasyonu geliştirildi ve tüm birim testlerden geçti.



