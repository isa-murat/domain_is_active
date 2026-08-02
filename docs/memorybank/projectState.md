# Memory Bank - Proje Mevcut Durumu (projectState.md)

## 📌 Genel Özet
`domain_is_active` projesi, phishing/şüpheli alan adlarının canlılık durumlarını (DNS, WHOIS, SSL, HTTP) analiz eden ve URLScan.io üzerinden Multi-Vector (Favicon, SSL SPKI, IP, DOM Hash) tehdit avcılığı yapan modüler bir Python aracıdır.

- **Mevcut Sürüm:** v0.2.0 (Phishing Risk Classifier Geliştirme Aşamasında)
- **Aktif Branch:** `feat/phishing-risk-classifier`
- **CLI Kısayolu:** `dia -p <girdi> -o <cikti> [--reset-db]`

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
- `similarity.py`: Levenshtein string benzerlik algoritması.

### 6. Karar Facade & Raporlayıcı (`domain_is_active/checker/` & `exporters/`)
- `domain_checker.py`: Toplayıcıları sırayla çalıştırıp `ScanDecision` üreten Facade sınıfı.
- `excel.py`: openpyxl biçimlendirmeli tıklanabilir Excel rapor üretici.

---

## 🔄 Aktif Geliştirme Durumu
- **Tamamlanan Aşamalar:** 
  - **Aşama 1:** Shared Core DB (`src/core/db/`), Alembic Migrasyonları ve `ActiveDomainRepository` tamamlandı.
  - **Aşama 2:** Phishing Risk Sınıflandırma Motoru (`feat/phishing-risk-classifier`) tamamlandı. `src/phishing_classifier/` paketi (0-100 Ağırlıklı Risk Puanlama, Whitelist DB Tablosu & Set önbellekleme, HTML/Lexical/WHOIS/SSL analizörleri, Alembic migrasyonu ve çok sayfalı Excel rapor entegrasyonu) başarıyla geliştirildi ve tüm testlerden geçti.
- **Sıradaki Aşama:** Aşama 3 - Görsel pHash Klon Tespiti (`feat/visual-phash-analyzer`).


