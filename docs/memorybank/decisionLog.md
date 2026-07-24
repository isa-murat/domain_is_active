# Memory Bank - Mimari Karar Günlüğü (decisionLog.md)

Bu doküman, projede alınan kritik teknik ve mimari kararların gerekçelerini (ADR - Architecture Decision Records) saklar.

---

## 📝 Alınan Mimari Kararlar

### ADR-001: Bağlam Ayrımı (Domain Active vs Phishing Risk)
- **Karar:** `domain_is_active` modülü sadece alan adının teknik aktiflik durumuna (DNS, WHOIS, SSL, HTTP) ve korelasyon veri toplamaya odaklanacak. Phishing risk skorlaması ayrı bir modülde (`phishing_classifier`) ele alınacak.
- **Gerekçe:** Modülerlik, Single Responsibility prensibi ve `domain_is_active` modülünün genel amaçlı domain takibinde de bağımsız kullanılabilmesi.

### ADR-002: Centralized TextChoices Enums
- **Karar:** Hardcoded string'ler kaldırılıp Django tarzı `BaseTextChoices` Enum sınıflarında toplandı (`ScanDecision`, `HuntingVector`, `ReportColors`).
- **Gerekçe:** Tip güvenliği (Type Safety), IDE autocomplete ve typo kaynaklı hataların engellenmesi.

### ADR-003: Unverified SSL Context (`CERT_NONE`)
- **Karar:** `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` ile `CERT_NONE` kullanılarak SSL doğrulama hatası veren phishing sitelerinden bile SPKI hash çıkarılması sağlandı.
- **Gerekçe:** Phishing sitelerinin geçersiz SSL kullanması nedeniyle `spki_sha256` hash'inin `None` kalması ve tehdit avcılığının durması engellendi.

### ADR-004: Shared Core DB (`src/core/db/`) ve SQLite / Alembic
- **Karar:** Veritabanı altyapısı (Engine, SessionManager, Alembic migrasyonları) projenin tüm modüllerinin ortak erişebilmesi için `src/core/db/` altında merkezi bir paket olarak konumlandırıldı.
- **Gerekçe:** Çapraz modül bağımlılıklarını engellemek (Inverted Dependency önlendi) ve gelecekte `phishing_classifier`, `visual_analyzer` modüllerinin aynı DB altyapısını kod tekrarı olmadan kullanabilmesi.

### ADR-005: BaseRepository (Soyut Temel Sınıf / Repository Pattern)
- **Karar:** Tüm veritabanı işlemlerini jenerik CRUD fonksiyonları sunan `BaseRepository` (`src/core/db/base.py`) soyut temel sınıfı üzerinden yürütmek. Modüller kendi repository sınıflarını (`ActiveDomainRepository`) bu sınıftan türetir.
- **Gerekçe:** DRY prensibi, modülerlik, kolay birim testleri (unit testing/mocking) ve güvenli transaction/session yönetimi.

### ADR-006: Independent Phishing Risk Classifier Architecture & Risk Weighting Matrix
- **Karar:** 
  1. `phishing_classifier` (`src/phishing_classifier/`) modülü `domain_is_active` canlılık kontrolcüsünden **tamamen bağımsız** modüler bir yapı olarak tasarlanacaktır. `domain_is_active` verileri toplar; `phishing_classifier` ise bu verileri veya harici öznitelik nesnelerini girdi alarak risk hesaplar.
  2. **0-100 Ağırlıklı Risk Skorlama:** Risk puanı HTML (Form & Şifre kutusu), Leksikal (Typosquatting), WHOIS (Alan adı yaşı, privacy proxy) ve SSL/Network sinyallerinin ağırlıklı toplamı ile hesaplanacak ve 100 ile sınırlandırılacaktır (Skor Skalası: 0-19 Benign, 20-39 Low, 40-61 Medium, 62-84 High, 85-100 Critical).
  3. **DB Modeli (`PhishingRiskAssessment`):** `src/core/db/` ortak altyapısı kullanılarak `phishing_risk_assessments` tablosunda skor, risk seviyesi ve tetiklenen sinyal detayları (JSON/Text) saklanacaktır.
- **Gerekçe:** Esneklik, modüller arası tam ayrık çalışma (Loose Coupling).

### ADR-007: Database-Backed Whitelist (`whitelist_domains`) & In-Memory Caching
- **Karar:** Whitelist verileri statik metin dosyası yerine SQLite veritabanında `whitelist_domains` tablosunda tutulacak, ilk çalıştırmada seed edilecek ve `WhitelistManager` tarafından toplu taramalarda O(1) arama hızı için belleğe (`set`) önbelleklenecektir.
- **Gerekçe:** Kolay yönetim, veritabanı sorgulanabilirliği ve yüksek performans.

### ADR-008: Multi-Worksheet Single Excel Workbook Reporting
- **Karar:** Phishing risk analizi sonuçları ayrı bir Excel dosyası yerine mevcut `.xlsx` rapor kitabına **Sayfa 2: "Phishing Risk Analizi"** olarak eklenecektir.
- **Gerekçe:** Kullanıcı deneyimi, tek raporda hem canlılık hem risk detaylarına bütüncül erişim.


