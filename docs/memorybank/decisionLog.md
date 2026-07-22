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

### ADR-004: SQLite & Alembic Veritabanı Mimarisi
- **Karar:** Veritabanı katmanı için SQLite + Alembic seçildi.
- **Gerekçe:** Sıfır ek sunucu bağımlılığı, hızlı entegrasyon ve gelecekte PostgreSQL'e kod değiştirmeden geçiş olanağı.
