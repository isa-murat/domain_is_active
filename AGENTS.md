# Project-Scoped Coding Rules (Phishing Active & Correlation Tool)

Bu dosya, bu projede çalışırken AI IDE'ler (Antigravity, Cursor vb.) tarafından uyulması gereken kodlama standartlarını, mimari kuralları, Hafıza Bankası (Memory Bank) ve Git/GitHub kullanım yönergelerini tanımlar.

---

## 1. Kodlama Standartları ve Kurallar

1. **Dil ve Yapı:**
   - Tüm kodlar Python 3.9+ uyumlu olmalıdır.
   - Kodlarda tip ipuçları (type hints) kullanılmalıdır (`def check_dns(domain: str) -> bool:` gibi).
   - Tüm fonksiyon ve sınıflar için Türkçe veya İngilizce docstring açıklama blokları yazılmalıdır.

2. **Modüler Klasör Yapısı ve Düzeni:**
   - Kök dizine yeni Python dosyası eklenmemelidir. 
   - İlgili tüm kodlar belirlenen modül klasörleri altında geliştirilmelidir:
     - `collectors/`: Bağımsız veri toplayıcılar (DNS, WHOIS, SSL, HTTP)
     - `constants/`: Merkezi Enum ve varsayılan sabitler
     - `hunting/`: URLScan Multi-Vector avcılık ve benzerlik modülleri
     - `checker/`: Karar Facade sınıfı
     - `exporters/`: Raporlama üreticileri

3. **Merkezi Enum (TextChoices) Kullanımı:**
   - Kod içerisinde saçılmış hardcoded string ifadeleri (`"ACTIVE (AKTIF)"`, `"favicon"` vb.) **kesinlikle kullanılmamalıdır.**
   - Tüm durumlar ve parametreler `domain_is_active.constants.enums` (`ScanDecision`, `HuntingVector`, `ReportColors`) üzerinden çağrılmalıdır.

4. **Hata Yönetimi (Error Handling) & SSL Handling:**
   - Ağ istekleri (DNS, HTTP, SSL, WHOIS) doğası gereği kararsız olduğundan, her işlem mutlaka `try-except` blokları ile sarmalanmalıdır.
   - Hatalar programı çökertmemeli, ilgili domainin sonucuna hata mesajı yazılarak bir sonraki domaine geçilmelidir.
   - Phishing sitelerindeki geçersiz/self-signed SSL sertifikalarında `CERT_NONE` context kullanılarak SPKI hash'inin çıkarılması garanti edilmelidir.

5. **Performans, Hız ve Thread Pool:**
   - Ağ işlemlerinde mutlaka makul zaman aşımları (`timeout=5` saniye gibi) tanımlanmalıdır.
   - `ThreadPoolExecutor` döngü içinde baştan oluşturulmamalı, tek bir kez başlatılarak thread churn önlenmelidir.

6. **Güvenlik:**
   - Phishing domainlerine HTTP istekleri gönderirken sadece `GET` yöntemi kullanılmalı ve asla POST verisi gönderilmemelidir.
   - İsteklerde `constants/defaults.py` içerisinde tanımlı standart tarayıcı başlıkları (User-Agent) kullanılmalıdır.

---

## 2. Git ve GitHub Kullanım Kuralları (Git & GitHub Workflow Rules)

1. **Doğrudan `main` Branch'ine Commit Yasaktır:**
   - `main` branch'ine doğrudan commit atılamaz. Tüm geliştirmeler amaca uygun yeni bir branch üzerinde yapılmalıdır.

2. **Branch İsimlendirme Standartları:**
   - Refactoring için: `refactor/vX.Y.Z-tanim` (Örn: `refactor/v0.1.0-modular`)
   - Yeni Özellikler için: `feat/ozellik-adi` (Örn: `feat/sqlite-alembic-db`, `feat/phishing-risk-classifier`)
   - Dokümantasyon için: `docs/dokuman-adi` (Örn: `docs/memory-bank`)
   - Hata Düzeltme için: `fix/hata-adi` (Örn: `fix/ssl-verification-fix`)

3. **Commit Mesajı Formatı (Conventional Commits):**
   - Commit mesajları yapılan işi açıkça ifade etmelidir: `type(scope): açıklama`
   - Örnek: `docs(memorybank): add projectState, roadmap and AGENTS.md workflow rules`

4. **Pull Request ve GitHub Merge Protokolü:**
   - Geliştirme tamamlandığında branch uzak sunucuya pushlanır (`git push -u origin <branch-name>`).
   - GitHub CLI (`gh`) kullanılarak PR açılır: `gh pr create --title "..." --body "..."`
   - PR incelemesinden sonra birleştirme `gh pr merge --merge --delete-branch` komutuyla yapılır ve birleşen branch otomatik silinir.

---

## 3. Hafıza Bankası (Memory Bank) Yönergeleri

AI IDE'ler proje üzerinde çalışırken aşağıdaki Hafıza Bankası dosyalarını anlık olarak takip etmek ve güncel tutmakla yükümlüdür:

* **`docs/memorybank/projectState.md`:** Tamamlanan modüller ve mevcut proje durumunun takibi.
* **`docs/memorybank/roadmap.md`:** Gelecek sürümlerde açılacak özellik branch'leri ve yol haritası.
* **`docs/memorybank/decisionLog.md`:** Alınan mimari kararlar (ADR) ve gerekçeleri.
