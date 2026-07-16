# Project-Scoped Coding Rules (Phishing Active & Correlation Tool)

Bu dosya, bu projede çalışırken AI IDE (Antigravity) tarafından uyulması gereken kodlama standartlarını tanımlar.

## Kodlama Standartları ve Kurallar

1.  **Dil ve Yapı:**
    *   Tüm kodlar Python 3.9+ uyumlu olmalıdır.
    *   Kodlarda tip ipuçları (type hints) kullanılmalıdır (`def check_dns(domain: str) -> bool:` gibi).
    *   Tüm fonksiyon ve sınıflar için Türkçe veya İngilizce docstring açıklama blokları yazılmalıdır.

2.  **Hata Yönetimi (Error Handling):**
    *   Ağ istekleri (DNS, HTTP, SSL, WHOIS) doğası gereği kararsız olduğundan, her işlem mutlaka `try-except` blokları ile sarmalanmalıdır.
    *   Hatalar programı çökertmemeli, ilgili domainin sonucuna hata mesajı yazılarak bir sonraki domaine geçilmelidir.

3.  **Performans ve Hız:**
    *   Ağ işlemlerinde mutlaka makul zaman aşımları (`timeout=5` saniye gibi) tanımlanmalıdır. Zaman aşımı belirtilmeyen istekler engellenmelidir.

4.  **Güvenlik:**
    *   Phishing domainlerine HTTP istekleri gönderirken sadece `GET` yöntemi kullanılmalı ve asla POST verisi gönderilmemelidir.
    *   İsteklerde sahte tarayıcı başlıkları (User-Agent) kullanılmalıdır.
