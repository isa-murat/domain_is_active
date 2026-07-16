# Proje Tasarım Notları (Phishing Active & Correlation Tool)

Bu döküman, 1 haftalık geliştirme sürecinde "over-engineering" (aşırı mühendislik) yapmadan, en basit ve etkili şekilde çalışan bir hibrit sistem oluşturmak için karar verilen mimariyi ve teknik detayları içerir. AI IDE ile kod yazarken bu rehber referans alınacaktır.

---

## 1. Genel Akış ve Mimari (Hibrit & Keşif Odaklı)

Sistem, girdi olarak verilen domain listesini dinamik bir kuyruğa yükler. Her domain için parmak izleri (favicon, SSL, SPKI) toplanır. Toplanan bu parmak izleri ile yeni ilişkili domainler avlanır ve kuyruğa eklenir. Sonrasında domain aktiflik durumu belirlenir ve raporlanır.

```
                  [ Girdi Domain Listesi ]
                             │
                             ▼
                    [ Dinamik Kuyruk ] ◄────────────────┐
                             │                          │
                             ▼                          │ (Keşfedilen Yeni
             [ Parmak İzi Toplama Aşaması ]             │  Domainler Eklenir)
            ├── A. Lokal Bağlantı (Port 443)            │
            └── B. URLScan Geçmiş Sorgusu (Yedek)        │
                             │                          │
                             ▼                          │
             [ Korelasyon & Tehdit Avcılığı ] ──────────┘
            ├── Arama: Aynı Favicon Hash'ine Sahip Domainler
            └── Arama: Aynı SPKI SHA256 Değerine Sahip Domainler
                             │
                             ▼
             [ Aktiflik Kontrolü Aşaması ]
            ├── DNS Kontrolleri (A, MX, NS)
            ├── WHOIS Durum Kodları (Hold)
            └── HTTP/HTTPS İstek Analizi (Status, DOM, Redirect)
                             │
                             ▼
              [ Karar Motoru ve Raporlama ]
            └── ACTIVE, PARKED, TAKEN_DOWN, INACTIVE
```

---

## 2. Teknik Detaylar ve Kütüphaneler

Projeyi en sade şekilde tutmak için standart Python kütüphaneleri ve en popüler harici kütüphaneler tercih edilecektir.

### A. Gerekli Kütüphaneler (requirements.txt)
*   `requests` -> HTTP istekleri ve URLScan API sorguları için.
*   `python-whois` -> WHOIS EPP durumlarını sorgulamak için.
*   `dnspython` -> Detaylı DNS (A, MX, NS) sorguları için.
*   `mmh3` -> Favicon için MurmurHash3 hesaplamada kullanılır.
*   `pandas` veya `openpyxl` -> Sonuçları Excel formatında kaydetmek için.

### B. Parmak İzi (Fingerprint) Hesaplama Yöntemleri

#### 1. SSL Sertifikası SHA256/SHA1 ve SPKI (Lokal)
Python `ssl` ve `hashlib` modülleri ile doğrudan sunucudan sertifika çekilir:
*   **SSL SHA256/SHA1:** Çekilen DER formatındaki sertifikanın doğrudan SHA256 ve SHA1 özetleri alınır.
*   **SPKI (Subject Public Key Info) SHA256:** Sertifikanın içindeki Public Key bilgisi çıkartılır ve SHA256 hash'i alınır.

#### 2. Favicon Hash (Lokal)
*   Sitenin `favicon.ico` dosyası indirilir (veya HTML içindeki `<link rel="icon">` okunur).
*   Görselin ham byte verisi Base64 formatına çevrilip `mmh3.hash()` (MurmurHash3) ile parmak izi hesaplanır (URLScan ve Shodan ile uyumlu olması için).

#### 3. URLScan.io API Entegrasyonu (Yedek)
Lokal bağlantı kurulamadığında veya ek veri gerektiğinde:
*   **Endpoint:** `https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>`
*   **Aksiyon:** Dönen JSON yanıtından en son başarılı taramanın `uuid` değeri alınır ve parmak izleri (`lists.hashes.favicon`, `lists.certificates` vb.) çekilir.

---

## 3. Korelasyon ve Yeni Domain Keşfi (Threat Hunting)

Toplanan parmak izleri kullanılarak URLScan API üzerinden tersine arama (reverse search) gerçekleştirilir:

1.  **Favicon Arama Sorgusu:**
    *   URLScan API: `https://urlscan.io/api/v1/search/?q=http.response.favicon.hash:"<FAVICON_HASH>"`
2.  **SPKI Arama Sorgusu:**
    *   URLScan API: `https://urlscan.io/api/v1/search/?q=ssl.cert.subject_public_key_info.sha256:"<SPKI_HASH>"`

**Kural:** Arama sonuçlarından dönen benzersiz (unique) domainler ayıklanır. Daha önce taranmamış ve kuyrukta bulunmayan yeni domainler dinamik olarak **Dinamik Kuyruk** yapısına eklenir.

---

## 4. Karar Matrisi Kuralları

Otomasyonun domain durumuna karar verirken uygulayacağı mantık:

1.  **TAKEN_DOWN:** WHOIS sorgusunda `clientHold` veya `serverHold` kodları varsa ya da DNS çözümlenemiyorsa (ve geçmişte aktif olduğu biliniyorsa).
2.  **INACTIVE:** DNS çözümlenemiyor ve WHOIS hold değilse (site ölü veya kaydı silinmiş).
3.  **PARKED:** DNS çözülüyor ancak IP adresi bilinen bir park şirketine aitse veya sayfa içeriğinde park kelimeleri ("this domain is for sale", "buy this domain") geçiyorsa.
4.  **ACTIVE:** HTTP isteğine 200/3xx dönüyor, sayfa içeriğinde veya başlığında marka taklidi ya da şüpheli formlar barındırıyorsa.

---

## 5. Geliştirme Planı (Adım Adım)

*   **Adım 1:** Python sanal ortamının kurulması ve `requirements.txt` hazırlanması.
*   **Adım 2:** Lokal SSL/SPKI ve Favicon hash çıkarma fonksiyonlarının yazılması.
*   **Adım 3:** URLScan.io arama ve detay API entegrasyonunun yazılması.
*   **Adım 4:** Dinamik kuyruk yapısının kodlanması ve URLScan ters sorgularıyla **Tehdit Avcılığı / Keşif** modülünün yazılması.
*   **Adım 5:** DNS ve WHOIS kontrollerinin entegre edilmesi.
*   **Adım 6:** Karar mantığının kurulması ve Excel/CSV raporlayıcının yazılması.
*   **Adım 7:** CSV'deki 45 domain ile testlerin yapılması ve raporun doğrulanması.
