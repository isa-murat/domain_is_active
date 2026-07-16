# Phishing Otomasyonu Karar ve Veri Akış Şeması

Bu dosya, girdi olarak verilen bir alan adının (domain), sistemimiz içindeki tüm kontrol aşamalarından geçerek nihai **ACTIVE / PARKED / INACTIVE / TAKEN_DOWN** kararına ulaşma akışını ve **korelasyon tabanlı yeni domain keşfi (Threat Hunting)** döngüsünü belgeler.

---

## 1. Karar ve Keşif Akış Şeması (Mermaid)

Yeni mimaride sisteme bir **Geri Besleme (Feedback Loop) / Keşif Döngüsü** eklenmiştir. Analiz edilen domainlerden elde edilen parmak izleri ile yeni domainler avlanır ve bunlar kuyruğa tekrar eklenir.

```mermaid
graph TD
    %% Girdi ve Kuyruk
    Start([1. Başlangıç]) --> InitQueue[Domain Kuyruğu Oluştur\n(CSV Listesi)]
    InitQueue --> PopQueue{Kuyrukta Domain Var mı?}
    
    PopQueue -- Hayır --> GenerateFinalReport[9. Nihai Raporu Oluştur\n(Excel/HTML)]
    GenerateFinalReport --> End([Tarama Sonu])
    
    PopQueue -- Evet --> GetNext[Sıradaki Domaini Al]
    
    %% DNS ve WHOIS Aşamaları
    GetNext --> CheckDNS{2. DNS Çözümleniyor mu?}
    
    CheckDNS -- Evet --> CheckWhoisHold{3. WHOIS Hold Var mı?}
    CheckWhoisHold -- Evet --> DecisionTD[TAKEN_DOWN\nRegistrar Askıya Almış]
    
    %% Bağlantı Aşaması
    CheckWhoisHold -- Hayır --> TryConnect{4. Canlı Bağlantı\n(HTTPS - Port 443)}
    
    %% Canlı Bağlantı Başarılı
    TryConnect -- Başarılı --> FetchLocalInfo[Sertifika & Favicon İndir\nSPKI & Favicon Hash Hesapla]
    
    %% Canlı Bağlantı Başarısız
    TryConnect -- Başarısız --> QueryURLScan{8. URLScan API Sorgusu\nGeçmiş Tarama Var mı?}
    QueryURLScan -- Evet --> ExtractHistorical[Geçmiş Parmak İzlerini Çek]
    ExtractHistorical --> DecisionTD_Hist[TAKEN_DOWN\nGeçmişte aktifmiş, şimdi kapalı]
    QueryURLScan -- Hayır --> DecisionInactive[INACTIVE\nUlaşılamıyor, geçmişi yok]

    %% DNS Hayır Akışı
    CheckDNS -- Hayır --> CheckWhoisHoldDNS{3b. WHOIS Hold Var mı?}
    CheckWhoisHoldDNS -- Evet --> DecisionTD
    CheckWhoisHoldDNS -- Hayır --> DecisionInactive

    %% KORELASYON VE KEŞİF DÖNGÜSÜ (YENİ SÜREÇ)
    FetchLocalInfo --> CorrelationSearch{5. Korelasyon Araması\n(URLScan API Reverse Search)}
    ExtractHistorical --> CorrelationSearch
    
    CorrelationSearch --> GetRelated[İlişkili Yeni Domainleri Bul\n(Aynı Favicon/SPKI kullananlar)]
    GetRelated --> FilterNew{Bu Domainler Daha Önce\nTaranmadı mı?}
    FilterNew -- Evet --> AddToQueue[Kuyruğa Ekle\n(Yeni Bulunan Domainler)]
    AddToQueue --> CheckHTTPStatus
    FilterNew -- Hayır --> CheckHTTPStatus

    %% HTTP ve İçerik Analizi
    CheckHTTPStatus{6. HTTP Durumu nedir?}
    
    CheckHTTPStatus -- 200 OK --> AnalyzeContent{7. İçerik Analizi\nForm/Marka Taklidi?}
    AnalyzeContent -- Evet --> DecisionActive[ACTIVE\nCanlı Phishing]
    AnalyzeContent -- Hayır --> CheckParking{8. Parking İncelemesi}
    
    CheckParking -- Evet --> DecisionParked[PARKED]
    CheckParking -- Hayır --> DecisionSuspicious[SUSPICIOUS / INACTIVE]

    CheckHTTPStatus -- 5xx / Hata --> DecisionUnstable[UNSTABLE]
    CheckHTTPStatus -- 403 / 404 --> DecisionUnstable

    %% Kararların Rapor Kuyruğuna Gönderilmesi
    DecisionTD --> SaveTemp[Sonuçları Belleğe Kaydet]
    DecisionTD_Hist --> SaveTemp
    DecisionActive --> SaveTemp
    DecisionParked --> SaveTemp
    DecisionSuspicious --> SaveTemp
    DecisionUnstable --> SaveTemp
    DecisionInactive --> SaveTemp
    
    SaveTemp --> PopQueue
```

---

## 2. Mimari Değişiklikler ve Yeni Süreçler

Eski düz akışa kıyasla yapılan mimari değişiklikler şunlardır:

1.  **Dinamik Kuyruk Yönetimi (Queue Management):** Tarama listesi sabit bir CSV okuyucusundan çıkarılıp dinamik bir kuyruk yapısına dönüştürülmüştür. Script çalışırken yeni domainler keşfederse bunları kuyruğa ekler ve tarama kapsamını genişletir.
2.  **Korelasyon Sorgu Modülü (Correlation Module):** Bir domainin taraması bittiğinde veya geçmiş verisi çekildiğinde, elde edilen `Favicon Hash` ve `SPKI SHA256` değerleri kullanılarak URLScan API'si üzerinden ters arama yapılır.
3.  **Tekilleştirme Filtresi (Deduplication Filter):** Keşfedilen yeni domainlerin sonsuz döngü yaratmaması veya mükerrer taranmaması için daha önce tarananlar veya kuyrukta olanlar elenir.
