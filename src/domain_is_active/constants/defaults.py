"""Varsayılan konfigürasyon ve zaman aşımı sabitleri."""

DEFAULT_TIMEOUT_SECONDS: float = 5.0
DEFAULT_MAX_THREADS: int = 10
DEFAULT_MAX_CORRELATED_PER_DOMAIN: int = 5

DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Bilinen jenerik park firması NS kelimeleri
PARKING_NS_KEYWORDS = [
    "parking",
    "sedo",
    "bodis",
    "parkingcrew",
    "above.com",
    "domainmarket",
]

# Bilinen park/satılık içerik kelimeleri
PARKING_CONTENT_KEYWORDS = [
    "for sale",
    "satiliktir",
    "satılıktır",
    "buy this domain",
    "under construction",
    "bu alan adı satılıktır",
    "domain is for sale",
]

# Bilinen Jenerik SSL SPKI Hash'leri (Cloudflare Shared, Let's Encrypt default wildcards)
# Bu hash'ler URLScan korelasyonunda gürültü yapmamak için filtrelenir.
GENERIC_SPKI_HASH_IGNORELIST = {
    # Cloudflare Universal SSL shared SPKI (örnek)
    "0000000000000000000000000000000000000000000000000000000000000000",
}

# Bilinen Jenerik Favicon Hash'leri (Apache default, Nginx 404, cPanel default)
GENERIC_FAVICON_HASH_IGNORELIST = {
    # Apache2 default favicon sha256
    "6da5620880159634213e197fafca1dde0272153be3e4590818533fab8d040770",  # Örnek/test hash
}
