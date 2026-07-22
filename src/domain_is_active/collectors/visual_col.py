import io
import requests
from typing import Optional
from PIL import Image
from domain_is_active.constants.defaults import DEFAULT_TIMEOUT_SECONDS, DEFAULT_USER_AGENT


class VisualCollector:
    """
    Ekran görüntüsü indirip Algısal Hash (dHash - Difference Hash) üreten
    ve iki ekran görüntüsü arasındaki görsel benzerliği hesaplayan modül.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT}

    @staticmethod
    def calculate_dhash(image_bytes: bytes) -> Optional[str]:
        """
        Görsel verisinden 64-bit dHash (Difference Hash) hex string üretir.
        
        Args:
            image_bytes (bytes): Görsel dosya içeriği (PNG/JPG).
            
        Returns:
            str | None: 16 karakterlik hex dHash değeri.
        """
        try:
            image = Image.open(io.BytesIO(image_bytes)).convert("L")
            # 9x8 boyutuna indirgeyerek piksel farklarını hesaplıyoruz
            resized = image.resize((9, 8), Image.Resampling.LANCZOS)
            pixels = list(resized.getdata())

            difference = []
            for row in range(8):
                for col in range(8):
                    pixel_left = pixels[row * 9 + col]
                    pixel_right = pixels[row * 9 + col + 1]
                    difference.append(pixel_left > pixel_right)

            decimal_value = 0
            for i, val in enumerate(difference):
                if val:
                    decimal_value += 1 << i

            return f"{decimal_value:016x}"
        except Exception:
            return None

    @staticmethod
    def hamming_distance(hash1: str, hash2: str) -> int:
        """İki dHash hex string arasındaki Hamming Mesafesini (Farklı bit sayısı) hesaplar."""
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 64
        try:
            n1 = int(hash1, 16)
            n2 = int(hash2, 16)
            x = n1 ^ n2
            return bin(x).count("1")
        except Exception:
            return 64

    def fetch_screenshot_dhash(self, screenshot_url: str) -> Optional[str]:
        """
        URLScan screenshot URL'sinden resmi indirir ve dHash değerini hesaplar.
        """
        if not screenshot_url or screenshot_url == "-":
            return None

        try:
            res = requests.get(screenshot_url, headers=self.headers, timeout=self.timeout)
            if res.status_code == 200:
                return self.calculate_dhash(res.content)
        except Exception:
            pass

        return None
