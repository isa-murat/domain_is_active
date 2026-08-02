import os
import io
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image
from phishing_classifier.classifier.analyzers.base import BaseAnalyzer, AnalysisResult
from phishing_classifier.enums import RiskSignalCategory
from domain_is_active.collectors.visual_col import VisualCollector


class VisualRiskAnalyzer(BaseAnalyzer):
    """
    Görsel Algısal Hash (dHash) Klon Tespiti Analizörü.
    'assets/reference_screenshots/' dizinindeki meşru kurum ekran görüntüleri
    ile aday sitenin URLScan ekran görüntüsünü kıyaslayarak sahte klon siteleri tespit eder.
    """

    def __init__(
        self,
        reference_dir: str = "assets/reference_screenshots",
        similarity_threshold_bits: int = 10,  # Max 10 bit fark -> %84.3+ benzerlik
    ):
        self.reference_dir = reference_dir
        self.similarity_threshold_bits = similarity_threshold_bits
        self.collector = VisualCollector()
        self._reference_hashes: List[Tuple[str, str]] = []  # (brand_name, dhash)
        self._load_reference_hashes()

    def _load_reference_hashes(self):
        """Referans klasöründeki ('assets/reference_screenshots') tüm görsellerin dHash değerlerini önbelleğe yükler."""
        self._reference_hashes.clear()
        
        target_dir = self.reference_dir or "assets/reference_screenshots"
        if not os.path.exists(target_dir):
            try:
                os.makedirs(target_dir, exist_ok=True)
            except Exception:
                pass
            return

        for filename in os.listdir(target_dir):
            ext = os.path.splitext(filename)[1].lower()
            if ext in [".png", ".jpg", ".jpeg", ".webp"]:
                brand_name = os.path.splitext(filename)[0].lower()
                filepath = os.path.abspath(os.path.join(target_dir, filename))

                try:
                    with open(filepath, "rb") as f:
                        image_bytes = f.read()
                        dhash = self.collector.calculate_dhash(image_bytes)
                        if dhash:
                            self._reference_hashes.append((brand_name, dhash))
                except Exception as e:
                    print(f"[!] Referans görsel okuma hatası ({filename}): {e}")

    def reload_references(self):
        """Referans görsellerini yeniden yükler."""
        self._load_reference_hashes()

    def analyze(self, domain: str, data: Dict[str, Any]) -> AnalysisResult:
        """
        Aday domainin screenshot_url veya screenshot_dhash verisini referans görsellerle kıyaslar.
        """
        score = 0
        signals = []

        if not self._reference_hashes:
            return AnalysisResult(score=score, signals=signals, category=RiskSignalCategory.VISUAL_CLONE)

        screenshot_url = data.get("screenshot_url")
        candidate_dhash = data.get("screenshot_dhash")

        # Eğer dHash hazır verilmediyse screenshot URL'den indir
        if not candidate_dhash and screenshot_url and screenshot_url != "-":
            candidate_dhash = self.collector.fetch_screenshot_dhash(screenshot_url)

        if not candidate_dhash:
            return AnalysisResult(score=score, signals=signals, category=RiskSignalCategory.VISUAL_CLONE)

        # Tüm referans görseller ile Hamming mesafesini kıyasla
        best_match_brand = None
        min_distance = 64

        for brand_name, ref_hash in self._reference_hashes:
            dist = self.collector.hamming_distance(candidate_dhash, ref_hash)
            if dist < min_distance:
                min_distance = dist
                best_match_brand = brand_name

        # Eşik değer kontrolü
        if min_distance <= self.similarity_threshold_bits and best_match_brand:
            similarity_percent = ((64 - min_distance) / 64.0) * 100.0
            score += 50
            signals.append(
                f"[Görsel Klon Tespiti] Sitenin ekran görüntüsü '{best_match_brand}' meşru markasının referans "
                f"görseli ile %{similarity_percent:.1f} oranında görsel benzerlik gösteriyor (Hamming mesafesi: {min_distance})."
            )

        return AnalysisResult(score=score, signals=signals, category=RiskSignalCategory.VISUAL_CLONE)

