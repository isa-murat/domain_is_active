import os
import pytest
from PIL import Image
import io
from phishing_classifier.visual import VisualRiskAnalyzer
from phishing_classifier.enums import RiskSignalCategory


def test_visual_analyzer_with_reference_image(tmp_path):
    ref_dir = tmp_path / "reference_screenshots"
    ref_dir.mkdir()

    # Create a simple reference image
    img = Image.new("RGB", (200, 200), color="blue")
    img_path = ref_dir / "garanti.png"
    img.save(img_path)

    analyzer = VisualRiskAnalyzer(reference_dir=str(ref_dir))

    # Calculate dHash of reference image
    ref_dhash = analyzer._reference_hashes[0][1]

    # Test exact match (Hamming distance = 0)
    data = {"screenshot_dhash": ref_dhash}
    result = analyzer.analyze("phishing-garanti.com", data)

    assert result.score == 50
    assert len(result.signals) == 1
    assert "garanti" in result.signals[0]
    assert result.category == RiskSignalCategory.VISUAL_CLONE


def test_visual_analyzer_no_match(tmp_path):
    ref_dir = tmp_path / "reference_screenshots"
    ref_dir.mkdir()

    analyzer = VisualRiskAnalyzer(reference_dir=str(ref_dir))
    result = analyzer.analyze("random-site.com", {"screenshot_dhash": "ffffffffffffffff"})

    assert result.score == 0
    assert len(result.signals) == 0
