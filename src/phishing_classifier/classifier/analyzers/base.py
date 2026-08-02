from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from phishing_classifier.enums import RiskSignalCategory


@dataclass
class AnalysisResult:
    """Tekil bir analizörün ürettiği puan ve sinyal detayları."""

    score: int
    signals: List[str]
    category: RiskSignalCategory


class BaseAnalyzer(ABC):
    """Tüm vektör analizörlerinin türetildiği soyut temel sınıf."""

    @abstractmethod
    def analyze(self, domain: str, data: Dict[str, Any]) -> AnalysisResult:
        """
        Toplanan domain verilerini analiz eder ve eklenen puanı ile sinyal listesini döndürür.
        """
        pass
