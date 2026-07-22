"""
Domain adı ve marka adı dizgi benzerliklerini (Levenshtein distance)
hesaplayan yardımcı modül.
"""


def levenshtein_distance(s1: str, s2: str) -> int:
    """İki string arasındaki Levenshtein mesafesini hesaplar."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def similarity_ratio(s1: str, s2: str) -> float:
    """
    İki metin arasındaki benzerlik oranını (0.0 ile 1.0 arası) hesaplar.
    1.0 = Birebir aynı.
    """
    s1_clean = s1.lower().strip()
    s2_clean = s2.lower().strip()
    if not s1_clean or not s2_clean:
        return 0.0

    distance = levenshtein_distance(s1_clean, s2_clean)
    max_len = max(len(s1_clean), len(s2_clean))
    if max_len == 0:
        return 1.0
    return 1.0 - (distance / max_len)
