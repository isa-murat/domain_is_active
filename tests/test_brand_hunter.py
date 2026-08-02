import pytest
from domain_is_active.hunting.brand_hunter import URLScanBrandHunter, TARGET_INSTITUTIONS, BrandTarget


def test_target_institutions_count():
    assert len(TARGET_INSTITUTIONS) == 11
    names = [t.name for t in TARGET_INSTITUTIONS]
    assert "A101" in names
    assert "Togg" in names
    assert "Garanti Bankası" in names
    assert "Vakıfbank" in names
    assert "İş Bankası" in names
    assert "Borsa İstanbul" in names
    assert "Takasbank" in names
    assert "Otokoç" in names
    assert "Azercell" in names
    assert "BIDV" in names
    assert "THE BODY SHOP" in names


def test_brand_hunter_whitelist_filtering():
    hunter = URLScanBrandHunter()

    target = BrandTarget(
        name="Garanti Bankası",
        keywords=["garanti"],
        official_domains=["garanti.com.tr", "garantibbva.com.tr"],
        search_query='page.domain:*garanti*',
    )

    # Fake raw domain response including official domains and suspicious domain
    fake_raw = {"garanti.com.tr", "sub.garantibbva.com.tr", "sahte-garanti-islemleri.xyz"}
    hunter.hunter._execute_query = lambda q: fake_raw

    filtered = hunter.search_brand(target, hours=24)

    assert "garanti.com.tr" not in filtered
    assert "sub.garantibbva.com.tr" not in filtered
    assert "sahte-garanti-islemleri.xyz" in filtered
