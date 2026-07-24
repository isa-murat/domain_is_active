import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.db.database import Base
from domain_is_active.models import ActiveDomainScan, ActiveScanHistory
from domain_is_active.repository import ActiveDomainRepository


@pytest.fixture
def in_memory_repo():
    """Testler için bellek içi (in-memory) SQLite veritabanı oluşturan fixture."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return ActiveDomainRepository(session_factory=session_factory)


def test_save_and_retrieve_scan(in_memory_repo):
    """Domain tarama sonucunun kaydedilmesi ve okunması testi."""
    record = {
        "domain": "phishing-test.xyz",
        "decision": "ACTIVE (AKTIF)",
        "reason": "HTTP 200 OK",
        "dns_resolved": "Evet",
        "ipv4_addresses": "1.2.3.4",
        "ssl_valid": "Evet",
    }
    in_memory_repo.save_scan_result(record)

    results = in_memory_repo.get_all_as_dict()
    assert len(results) == 1
    assert results[0]["domain"] == "phishing-test.xyz"
    assert results[0]["decision"] == "ACTIVE (AKTIF)"


def test_upsert_and_history_logging(in_memory_repo):
    """Domain kararının değişmesi durumunda tarihsel log kaydı oluşma testi."""
    record1 = {
        "domain": "phishing-test.xyz",
        "decision": "ACTIVE (AKTIF)",
        "reason": "HTTP 200 OK",
    }
    in_memory_repo.save_scan_result(record1)

    # Karar değişti: TAKEDOWN
    record2 = {
        "domain": "phishing-test.xyz",
        "decision": "TAKEDOWN (KAPATILMIS)",
        "reason": "WHOIS hold statusu tespit edildi",
    }
    in_memory_repo.save_scan_result(record2)

    # Ana tabloda 1 güncel kayıt olmalı
    results = in_memory_repo.get_all_as_dict()
    assert len(results) == 1
    assert results[0]["decision"] == "TAKEDOWN (KAPATILMIS)"

    # History tablosunda 1 tarihsel değişim kaydı olmalı
    with in_memory_repo.session_scope() as session:
        history = session.query(ActiveScanHistory).all()
        assert len(history) == 1
        assert history[0].domain == "phishing-test.xyz"
        assert history[0].decision == "TAKEDOWN (KAPATILMIS)"
