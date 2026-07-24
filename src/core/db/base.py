import contextlib
from typing import Generic, TypeVar, Type, List, Optional, Any
from sqlalchemy.orm import Session, sessionmaker
from core.db.database import get_session_factory, Base

T = TypeVar("T", bound=Base)


class BaseRepository(Generic[T]):
    """
    Tüm modül repository sınıflarının miras alacağı jenerik CRUD ve
    transaction yöneticisi olan Soyut Temel Sınıf (Abstract Base Repository).
    """

    def __init__(self, model: Type[T], session_factory: Optional[sessionmaker] = None):
        self.model = model
        self.session_factory = session_factory or get_session_factory()

    @contextlib.contextmanager
    def session_scope(self) -> Session:
        """
        Thread-safe session yaşam döngüsü sağlayan context manager.
        Hata durumunda otomatik rollback yapar ve session'ı kapatır.
        """
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def add(self, entity: T) -> T:
        """Tek bir veriyi veritabanına ekler."""
        with self.session_scope() as session:
            session.add(entity)
            session.refresh(entity)
            return entity

    def bulk_add(self, entities: List[T]) -> None:
        """Toplu veri eklemesi yapar."""
        if not entities:
            return
        with self.session_scope() as session:
            session.add_all(entities)

    def get_by_id(self, entity_id: Any) -> Optional[T]:
        """ID üzerinden tekil nesne getirir."""
        with self.session_scope() as session:
            return session.query(self.model).get(entity_id)

    def get_all(self, limit: int = 1000) -> List[T]:
        """Tüm kayıtları getirir."""
        with self.session_scope() as session:
            return session.query(self.model).limit(limit).all()
