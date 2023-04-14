from typing import List
from typing import Optional
from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

class Base(DeclarativeBase):
    pass

class Host(Base):
    __tablename__ = "host"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(30))
    name: Mapped[Optional[str]]

    def __repr__(self) -> str:
        return f"Host(id={self.id!r}, name={self.name!r}, fullname={self.ip!r})"

class Certificate(Base):
    __tablename__ = "certificate"
    id: Mapped[int] = mapped_column(primary_key=True)
    cn: Mapped[str]
    SAN: Mapped[List["SAN"]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )
    def __repr__(self) -> str:
        return f"Cert(id={self.id!r}, cn={self.cn!r})"
    
class SAN(Base):
    __tablename__ = "subject_alternative_name"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str]
    type: Mapped[str]
    user_id: Mapped[int] = mapped_column(ForeignKey("certificate.id"))
    certificate: Mapped["Certificate"] = relationship(back_populates="SAN")
    def __repr__(self) -> str:
        return f"Address(id={self.id!r}, email_address={self.email_address!r})"    