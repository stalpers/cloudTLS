from typing import List
from typing import Optional
from sqlalchemy import ForeignKey
from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
import datetime
class Base(DeclarativeBase):
    pass

class ScanSession(Base):
    __tablename__ = "scan_session"
    id: Mapped[int] = mapped_column(primary_key=True)
    parse_date: Mapped[DateTime] = mapped_column(DateTime(30))
    hosts: Mapped[List["Host"]] = relationship(back_populates="scan_session")


class Certificate(Base):
    __tablename__ = "certificate"
    id: Mapped[int] = mapped_column(primary_key=True)
    cn: Mapped[str]
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id"))
    host: Mapped["Host"] = relationship(back_populates="certificate")



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
    certificate_id: Mapped[int] = mapped_column(ForeignKey("certificate.id"))
    certificate: Mapped["Certificate"] = relationship(back_populates="SAN")
    def __repr__(self) -> str:
        return f"SAN(id={self.id!r}, value={self.value!r})"


class Host(Base):
    __tablename__ = "host"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(30))
    port: Mapped[int] = mapped_column(Integer)
    # parse_date: Mapped[DateTime] = mapped_column(DateTime(30))
    name: Mapped[Optional[str]]
    cloud: Mapped[str] = mapped_column(String(30))
    certificate: Mapped["Certificate"] = relationship(back_populates="host")

    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_session.id"))
    scan_session: Mapped["ScanSession"] = relationship(back_populates="hosts")

    def __repr__(self) -> str:
        return f"Host(id={self.id!r}, name={self.name!r}, fullname={self.ip!r})"