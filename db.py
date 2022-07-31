from sqlalchemy import Column, String, Integer, create_engine, DECIMAL, Boolean, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

Base = declarative_base()


class Record(Base):
    __tablename__ = 'records'
    id = Column(Integer, primary_key=True)
    logo = Column(String(256))
    type = Column(Integer, index=True)  # 4=ipv4, 6=ipv6
    cidr = Column(String(60))
    start_addr = Column(DECIMAL(45, 0), index=True)
    end_addr = Column(DECIMAL(45, 0), index=True)
    as_num = Column(String(15), index=True)
    location = Column(String(256))
    country = Column(String(64), index=True)
    geo_x = Column(DECIMAL(10, 6))
    geo_y = Column(DECIMAL(10, 6))
    provider = Column(String(64))
    idc = Column(String(64))
    usage = Column(String(64))
    pop = Column(Boolean)
    creator = Column(Integer)
    create_time = Column(DateTime, default=datetime.now)
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    as_num = Column(String(15), index=True)
    password = Column(String(128), index=True)
    create_time = Column(DateTime, default=datetime.now)
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now)


engine = create_engine('mysql://root:app0213@127.0.0.1/ipipdn42?charset=utf8', echo=True)
sess = sessionmaker(bind=engine)
session = sess()
