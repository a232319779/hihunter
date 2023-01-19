# -*- coding: utf-8 -*-
# @Time     : 2023/01/14 00:43:42
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : sqlite_db.py
# @Software : Visual Studio Code
# @WeChat   : NextB


from sqlalchemy import create_engine
from sqlalchemy import Column, String, Text, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql.sqltypes import Integer


Base = declarative_base()


class HiHunterVTDatas(Base):
    __tablename__ = "hihunter_vt_datas"

    # id = Column(Integer, primary_key=True, unique=True, autoincrement=True)
    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    md5 = Column(String(32), unique=True)
    sha1 = Column(String(40), unique=True)
    size = Column(Integer)
    positive = Column(Integer)
    times_submitted = Column(Integer)
    unique_sources = Column(Integer)
    type = Column(String(255))
    tags = Column(String(255))
    suggested_threat_label = Column(String(255))
    first_submission_date = Column(Integer)
    names = Column(String(1024))
    virustotal_status = Column(Integer)


class HiHunterRSDatas(Base):
    __tablename__ = "hihunter_rs_datas"

    id = Column(Integer, primary_key=True, unique=True, autoincrement=True)
    md5 = Column(String(32), unique=True)
    sha1 = Column(String(40), unique=True)
    serial_id = Column(String(40))
    task_id = Column(String(40))
    domains = Column(Text())
    hosts = Column(Text())
    urls = Column(Text())
    graph = Column(Text())
    ti_tags = Column(String(1024))
    score = Column(Integer)
    has_network = Column(Integer)
    sandbox_status = Column(Integer)


class HiHunterDB:
    def __init__(self, db_name):
        conn_str = "sqlite:///{db_name}".format(db_name=db_name)
        self.engine = create_engine(conn_str)
        self.session_maker = None
        self.create_session()
        self.create_table()

    def create_session(self):
        """
        创建数据库链接
        """
        if self.session_maker is None:
            self.session_maker = scoped_session(
                sessionmaker(autoflush=True, autocommit=False, bind=self.engine)
            )

    def close_session(self):
        """
        关闭会话链接
        """
        if self.session_maker:
            self.session_maker.close()

    def close(self):
        """
        关闭数据库链接
        """
        self.close_session()
        self.engine.dispose()

    # 创建表
    def create_table(self):
        try:
            Base.metadata.create_all(self.engine)
        except Exception as e:
            pass

    def add_vt_data(self, datas):
        all_sha1s = self.get_all_sha1s(HiHunterVTDatas)
        for data in datas:
            file_sha1 = data.get("sha1", "")
            if file_sha1 not in all_sha1s:
                hi_data = HiHunterVTDatas()
                hi_data.md5 = data.get("md5", "")
                hi_data.sha1 = data.get("sha1", "")
                hi_data.size = data.get("size", -1)
                hi_data.positive = data.get("positive", -1)
                hi_data.times_submitted = data.get("times_submitted", -1)
                hi_data.unique_sources = data.get("unique_sources", -1)
                hi_data.type = data.get("type", "")
                hi_data.tags = data.get("tags", "")
                hi_data.suggested_threat_label = data.get("suggested_threat_label", "")
                hi_data.first_submission_date = data.get("first_submission_date", -1)
                hi_data.names = data.get("names", "")
                hi_data.virustotal_status = data.get("virustotal_status", 0)
                self.session_maker.merge(hi_data)
        self.session_maker.commit()

    def add_rs_data(self, datas):
        all_sha1s = self.get_all_sha1s(HiHunterRSDatas)
        for data in datas:
            file_sha1 = data.get("sha1", "")
            if file_sha1 not in all_sha1s:
                hi_data = HiHunterRSDatas()
                hi_data.md5 = data.get("md5", "")
                hi_data.sha1 = data.get("sha1", "")
                hi_data.serial_id = data.get("serial_id")
                hi_data.sandbox_status = data.get("sandbox_status", 0)
                self.session_maker.merge(hi_data)
        self.session_maker.commit()

    def update_rs_by_serial_id(self, data_json, serial_id):
        data = (
            self.session_maker.query(HiHunterRSDatas)
            .filter(HiHunterRSDatas.serial_id == serial_id)
            .first()
        )
        data.graph = data_json.get("graph", "")
        data.domains = data_json.get("domains", "")
        data.hosts = data_json.get("hosts", "")
        data.urls = data_json.get("urls", "")
        data.ti_tags = data_json.get("ti_tags", "")
        data.task_id = data_json.get("task_id", "")
        data.has_network = data_json.get("has_network", -1)
        data.score = data_json.get("score", -1)
        data.sandbox_status = data_json.get("sandbox_status", 1)
        self.session_maker.commit()

    def update_rs_by_serial_id_screenshot(self, serial_id):
        data = (
            self.session_maker.query(HiHunterRSDatas)
            .filter(HiHunterRSDatas.serial_id == serial_id)
            .first()
        )
        data.sandbox_status = 2
        self.session_maker.commit()

    def search_sha1(self, HiHunterDatas, sha1):
        data = (
            self.session_maker.query(HiHunterDatas)
            .filter(HiHunterDatas.sha1 == sha1)
            .order_by(HiHunterDatas.id.desc())
            .limit(1)
        )
        if data.count():
            return data[0]
        else:
            return {}

    def update_vt_by_sha1(self, sha1):
        data = (
            self.session_maker.query(HiHunterVTDatas)
            .filter(HiHunterVTDatas.sha1 == sha1)
            .first()
        )
        data.virustotal_status = 1
        self.session_maker.commit()

    def get_all_sha1s(self, HiHunterDatas):
        data = self.session_maker.query(HiHunterDatas.sha1).all()
        if data:
            return [d[0] for d in data]
        else:
            return []

    def get_mb_sha1s(self, file_type, limit=1):
        data = (
            self.session_maker.query(HiHunterVTDatas.sha1)
            .filter(
                HiHunterVTDatas.positive >= 5,
                HiHunterVTDatas.virustotal_status == 0,
                HiHunterVTDatas.type == file_type,
                HiHunterVTDatas.size < 1 * 1024 * 1024,
            )
            .order_by(HiHunterVTDatas.id.desc())
            .limit(limit)
        )
        if data:
            return [d[0] for d in data]
        else:
            return []

    def get_rs_serial_id(self, sandbox_status=0, limit=1):
        data = (
            self.session_maker.query(HiHunterRSDatas.serial_id)
            .filter(HiHunterRSDatas.sandbox_status == sandbox_status)
            .order_by(HiHunterRSDatas.id.asc())
            .limit(limit)
        )
        if data:
            return [d[0] for d in data]
        else:
            return []
