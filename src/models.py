"""SQLAlchemy models for the verificationrotation database."""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Service(Base):
    __tablename__ = "services"

    id = Column(String, primary_key=True)
    display_name = Column(String, nullable=False)
    env_var = Column(String, nullable=True)
    is_password = Column(Integer, default=0)
    settings_url = Column(String, nullable=True)
    last_rotated = Column(DateTime, nullable=True)
    current_hash = Column(String, nullable=True)
    hit_count = Column(Integer, default=0)
    status = Column(String, default="ok")  # ok, stale, missing, error
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    detected_config_path = Column(String(512), nullable=True)
    detected_config_format = Column(String(32), nullable=True)


class RotationHistory(Base):
    __tablename__ = "rotation_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String, nullable=False, index=True)
    old_hash = Column(String, nullable=True)
    new_hash = Column(String, nullable=True)
    changed_files = Column(Integer, default=0)
    changed_dbs = Column(Integer, default=0)
    success = Column(Integer, default=0)
    message = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class ScanLog(Base):
    __tablename__ = "scan_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    files_scanned = Column(Integer, default=0)
    keys_found = Column(Integer, default=0)
    status = Column(String, default="pending")  # pending, running, completed, failed
    error_message = Column(Text, nullable=True)


class RemoteHost(Base):
    __tablename__ = "remote_hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    label = Column(String, nullable=False)
    host = Column(String, nullable=False)
    user = Column(String, nullable=False)
    search_dirs = Column(Text, nullable=False, default="[]")  # JSON list
    db_refs = Column(Text, nullable=False, default="[]")     # JSON list of tuples
    ssh_key_name = Column(String, nullable=True)             # name of key in data_dir/ssh_keys/
    ssh_public_key = Column(Text, nullable=True)             # cached public key text
    created_at = Column(DateTime, server_default=func.now())


class DiscoveredKey(Base):
    __tablename__ = "discovered_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String(128), nullable=False)
    env_var = Column(String(128), nullable=False)
    display_name = Column(String(256))
    value_encrypted = Column(Text, nullable=False)  # Fernet-encrypted with SECRET_KEY
    source_file = Column(String(512))
    confidence = Column(String(16), default="medium")
    strategy = Column(String(32))
    discovered_at = Column(DateTime, server_default=func.now())
    applied_at = Column(DateTime, nullable=True)


class SSHKey(Base):
    __tablename__ = "ssh_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    public_key = Column(Text, nullable=False)
    private_key_path = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
