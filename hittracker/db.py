# db_manager.py
import threading
import time
import json
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from os import environ as ENV
import os

from sqlalchemy import (
    Column,
    Date,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
    JSON,
)
from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, scoped_session, sessionmaker

from utils import normalize_path

Base = declarative_base()


def retry_on_locked_database(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except OperationalError as e:
            if "database is locked" in str(e):
                print("Database is locked. Retrying in 10 seconds...")
                time.sleep(10)
                return wrapper(*args, **kwargs)
            elif "disk I/O error" in str(e):
                print("Disk I/O error. Retrying in 20 seconds...")
                time.sleep(20)
                return wrapper(*args, **kwargs)
            elif "database disk image is malformed" in str(e):
                print("database disk image is malformed. Retrying in 20 seconds...")
                time.sleep(20)
                return wrapper(*args, **kwargs)
            else:
                raise
        except IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                print("UNIQUE constraint failed. Discarding...")
                time.sleep(1)
                return None
            else:
                raise

    return wrapper


class Firewall(Base):
    __tablename__ = "firewalls"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    device_type = Column(String)
    policies = relationship("Policy", back_populates="firewall")
    __table_args__ = (
        UniqueConstraint("name", "device_type", name="_name_device_type_uc"),
    )


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id"))
    name = Column(String)
    current_hit_count = Column(Integer)
    last_seen = Column(Date)
    first_zero_hit = Column(Date)
    last_zero_hit = Column(Date)
    rule_details = Column(JSON)  # Changed to JSON type

    firewall = relationship("Firewall", back_populates="policies")
    history = relationship("PolicyHistory", back_populates="policy")


class PolicyHistory(Base):
    __tablename__ = "policy_history"

    id = Column(Integer, primary_key=True)
    policy_id = Column(Integer, ForeignKey("policies.id"))
    hit_count = Column(Integer)
    date = Column(Date)

    policy = relationship("Policy", back_populates="history")


class ProcessedFile(Base):
    __tablename__ = "processed_files"

    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id"))
    filename = Column(String)
    processed_date = Column(Date)

    firewall = relationship("Firewall")
    __table_args__ = (
        UniqueConstraint("firewall_id", "filename", name="_firewall_filename_uc"),
    )


def enable_wal(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_name="firewall_policies.db"):
        if ENV.get("DB_FILE_HT"):
            engine = ENV["DB_FILE_HT"]
            db_name = engine.replace(r"sqlite:///", "")
        else:
            engine = f"sqlite:///{db_name}"

        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DatabaseManager, cls).__new__(cls)
                cls._instance.engine = create_engine(engine)
                event.listen(cls._instance.engine, "connect", enable_wal)
                Base.metadata.create_all(cls._instance.engine)
                cls._instance.Session = scoped_session(
                    sessionmaker(bind=cls._instance.engine)
                )
        return cls._instance

    @contextmanager
    def session_scope(self):
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @retry_on_locked_database
    def add_firewall(self, name, device_type):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=name, device_type=device_type)
                .first()
            )
            if not firewall:
                firewall = Firewall(name=name, device_type=device_type)
                session.add(firewall)

    @retry_on_locked_database
    def update_policy(
        self,
        firewall_name,
        device_type,
        policy_name,
        hit_count,
        date,
        rule_details=None,
    ):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )

            if not firewall:
                firewall = Firewall(name=firewall_name, device_type=device_type)
                session.add(firewall)
                session.flush()

            policy = (
                session.query(Policy)
                .filter_by(firewall_id=firewall.id, name=policy_name)
                .first()
            )

            if policy:
                if hit_count == 0:
                    if policy.current_hit_count > 0:
                        policy.first_zero_hit = date
                    policy.last_zero_hit = date
                else:
                    policy.last_zero_hit = None
                    if policy.current_hit_count == 0:
                        policy.first_zero_hit = None
                policy.current_hit_count = hit_count
                policy.last_seen = date
                if rule_details:
                    policy.rule_details = rule_details
            else:
                policy = Policy(
                    firewall_id=firewall.id,
                    name=policy_name,
                    current_hit_count=hit_count,
                    last_seen=date,
                    first_zero_hit=date if hit_count == 0 else None,
                    last_zero_hit=date if hit_count == 0 else None,
                    rule_details=rule_details,
                )
                session.add(policy)

            history_entry = PolicyHistory(policy=policy, hit_count=hit_count, date=date)
            session.add(history_entry)

            session.commit()

    @retry_on_locked_database
    def batch_update_policies(self, updates):
        with self.session_scope() as session:
            for update in updates:
                (
                    firewall_name,
                    device_type,
                    policy_name,
                    hit_count,
                    date,
                    rule_details,
                ) = update
                firewall = (
                    session.query(Firewall)
                    .filter_by(name=firewall_name, device_type=device_type)
                    .first()
                )

                if not firewall:
                    firewall = Firewall(name=firewall_name, device_type=device_type)
                    session.add(firewall)
                    session.flush()

                policy = (
                    session.query(Policy)
                    .filter_by(firewall_id=firewall.id, name=policy_name)
                    .first()
                )

                if policy:
                    if hit_count == 0:
                        if policy.current_hit_count > 0:
                            policy.first_zero_hit = date
                        policy.last_zero_hit = date
                    else:
                        policy.last_zero_hit = None
                        if policy.current_hit_count == 0:
                            policy.first_zero_hit = None
                    policy.current_hit_count = hit_count
                    policy.last_seen = date
                    if rule_details:
                        policy.rule_details = rule_details
                else:
                    policy = Policy(
                        firewall_id=firewall.id,
                        name=policy_name,
                        current_hit_count=hit_count,
                        last_seen=date,
                        first_zero_hit=date if hit_count == 0 else None,
                        last_zero_hit=date if hit_count == 0 else None,
                        rule_details=rule_details,
                    )
                    session.add(policy)

                history_entry = PolicyHistory(
                    policy=policy, hit_count=hit_count, date=date
                )
                session.add(history_entry)

            session.commit()

    @retry_on_locked_database
    def get_policy_history(self, firewall_name, device_type, policy_name):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )
            if not firewall:
                return None

            policy = (
                session.query(Policy)
                .filter_by(firewall_id=firewall.id, name=policy_name)
                .first()
            )

            if not policy:
                return None

            return [
                {"date": entry.date, "hit_count": entry.hit_count}
                for entry in policy.history
            ]

    @retry_on_locked_database
    def get_unused_policies(self, days_threshold):
        with self.session_scope() as session:
            today = datetime.now().date()
            threshold_date = today - timedelta(days=days_threshold)

            unused_policies = (
                session.query(
                    Firewall.name.label("firewall_name"),
                    Firewall.device_type.label("device_type"),
                    Policy.name.label("policy_name"),
                    Policy.last_zero_hit,
                    Policy.first_zero_hit,
                    Policy.rule_details,
                )
                .join(Policy)
                .filter(
                    Policy.current_hit_count == 0,
                    Policy.last_zero_hit.isnot(None),
                    Policy.first_zero_hit <= threshold_date,
                )
                .all()
            )

            return unused_policies

    @retry_on_locked_database
    def add_processed_file(self, firewall_name, device_type, filename, processed_date):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )
            if not firewall:
                firewall = Firewall(name=firewall_name, device_type=device_type)
                session.add(firewall)
                session.flush()

            normalized_filename = normalize_path(filename)
            processed_file = ProcessedFile(
                firewall_id=firewall.id,
                filename=normalized_filename,
                processed_date=processed_date,
            )
            session.add(processed_file)

    @retry_on_locked_database
    def is_file_processed(self, firewall_name, device_type, filename):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )
            if not firewall:
                return False

            normalized_filename = normalize_path(filename)
            processed_file = (
                session.query(ProcessedFile)
                .filter_by(firewall_id=firewall.id, filename=normalized_filename)
                .first()
            )
            return processed_file is not None

    @retry_on_locked_database
    def get_latest_config(self, firewall_name, device_type):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )
            if not firewall:
                print("No firewall found")
                return None

            latest_config = (
                session.query(ProcessedFile)
                .filter_by(firewall_id=firewall.id)
                .order_by(ProcessedFile.processed_date.desc())
                .first()
            )
            result = latest_config.filename if latest_config else None
            if not result:
                print("No latest config found")
            return result

    def pack_rule_details(self, rule_details):
        return json.dumps(rule_details)

    def unpack_rule_details(self, packed_rule_details):
        if isinstance(packed_rule_details, dict):
            return packed_rule_details
        return json.loads(packed_rule_details)

    @retry_on_locked_database
    def update_policy_details(
        self, firewall_name, device_type, policy_name, rule_details
    ):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )
            if not firewall:
                print(f"No firewall found for {firewall_name} ({device_type})")
                return False

            policy = (
                session.query(Policy)
                .filter_by(firewall_id=firewall.id, name=policy_name)
                .first()
            )
            if not policy:
                print(
                    f"No policy found for {policy_name} on {firewall_name} ({device_type})"
                )
                return False

            policy.rule_details = rule_details
            print(
                f"Updated rule details for {policy_name} on {firewall_name} ({device_type})"
            )
            return True

    @retry_on_locked_database
    def are_rule_details_complete(self, firewall_name, device_type):
        with self.session_scope() as session:
            firewall = (
                session.query(Firewall)
                .filter_by(name=firewall_name, device_type=device_type)
                .first()
            )
            if not firewall:
                print(f"No firewall found for {firewall_name} ({device_type})")
                return False

            policies = session.query(Policy).filter_by(firewall_id=firewall.id).all()

            for policy in policies:
                if policy.rule_details is None:
                    return False

                # Handle both string (JSON) and dictionary cases
                if isinstance(policy.rule_details, str):
                    try:
                        rule_details = json.loads(policy.rule_details)
                    except json.JSONDecodeError:
                        print(f"Invalid JSON for policy {policy.name}")
                        return False
                elif isinstance(policy.rule_details, dict):
                    rule_details = policy.rule_details
                else:
                    print(f"Unexpected rule_details type for policy {policy.name}")
                    return False

                # Check if any required fields are empty
                if any(
                    len(value) == 0
                    for key, value in rule_details.items()
                    if key not in ["Source Services", "Destination Services"]
                ):
                    return False

            return True

    def close(self):
        self.Session.remove()
        self.engine.dispose()
