import json
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from webapp import db

STALE_DAYS = 7


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="pending")  # admin | analyst | pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_approved(self) -> bool:
        return self.role in ("admin", "analyst")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class IOCRecord(db.Model):
    __tablename__ = "ioc_records"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(512), unique=True, nullable=False, index=True)
    ioc_type = db.Column(db.String(10), nullable=False)
    enriched_at = db.Column(db.DateTime, default=datetime.utcnow)
    enriched_by = db.Column(db.String(120), nullable=True)
    raw_results = db.Column(db.Text, nullable=True)
    paragraph = db.Column(db.Text, nullable=True)

    def get_results(self) -> list[dict]:
        return json.loads(self.raw_results) if self.raw_results else []

    def set_results(self, results: list[dict]) -> None:
        self.raw_results = json.dumps(results, ensure_ascii=False)

    @property
    def age_days(self) -> int:
        return (datetime.utcnow() - self.enriched_at).days

    @property
    def is_stale(self) -> bool:
        return self.age_days >= STALE_DAYS
