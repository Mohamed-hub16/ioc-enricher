import json
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from webapp import db

STALE_DAYS = 14


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="pending")  # admin | analyst | pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # API keys stored AES-128-GCM encrypted
    virustotal_key_enc = db.Column(db.Text, nullable=True)
    abuseipdb_key_enc  = db.Column(db.Text, nullable=True)
    urlscan_key_enc    = db.Column(db.Text, nullable=True)
    groq_key_enc       = db.Column(db.Text, nullable=True)

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

    @property
    def has_api_keys(self) -> bool:
        """True if the user has at minimum the VirusTotal key configured."""
        return bool(self.virustotal_key_enc)

    def set_api_keys(self, vt: str = "", abuse: str = "", urlscan: str = "",
                     groq: str = "") -> None:
        from src.crypto import encrypt
        if vt:     self.virustotal_key_enc = encrypt(vt)
        if abuse:  self.abuseipdb_key_enc  = encrypt(abuse)
        if urlscan:self.urlscan_key_enc    = encrypt(urlscan)
        if groq:   self.groq_key_enc       = encrypt(groq)

    def get_api_keys(self) -> dict:
        from src.crypto import decrypt
        return {
            "VIRUSTOTAL_API_KEY": decrypt(self.virustotal_key_enc or ""),
            "ABUSEIPDB_API_KEY":  decrypt(self.abuseipdb_key_enc or ""),
            "URLSCAN_API_KEY":    decrypt(self.urlscan_key_enc or ""),
            "GROQ_API_KEY":       decrypt(self.groq_key_enc or ""),
        }


class IOCRecord(db.Model):
    __tablename__ = "ioc_records"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(512), unique=True, nullable=False, index=True)
    ioc_type = db.Column(db.String(10), nullable=False)
    enriched_at = db.Column(db.DateTime, default=datetime.utcnow)
    enriched_by = db.Column(db.String(120), nullable=True)
    raw_results = db.Column(db.Text, nullable=True)
    paragraph = db.Column(db.Text, nullable=True)
    threat_score = db.Column(db.Integer, default=0, nullable=False, server_default="0")
    view_count = db.Column(db.Integer, default=0, nullable=False, server_default="0")

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

    @property
    def is_malicious(self) -> bool:
        return (self.threat_score or 0) > 0


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    ioc_record_id = db.Column(db.Integer, db.ForeignKey("ioc_records.id"), nullable=False, index=True)
    author = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    enriched_at_snapshot = db.Column(db.DateTime, nullable=False)

    ioc_record = db.relationship(
        "IOCRecord",
        backref=db.backref("comments", order_by="Comment.created_at", lazy="dynamic"),
    )
