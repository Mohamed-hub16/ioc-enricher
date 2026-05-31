import hashlib
import json
import secrets
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

    # REST API token (SHA-256 hash of the plain token — shown only once at generation)
    rest_api_key_hash = db.Column(db.String(64), nullable=True, unique=True, index=True)

    # API keys stored AES-128-GCM encrypted
    virustotal_key_enc = db.Column(db.Text, nullable=True)
    abuseipdb_key_enc  = db.Column(db.Text, nullable=True)
    urlscan_key_enc    = db.Column(db.Text, nullable=True)
    groq_key_enc       = db.Column(db.Text, nullable=True)
    greynoise_key_enc  = db.Column(db.Text, nullable=True)
    abusech_key_enc    = db.Column(db.Text, nullable=True)

    def generate_rest_api_key(self) -> str:
        """Generate a new REST API token. Store its SHA-256 hash; return the plain token (shown once)."""
        plain = secrets.token_hex(32)
        self.rest_api_key_hash = hashlib.sha256(plain.encode()).hexdigest()
        return plain

    def revoke_rest_api_key(self) -> None:
        self.rest_api_key_hash = None

    @staticmethod
    def get_by_rest_api_key(plain: str) -> "User | None":
        key_hash = hashlib.sha256(plain.encode()).hexdigest()
        return User.query.filter_by(rest_api_key_hash=key_hash).first()

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
                     groq: str = "", greynoise: str = "", abusech: str = "") -> None:
        from src.crypto import encrypt
        if vt:        self.virustotal_key_enc = encrypt(vt)
        if abuse:     self.abuseipdb_key_enc  = encrypt(abuse)
        if urlscan:   self.urlscan_key_enc    = encrypt(urlscan)
        if groq:      self.groq_key_enc       = encrypt(groq)
        if greynoise: self.greynoise_key_enc  = encrypt(greynoise)
        if abusech:   self.abusech_key_enc    = encrypt(abusech)

    def get_api_keys(self) -> dict:
        from src.crypto import decrypt
        return {
            "VIRUSTOTAL_API_KEY": decrypt(self.virustotal_key_enc or ""),
            "ABUSEIPDB_API_KEY":  decrypt(self.abuseipdb_key_enc or ""),
            "URLSCAN_API_KEY":    decrypt(self.urlscan_key_enc or ""),
            "GROQ_API_KEY":       decrypt(self.groq_key_enc or ""),
            "GREYNOISE_API_KEY":  decrypt(self.greynoise_key_enc or ""),
            "ABUSE_CH_API_KEY":   decrypt(self.abusech_key_enc or ""),
        }


class IOCRecord(db.Model):
    __tablename__ = "ioc_records"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(512), unique=True, nullable=False, index=True)
    ioc_type = db.Column(db.String(10), nullable=False)
    enriched_at = db.Column(db.DateTime, default=datetime.utcnow)
    enriched_by = db.Column(db.String(120), nullable=True)
    raw_results = db.Column(db.Text, nullable=True)
    paragraph = db.Column(db.Text, nullable=True)  # legacy: kept synced to the default level
    paragraphs_json = db.Column(db.Text, nullable=True)  # {"brief":…, "standard":…, "detailed":…}
    threat_score = db.Column(db.Integer, default=0, nullable=False, server_default="0")
    view_count = db.Column(db.Integer, default=0, nullable=False, server_default="0")
    # Extended fields from PR #1
    verdict = db.Column(db.String(20), nullable=True)           # malicious | suspicious | clean
    malware_family = db.Column(db.String(120), nullable=True)   # e.g. "Cobalt Strike"
    tags_json = db.Column(db.Text, nullable=True)               # JSON list of analyst tags
    score_breakdown_json = db.Column(db.Text, nullable=True)    # JSON dict per-source scores

    def get_results(self) -> list[dict]:
        return json.loads(self.raw_results) if self.raw_results else []

    def set_results(self, results: list[dict]) -> None:
        self.raw_results = json.dumps(results, ensure_ascii=False)

    def get_paragraphs(self) -> dict:
        """Available AI analyses keyed by level. Falls back to legacy .paragraph as 'standard'."""
        data = json.loads(self.paragraphs_json) if self.paragraphs_json else {}
        if not data and self.paragraph:
            data = {"standard": self.paragraph}
        return {k: v for k, v in data.items() if v}

    def set_paragraph_level(self, level: str, text: str | None) -> None:
        """Store one analysis level; keep legacy .paragraph synced to the best default."""
        if not text:
            return
        data = json.loads(self.paragraphs_json) if self.paragraphs_json else {}
        data[level] = text
        self.paragraphs_json = json.dumps(data, ensure_ascii=False)
        self.paragraph = data.get("standard") or data.get("detailed") or data.get("brief")

    def get_tags(self) -> list[str]:
        return json.loads(self.tags_json) if self.tags_json else []

    def set_tags(self, tags: list[str]) -> None:
        self.tags_json = json.dumps(tags, ensure_ascii=False)

    def get_score_breakdown(self) -> dict:
        return json.loads(self.score_breakdown_json) if self.score_breakdown_json else {}

    def set_score_breakdown(self, breakdown: dict) -> None:
        self.score_breakdown_json = json.dumps(breakdown, ensure_ascii=False)

    @property
    def age_days(self) -> int:
        return (datetime.utcnow() - self.enriched_at).days

    @property
    def is_malicious(self) -> bool:
        return (self.threat_score or 0) > 0

    @property
    def is_suspect(self) -> bool:
        score = self.threat_score or 0
        return 0 < score <= 30

    @property
    def card_meta(self) -> dict:
        """Single-pass extraction of all card-display data from raw results."""
        meta = {"vt_ratio": "", "geo": "", "isp": "", "sources": []}
        for res in self.get_results():
            if res.get("error"):
                continue
            src = res.get("source", "")
            d = res.get("data") or {}
            meta["sources"].append(src)
            if src == "VirusTotal":
                mal = d.get("malicious", 0) or 0
                tot = d.get("total_engines", 0) or 0
                if tot:
                    meta["vt_ratio"] = f"{mal}/{tot}"
            elif src == "ip-api.com":
                country = d.get("country_code") or d.get("country", "")
                city = d.get("city", "")
                parts = [p for p in [country, city] if p]
                meta["geo"] = " · ".join(parts)
                asn = d.get("asn", "")
                meta["isp"] = " ".join(asn.split()[:2]) if asn else d.get("isp", "")
        return meta


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
