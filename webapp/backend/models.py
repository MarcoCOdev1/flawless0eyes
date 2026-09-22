"""
SQLAlchemy database models for OSINT Agent web application.
"""
from datetime import datetime, timezone
import json
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    scans = db.relationship("Scan", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.email}>"

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return utcnow() < self.locked_until

    def to_dict(self) -> dict:
        """Safe serialization — never includes password_hash."""
        return {
            "id": self.id,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_DONE = "done"
    STATUS_ERROR = "error"

    VALID_MODULES = {"domain", "username", "breach", "search", "entity", "dork", "metadata", "full"}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    module = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(500), nullable=False)

    # Optional full-scan extra targets
    extra_username = db.Column(db.String(255), nullable=True)
    extra_email = db.Column(db.String(255), nullable=True)
    extra_entity_name = db.Column(db.String(500), nullable=True)

    status = db.Column(db.String(20), default=STATUS_PENDING, nullable=False, index=True)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    user = db.relationship("User", back_populates="scans")
    report = db.relationship("Report", back_populates="scan", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.id} module={self.module} target={self.target!r} status={self.status}>"

    def to_dict(self, include_report=False) -> dict:
        result = {
            "id": self.id,
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
        if include_report and self.report:
            result["report"] = self.report.to_dict()
        return result


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    json_data = db.Column(db.Text, nullable=True)   # JSON string of findings
    markdown_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationship
    scan = db.relationship("Scan", back_populates="report")

    def get_findings(self) -> dict:
        if not self.json_data:
            return {}
        try:
            return json.loads(self.json_data)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_findings(self, findings: dict):
        self.json_data = json.dumps(findings, default=str, ensure_ascii=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "findings": self.get_findings(),
            "markdown": self.markdown_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
