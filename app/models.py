from datetime import datetime
from . import db, login_manager
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='user')


class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    os = db.Column(db.String(120), nullable=False)
    os_type = db.Column(db.String(50), nullable=False)
    tag = db.Column(db.String(120))
    cve = db.Column(db.String(120))
    status = db.Column(db.String(20), default='offline')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    vulnerabilities = db.Column(db.JSON)
    report = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    server = db.relationship('Server', backref=db.backref('scan_results', lazy=True))


class RemediationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    cve = db.Column(db.String(120))
    os_type = db.Column(db.String(50))
    action = db.Column(db.String(50))
    summary = db.Column(db.String(255))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    server = db.relationship('Server', backref=db.backref('remediation_logs', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
