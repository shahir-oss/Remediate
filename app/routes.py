"""Routes for ConiferRemediate."""

import csv
import io
import os
import random

import requests
from flask import (Blueprint, flash, make_response, redirect, render_template,
                   request, url_for)
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .models import RemediationLog, ScanResult, Server, User

main_bp = Blueprint('main', __name__)


def simulate_cloud_discovery(provider: str, api_key: str):
    """Simulate discovery from a cloud provider."""
    # Placeholder for real provider API calls
    return [{
        'ip': f'10.0.0.{random.randint(1, 254)}',
        'name': f'{provider}-vm-{random.randint(1, 100)}',
        'os': 'Ubuntu 22.04',
        'os_type': 'linux'
    }]


SAMPLE_VULNS = [
    {"cve": "CVE-2024-0001", "description": "Sample vulnerability", "severity": "high"},
    {"cve": "CVE-2023-1234", "description": "Another issue", "severity": "medium"},
]


def simulate_openvas_scan(server: Server):
    """Return a list of simulated vulnerabilities for a server."""
    count = random.randint(1, len(SAMPLE_VULNS))
    return random.sample(SAMPLE_VULNS, count)


def get_bearer_token():
    """Retrieve OAuth token for remediation API."""
    payload = {
        "client_id": "5M8VkYrGn7Qh8xWuh9fecTO8CwkJH7EZ",
        "client_secret": os.getenv('CLIENT_SECRET', ''),
        "audience": "https://dev-0wrutskhefy2ibby.us.auth0.com/api/v2/",
        "grant_type": "client_credentials",
    }
    resp = requests.post(
        "https://dev-0wrutskhefy2ibby.us.auth0.com/oauth/token", json=payload, timeout=10
    )
    resp.raise_for_status()
    return resp.json().get("access_token")


def call_remediation_api(cve: str, os_type: str):
    """Call external remediation API and return summary and full log."""
    token = get_bearer_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"cve": cve, "os_type": os_type}
    resp = requests.post(
        "https://api-ai.besoftware.xyz/api/get_cve_details",
        headers=headers,
        json=body,
        timeout=10,
    )
    summary = "success"
    try:
        data = resp.json()
        summary = data.get("summary", summary)
        details = resp.text
    except ValueError:
        details = resp.text
    return summary, details


@main_bp.route('/')
@login_required
def dashboard():
    total = Server.query.count()
    vulnerable = Server.query.filter(Server.cve.isnot(None)).count()
    return render_template('dashboard.html', total=total, vulnerable=vulnerable)


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('User already exists')
            return redirect(url_for('main.register'))
        user = User(username=username, email=email,
                    password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('main.login'))
    return render_template('register.html')


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')


@main_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main_bp.route('/servers', methods=['GET', 'POST'])
@login_required
def servers():
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        name = request.form['name']
        os = request.form['os']
        os_type = request.form['os_type']
        tag = request.form.get('tag')
        server = Server(ip_address=ip_address, name=name, os=os, os_type=os_type, tag=tag)
        db.session.add(server)
        db.session.commit()
        flash('Server added successfully')
        return redirect(url_for('main.servers'))
    servers = Server.query.all()
    return render_template('servers.html', servers=servers)


@main_bp.route('/discover', methods=['GET', 'POST'])
@login_required
def discover():
    if request.method == 'POST':
        provider = request.form['provider']
        api_key = request.form['api_key']
        servers = simulate_cloud_discovery(provider, api_key)
        for s in servers:
            if not Server.query.filter_by(ip_address=s['ip']).first():
                srv = Server(ip_address=s['ip'], name=s['name'], os=s['os'], os_type=s['os_type'], tag=provider, status='online')
                db.session.add(srv)
        db.session.commit()
        flash(f'Discovered {len(servers)} servers from {provider}')
        return redirect(url_for('main.discover'))
    servers = Server.query.all()
    return render_template('discover.html', servers=servers)


@main_bp.route('/scan')
@login_required
def scan_index():
    servers = Server.query.all()
    return render_template('scan.html', servers=servers)


@main_bp.route('/scan/<int:server_id>', methods=['POST'])
@login_required
def scan_server(server_id):
    server = Server.query.get_or_404(server_id)
    vulns = simulate_openvas_scan(server)
    cve_ids = [v['cve'] for v in vulns]
    report_lines = [f"{v['cve']}: {v['description']}" for v in vulns]
    result = ScanResult(server_id=server.id, vulnerabilities=vulns, report='\n'.join(report_lines))
    db.session.add(result)
    server.cve = ','.join(cve_ids)
    server.status = 'online'
    db.session.commit()
    flash(f'Scan completed for {server.name}')
    return redirect(url_for('main.scan_index'))


@main_bp.route('/scan/report/<int:result_id>')
@login_required
def scan_report(result_id):
    result = ScanResult.query.get_or_404(result_id)
    return render_template('scan_report.html', result=result)


@main_bp.route('/remediate')
@login_required
def remediate_index():
    servers = Server.query.filter(Server.cve.isnot(None)).all()
    return render_template('remediate.html', servers=servers)


@main_bp.route('/remediate/<int:server_id>', methods=['POST'])
@login_required
def remediate(server_id):
    server = Server.query.get_or_404(server_id)
    action = request.form['action']
    cve = server.cve.split(',')[0]
    summary, details = call_remediation_api(cve, server.os_type)
    log = RemediationLog(server_id=server.id, cve=cve, os_type=server.os_type,
                         action=action, summary=summary, details=details)
    db.session.add(log)
    db.session.commit()
    flash(f'Remediation {action} triggered for {server.name}')
    return redirect(url_for('main.remediate_index'))


@main_bp.route('/results/<int:log_id>')
@login_required
def results(log_id):
    log = RemediationLog.query.get_or_404(log_id)
    return render_template('results.html', log=log)


@main_bp.route('/reports')
@login_required
def reports():
    servers = Server.query.all()
    return render_template('reports.html', servers=servers)


@main_bp.route('/reports/export')
@login_required
def export_reports():
    servers = Server.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'IP', 'OS', 'CVE', 'Status'])
    for s in servers:
        writer.writerow([s.name, s.ip_address, s.os, s.cve or '', s.status])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=report.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

