from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from .models import User, Server

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@login_required
def dashboard():
    servers = Server.query.all()
    return render_template('dashboard.html', servers=servers)


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


@main_bp.route('/scan/<int:server_id>')
@login_required
def scan(server_id):
    server = Server.query.get_or_404(server_id)
    # Placeholder for OpenVAS integration
    server.cve = 'CVE-2024-0001'
    db.session.commit()
    flash(f'Scan completed for {server.name}')
    return redirect(url_for('main.servers'))


@main_bp.route('/remediate/<int:server_id>', methods=['POST'])
@login_required
def remediate(server_id):
    server = Server.query.get_or_404(server_id)
    action = request.form['action']
    # Placeholder for remediation API call
    flash(f'Remediation {action} triggered for {server.name}')
    return redirect(url_for('main.servers'))
