# ConiferRemediate

A simplified skeleton for the ConiferRemediate web application. This project uses Flask with SQLAlchemy and Login management. It provides basic routes for registration, login, server management, placeholder scanning, and remediation triggers.

## Running locally

```bash
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt
flask db upgrade  # if migrations are set up
python run.py
```

Or with Docker:

```bash
docker-compose up --build
```

## Disclaimer

This repository contains only a minimal implementation. Many advanced features described in the specification (cloud discovery, OpenVAS integration, detailed remediation workflows, reporting exports, etc.) still need to be developed.
