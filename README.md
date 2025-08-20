# ConiferRemediate

A growing implementation for the ConiferRemediate web application. This project uses Flask with SQLAlchemy and Login management. It includes:

- User registration and authentication with role field.
- Server inventory with manual entry and stub cloud discovery.
- Simulated vulnerability scanning and reports.
- Remediation workflow calling external CVE details API and logging results.
- Dashboard with Chart.js and Plotly graphs.
- Reporting page with CSV export.
- Dark responsive UI built with Bootstrap.

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

This repository still represents an early implementation. Cloud provider APIs, real OpenVAS integration and advanced remediation workflows remain to be completed.

