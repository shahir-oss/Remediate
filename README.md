# ConiferRemediate



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


