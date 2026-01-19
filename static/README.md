# Mews Audit Web App

## Run locally
1) Install Python 3.10+
2) In the project folder:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="change-me"
python mews_full_audit_app.py
