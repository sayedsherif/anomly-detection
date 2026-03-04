# ELWARDANI — AI Anomaly Detection System v3.0

## Quick Start

### 1. Clone & setup
```bash
git clone https://github.com/sayedsherif/anomly-detection.git
cd anomly-detection
python -m venv .venv

# Windows
.venv\Scripts\activate
# Mac/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure environment
```bash
# Windows
copy .env.example .env
# Mac/Linux
cp .env.example .env
```
Edit `.env` and set a strong `SECRET_KEY`.

### 3. Run locally

**Windows (PyCharm / Terminal):**
```bash
python run.py
```

**Mac/Linux:**
```bash
python app.py
```

Then open: http://127.0.0.1:5000

## Production Deploy (Render / Heroku)
The `Procfile` uses `gunicorn` for Linux-based cloud deploys:
```
web: gunicorn app:app --bind 0.0.0.0:$PORT
```

## Security Notes
- ⚠️ Never commit `.env` — it contains your `SECRET_KEY`
- The `.gitignore` excludes `.env` automatically
- Use `.env.example` as a template
