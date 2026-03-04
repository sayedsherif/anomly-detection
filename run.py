"""
run.py — Local development server for Windows
Uses waitress (cross-platform WSGI server, works on Windows)
Usage: python run.py
"""
import os
import sys
from pathlib import Path

# Make sure .env is loaded
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

from app import app, Config

def main():
    host = Config.FLASK_HOST or "127.0.0.1"
    port = int(Config.FLASK_PORT or 5000)

    print(f"""
╔══════════════════════════════════════════════════════╗
║   ELWARDANI — Anomaly Detection System v3.0          ║
║   Local Development Server (Windows/waitress)        ║
╠══════════════════════════════════════════════════════╣
║   URL  : http://{host}:{port}
║   ENV  : {Config.FLASK_ENV}
╚══════════════════════════════════════════════════════╝
""")

    if sys.platform == "win32":
        # Use waitress on Windows (gunicorn doesn't support Windows)
        try:
            from waitress import serve
            print(f"[INFO] Starting waitress server on http://{host}:{port}")
            serve(app, host=host, port=port, threads=4)
        except ImportError:
            print("[ERROR] waitress not installed. Run: pip install waitress")
            print("[INFO]  Falling back to Flask dev server...")
            app.run(host=host, port=port, debug=(Config.FLASK_ENV == "development"))
    else:
        # On Linux/Mac use Flask dev server (gunicorn used in production via Procfile)
        app.run(host=host, port=port, debug=(Config.FLASK_ENV == "development"))


if __name__ == "__main__":
    main()
