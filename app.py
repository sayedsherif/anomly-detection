"""
AI-Powered Anomaly Detection System v3.0
Security-hardened Flask backend with ML anomaly detection
Windows UTF-8 compatible | Datadog removed
"""

# ══════════════════════════════════════════════════════════════
# A. WINDOWS UTF-8 FIX — MUST BE ABSOLUTE FIRST
# ══════════════════════════════════════════════════════════════
import sys
import io
import os

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import collections
import logging
import logging.handlers
import math
import random
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from flask_compress import Compress
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import BaseModel, Field, ValidationError
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)


# ══════════════════════════════════════════════════════════════
# B. CONFIGURATION
# ══════════════════════════════════════════════════════════════
class Config:
    FLASK_ENV    = os.getenv("FLASK_ENV", "production")
    FLASK_HOST   = os.getenv("FLASK_HOST", "127.0.0.1")
    FLASK_PORT   = int(os.getenv("FLASK_PORT", 5000))
    SECRET_KEY   = os.getenv("SECRET_KEY", "change-me-in-production")

    ALLOWED_ORIGINS = [
        o.strip()
        for o in os.getenv(
            "ALLOWED_ORIGINS",
            "http://localhost:5000,http://127.0.0.1:5000,null",
        ).split(",")
        if o.strip()
    ]

    MAX_PAYLOAD_SIZE = int(os.getenv("MAX_PAYLOAD_SIZE", 1_048_576))
    RATE_LIMIT       = os.getenv("RATE_LIMIT", "60/minute")
    DATASET_PATH     = os.getenv("DATASET_PATH", str(Path(__file__).parent / "dataset.csv"))

    MODEL_DIR  = Path(__file__).parent / "models"
    MODEL_PATH = MODEL_DIR / "model.joblib"

    IF_N_ESTIMATORS  = int(os.getenv("ISOLATION_FOREST_N_ESTIMATORS", 200))
    IF_CONTAMINATION = float(os.getenv("ISOLATION_FOREST_CONTAMINATION", 0.05))
    IF_RANDOM_STATE  = int(os.getenv("ISOLATION_FOREST_RANDOM_STATE", 42))

    MAX_URL_LENGTH     = int(os.getenv("MAX_URL_LENGTH", 2048))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 6000))

    LOG_FILE  = Path(__file__).parent / "logs" / "anomaly_detection.log"
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    ENFORCE_HTTPS = os.getenv("ENFORCE_HTTPS", "false").lower() == "true"


# ══════════════════════════════════════════════════════════════
# C. LOGGING
# ══════════════════════════════════════════════════════════════
def setup_logging():
    logger = logging.getLogger("AnomalyDetection")
    logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))
    logger.handlers.clear()

    Config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    plain_fmt = "%(asctime)s - %(levelname)s - %(message)s"
    json_fmt = (
        '{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)s",'
        '"message":"%(message)s"}'
    )

    file_handler = logging.handlers.RotatingFileHandler(
        Config.LOG_FILE,
        maxBytes=10_485_760,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(json_fmt))

    if sys.platform == "win32":
        try:
            safe_stream = open(
                sys.stdout.fileno(), mode="w", encoding="utf-8",
                errors="replace", buffering=1, closefd=False,
            )
            stream_handler = logging.StreamHandler(stream=safe_stream)
        except Exception:
            stream_handler = logging.StreamHandler(sys.stdout)
    else:
        stream_handler = logging.StreamHandler(sys.stdout)

    stream_handler.setFormatter(logging.Formatter(plain_fmt))

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


logger = setup_logging()


# ══════════════════════════════════════════════════════════════
# D. FLASK APP FACTORY
# ══════════════════════════════════════════════════════════════
app = Flask(__name__, static_folder=str(Path(__file__).parent), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_PAYLOAD_SIZE
app.config["JSON_SORT_KEYS"]     = False
app.config["SECRET_KEY"]         = Config.SECRET_KEY

Compress(app)

CORS(
    app,
    origins=Config.ALLOWED_ORIGINS,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type", "Authorization",
        "X-CSRF-Token", "X-Session-ID", "X-Requested-With",
    ],
    expose_headers=["Content-Range", "X-Content-Range"],
    supports_credentials=True,
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT],
    storage_uri="memory://",
)

logger.info(
    "Flask app initialized | env=%s host=%s port=%d",
    Config.FLASK_ENV, Config.FLASK_HOST, Config.FLASK_PORT,
)


# ══════════════════════════════════════════════════════════════
# E. IN-MEMORY STATE (thread-safe)
# ══════════════════════════════════════════════════════════════
_lock = threading.Lock()
_request_log = collections.deque(maxlen=500)
_stats = {"total": 0, "anomalies": 0, "normal": 0, "start_time": time.time()}


# ══════════════════════════════════════════════════════════════
# F. ML MODEL
# ══════════════════════════════════════════════════════════════
# Feature extraction helpers
_SQL_KW = re.compile(
    r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute|"
    r"sleep|benchmark|waitfor|having|group\s+by|order\s+by|where)\b",
    re.I,
)
_XSS_PAT = re.compile(
    r"<script[\s>]|javascript\s*:|on\w{1,20}\s*=|<iframe[\s>]|<img[^>]+src\s*=\s*[\"']?javascript:",
    re.I,
)
_TRAVERSAL = re.compile(
    r"\.{2}[/\\]|%2e%2e[%2f%5c]|/etc/passwd|/etc/shadow|boot\.ini|/proc/self",
    re.I,
)
_CMD_INJ = re.compile(
    r";\s*(ls|cat|rm|bash|sh|nc|wget|curl)\b|`[^`]{1,100}`|\$\([^)]{1,100}\)|"
    r"\|\s*(bash|sh|python|perl|ruby)\b|/bin/(bash|sh|dash|zsh)\b",
    re.I,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def extract_features(url: str) -> list:
    """Extract the 9-feature vector from a URL string."""
    url = str(url or "")
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    url_length        = len(url)
    param_count       = len(parse_qs(parsed.query)) if (parsed and parsed.query) else 0
    special_char_count = sum(
        not c.isalnum() and c not in "/:.-_~" for c in url
    )
    path_depth        = len([p for p in (parsed.path if parsed else url).split("/") if p])
    has_sql_keywords  = int(bool(_SQL_KW.search(url)))
    has_xss_pattern   = int(bool(_XSS_PAT.search(url)))
    has_traversal     = int(bool(_TRAVERSAL.search(url)))
    has_cmd_injection = int(bool(_CMD_INJ.search(url)))
    entropy           = round(_shannon_entropy(url), 4)

    return [
        url_length, param_count, special_char_count, path_depth,
        has_sql_keywords, has_xss_pattern, has_traversal, has_cmd_injection, entropy,
    ]


# Attack type detection regex patterns
_ATTACK_PATTERNS = {
    "SQL Injection": re.compile(
        r"\bUNION\b.+\bSELECT\b|\bDROP\b.+\bTABLE\b|'?\s*\bOR\b\s*'?[0-9]|"
        r"\bSELECT\b.+\bFROM\b|--\s+|\bSLEEP\s*\(|\bWAITFOR\b|\bBENCHMARK\s*\(",
        re.I,
    ),
    "XSS": re.compile(
        r"<script[\s>]|javascript\s*:|<iframe[\s>]|on\w{1,20}\s*=\s*[\"']?[^\"'\s>]{2,}|"
        r"\beval\s*\(|document\s*\.\s*cookie|vbscript\s*:|<svg[^>]*on\w",
        re.I,
    ),
    "Directory Traversal": re.compile(
        r"\.{2}[/\\]|%2e%2e[%2f%5c]|/etc/passwd|/etc/shadow|boot\.ini|/proc/self",
        re.I,
    ),
    "Command Injection": re.compile(
        r";\s*(ls|cat|rm|bash|sh|nc|wget|curl)\b|`[^`]{1,100}`|\$\([^)]{1,100}\)|"
        r"\|\s*(bash|sh|python|perl|ruby)\b|/bin/(bash|sh|dash|zsh)\b",
        re.I,
    ),
    "CSRF": re.compile(r"\b(csrf|xsrf|forgery)\b", re.I),
}


def detect_attack_type(url: str, content: str = "") -> str:
    combined = f"{url} {content}"
    for attack_type, pattern in _ATTACK_PATTERNS.items():
        if pattern.search(combined):
            return attack_type
    return "Safe"


# Module-level model state
_scaler: StandardScaler | None = None
_model: IsolationForest | None = None
_model_trained: bool = False
_model_accuracy: float = 0.0


def _train_model() -> None:
    """Train a fresh IsolationForest model with 9-feature extraction on synthetic + dataset URLs."""
    global _scaler, _model, _model_trained, _model_accuracy

    random.seed(42)

    training_urls: list = []
    training_labels: list = []

    # Load URLs from dataset.csv if it has a 'url' column
    dataset_path = Path(Config.DATASET_PATH)
    if dataset_path.exists():
        try:
            df = pd.read_csv(dataset_path, encoding="utf-8")
            if "url" in df.columns:
                for _, row in df.iterrows():
                    training_urls.append(str(row["url"]))
                    training_labels.append(int(row.get("is_anomaly", 0)))
        except Exception as exc:
            logger.warning("Could not load dataset for training: %s", exc)

    # Add synthetic training data for robust coverage
    normal_samples = [
        "/api/users", "/home", "/dashboard", "/login",
        "/api/data?id=10", "/profile/settings", "/search?q=hello",
        "/api/v1/products?page=1&limit=20", "/health", "/metrics",
        "/api/v1/orders", "/user/profile?tab=settings",
        "/assets/main.css", "/favicon.ico", "/robots.txt",
    ]
    attack_samples = [
        "/api/data?id=1 OR 1=1",
        "/page?name=<script>alert(1)</script>",
        "/download?file=../../etc/passwd",
        "/ping?host=127.0.0.1;ls -la",
        "/login?user=admin'--",
        "/search?q=UNION SELECT username, password FROM users",
        "/cmd?exec=bash+-c+ls",
        "/<img src=x onerror=alert(1)>",
        "/api?id=1; DROP TABLE users--",
        "/redirect?url=javascript:alert(document.cookie)",
    ]

    for _ in range(200):
        training_urls.append(random.choice(normal_samples))
        training_labels.append(0)
    for _ in range(20):
        training_urls.append(random.choice(attack_samples))
        training_labels.append(1)

    X = np.array([extract_features(u) for u in training_urls], dtype=float)

    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)

    _model = IsolationForest(
        n_estimators=Config.IF_N_ESTIMATORS,
        contamination=Config.IF_CONTAMINATION,
        random_state=Config.IF_RANDOM_STATE,
        n_jobs=-1,
    )
    _model.fit(X_scaled)
    _model_trained = True

    preds = _model.predict(X_scaled)
    y_pred = np.where(preds == -1, 1, 0)
    y_true = np.array(training_labels)
    _model_accuracy = float(np.mean(y_pred == y_true))

    Config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump((_scaler, _model), Config.MODEL_PATH)
    logger.info(
        "Model trained | samples=%d accuracy=%.4f", len(X), _model_accuracy
    )


def _load_or_train_model() -> None:
    """Load saved model from disk, or train a fresh one."""
    global _scaler, _model, _model_trained, _model_accuracy

    if Config.MODEL_PATH.exists():
        try:
            data = joblib.load(Config.MODEL_PATH)
            if isinstance(data, tuple) and len(data) == 2:
                scaler_c, model_c = data
                # Verify compatibility with our 9-feature extraction
                # (transform raises ValueError if feature count mismatches)
                test = np.array(extract_features("/test"), dtype=float).reshape(1, -1)
                _ = scaler_c.transform(test)  # raises if dimensions mismatch
                _scaler = scaler_c
                _model = model_c
                _model_trained = True
                logger.info("Loaded saved model from %s", Config.MODEL_PATH)
                return
        except Exception as exc:
            logger.warning("Saved model incompatible, retraining: %s", exc)

    try:
        _train_model()
    except Exception as exc:
        logger.error("Model training failed: %s", exc, exc_info=True)
        _model_trained = False


_load_or_train_model()


# ══════════════════════════════════════════════════════════════
# G. INPUT VALIDATION
# ══════════════════════════════════════════════════════════════
_HTTP_METHODS_PATTERN = r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$'


class DetectRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    method: str = Field("GET", pattern=_HTTP_METHODS_PATTERN)
    content_length: int = Field(0, ge=0)
    user_agent: str = Field("", max_length=500)


# ══════════════════════════════════════════════════════════════
# H. SECURITY HEADERS HOOK
# ══════════════════════════════════════════════════════════════
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"]       = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' data: blob:; "
        "connect-src 'self' http://127.0.0.1:5000; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'none';"
    )
    response.headers["Referrer-Policy"]  = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    return response


# ══════════════════════════════════════════════════════════════
# I. ROUTES
# ══════════════════════════════════════════════════════════════

# ── Frontend ──────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(str(Path(__file__).parent), "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    if filename.startswith("api/"):
        return jsonify({"error": "Not found", "status": 404}), 404
    return send_from_directory(str(Path(__file__).parent), filename)


# ── GET /api/v1/health ────────────────────────────────────────
@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "model":   "IsolationForest",
        "uptime":  round(time.time() - _stats["start_time"], 1),
    }), 200


# ── GET /api/v1/stats ─────────────────────────────────────────
@app.route("/api/v1/stats", methods=["GET", "OPTIONS"])
def get_stats():
    if request.method == "OPTIONS":
        return "", 204
    with _lock:
        total     = _stats["total"]
        anomalies = _stats["anomalies"]
        normal    = _stats["normal"]
    rate   = round((anomalies / total * 100), 2) if total > 0 else 0.0
    uptime = round(time.time() - _stats["start_time"], 1)
    return jsonify({
        # Primary fields (spec)
        "total_requests":  total,
        "anomalies":       anomalies,
        "normal":          normal,
        "detection_rate":  rate,
        "uptime_seconds":  uptime,
        "model":           "IsolationForest",
        "contamination":   Config.IF_CONTAMINATION,
        # Backward-compat fields (frontend uses these)
        "anomalies_detected": anomalies,
        "normal_requests":    normal,
        "model_trained":      _model_trained,
        "model_accuracy":     round(_model_accuracy, 4),
        "timestamp":          datetime.now().isoformat(),
    }), 200


# ── GET /api/v1/history ───────────────────────────────────────
@app.route("/api/v1/history", methods=["GET", "OPTIONS"])
def get_history():
    if request.method == "OPTIONS":
        return "", 204
    limit = min(request.args.get("limit", 50, type=int), 500)
    with _lock:
        all_items = list(_request_log)
    items = all_items[-limit:] if limit < len(all_items) else all_items
    return jsonify({
        # Primary fields (spec)
        "requests": items,
        "count":    len(items),
        # Backward-compat fields (frontend uses these)
        "history": items,
        "total":   len(all_items),
        "offset":  0,
        "limit":   limit,
    }), 200


# ── Core detection logic ──────────────────────────────────────
def _run_detect(url: str, method: str, content: str = "", user_agent: str = "") -> dict:
    """Run rule-based + ML detection and update in-memory state."""
    attack_type = detect_attack_type(url, content)
    is_anomaly  = attack_type != "Safe"
    confidence  = 87.5 if is_anomaly else 0.0
    score       = 0.0

    if _model_trained and _scaler is not None and _model is not None:
        try:
            feats    = np.array(extract_features(url), dtype=float).reshape(1, -1)
            X_scaled = _scaler.transform(feats)
            pred     = _model.predict(X_scaled)[0]
            score    = float(_model.score_samples(X_scaled)[0])
            if pred == -1 and not is_anomaly:
                is_anomaly  = True
                attack_type = "Behavioral Anomaly"
                confidence  = round(float(np.clip((0.5 - score) / 1.0, 0.05, 0.99)) * 100, 1)
            elif is_anomaly:
                ml_conf    = round(float(np.clip((0.5 - score) / 1.0, 0.05, 0.99)) * 100, 1)
                confidence = max(confidence, ml_conf)
        except Exception as exc:
            logger.warning("ML prediction error: %s", exc)

    ts = datetime.now().isoformat()
    entry = {
        # Primary fields (spec)
        "id":          f"{int(time.time() * 1000)}",
        "timestamp":   ts,
        "method":      method,
        "url":         url,
        "is_anomaly":  is_anomaly,
        "confidence":  round(confidence, 1),
        "attack_type": attack_type if is_anomaly else "Safe",
        "score":       round(score, 4),
        # Backward-compat fields (frontend uses these)
        "prediction_code":    1 if is_anomaly else 0,
        "threat_probability": (
            f"{int(round(confidence))}% probability of {attack_type}"
            if is_anomaly else "0% -- request appears clean"
        ),
        "model_type": "IsolationForest" if _model_trained else "Rule-based",
        "latency_ms": 0,
    }

    with _lock:
        _stats["total"] += 1
        if is_anomaly:
            _stats["anomalies"] += 1
        else:
            _stats["normal"] += 1
        _request_log.append(entry)

    if is_anomaly:
        logger.warning(
            "THREAT | attack=%s confidence=%.1f method=%s url=%s",
            attack_type, confidence, method, url[:120],
        )

    return entry


# ── POST /api/v1/detect ───────────────────────────────────────
@app.route("/api/v1/detect", methods=["POST", "OPTIONS"])
@limiter.limit("10000/hour")
def detect_anomaly():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}

    # Accept both new lowercase format and old capitalized format from legacy JS
    url        = str(data.get("url")    or data.get("URL")    or "").strip()
    method     = str(data.get("method") or data.get("Method") or "GET").upper().strip()
    content    = str(data.get("content") or "").strip()
    user_agent = str(data.get("user_agent") or "").strip()
    content_length = int(data.get("content_length") or len(content))

    try:
        req = DetectRequest(
            url=url or "/",
            method=method,
            content_length=content_length,
            user_agent=user_agent,
        )
    except ValidationError as exc:
        return jsonify({"error": "Validation Error", "details": exc.errors(), "status": 400}), 400

    result = _run_detect(req.url, req.method, content, req.user_agent)
    return jsonify(result), 200


# ── POST /detect (backward-compat alias) ─────────────────────
@app.route("/detect", methods=["POST", "OPTIONS"])
@limiter.limit("10000/hour")
def detect_alias():
    """Alias for /api/v1/detect — keeps old JS calls working."""
    return detect_anomaly()


# ── Error handlers ────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(_):
    return jsonify({"error": "Bad request", "status": 400}), 400


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found", "status": 404}), 404


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed", "status": 405}), 405


@app.errorhandler(429)
def ratelimited(_):
    return jsonify({"error": "Too many requests. Rate limit exceeded.", "status": 429}), 429


@app.errorhandler(500)
def internal(_):
    return jsonify({"error": "Internal server error", "status": 500}), 500


# ══════════════════════════════════════════════════════════════
# J. MAIN
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    sep = "=" * 70
    logger.info(sep)
    logger.info("AI Anomaly Detection System v3.0")
    logger.info("Server  : http://%s:%d", Config.FLASK_HOST, Config.FLASK_PORT)
    logger.info("Dataset : %s", Config.DATASET_PATH)
    logger.info("Model   : %s", "trained" if _model_trained else "NOT trained")
    logger.info(sep)

    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.FLASK_ENV == "development",
    )
