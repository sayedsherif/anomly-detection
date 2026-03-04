"""
AI-Powered Anomaly Detection System v3.0
Security-hardened Flask backend with ML anomaly detection
Windows UTF-8 compatible | Datadog removed
"""

# ══════════════════════════════════════════════════════════════
# WINDOWS UTF-8 FIX — MUST BE ABSOLUTE FIRST
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
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from flask_compress import Compress
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import AliasChoices, BaseModel, Field, ValidationError
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)


# ==================== CONFIGURATION ====================
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
    FRONTEND_DIR  = Path(__file__).parent / "frontend"


# ==================== LOGGING ====================
def setup_logging():
    logger = logging.getLogger("AnomalyDetection")
    logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))
    logger.handlers.clear()

    Config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    plain_fmt = "%(asctime)s - %(levelname)s - %(message)s"
    json_fmt  = (
        '{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)s",'
        '"message":"%(message)s"}'
    )

    # File handler — always UTF-8
    file_handler = logging.handlers.RotatingFileHandler(
        Config.LOG_FILE,
        maxBytes=10_485_760,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(json_fmt))

    # Stream handler — UTF-8 safe on Windows
    if sys.platform == "win32":
        try:
            safe_stream = open(
                sys.stdout.fileno(),
                mode="w",
                encoding="utf-8",
                errors="replace",
                buffering=1,
                closefd=False,
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


# ==================== APP INIT ====================
app = Flask(
    __name__,
    static_folder=str(Config.FRONTEND_DIR),
    static_url_path="",
)
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_PAYLOAD_SIZE
app.config["JSON_SORT_KEYS"]     = False
app.config["SECRET_KEY"]         = Config.SECRET_KEY

Compress(app)

CORS(
    app,
    resources={r"/api/*": {"origins": Config.ALLOWED_ORIGINS}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type", "Authorization",
        "X-CSRF-Token", "X-Session-ID", "X-Requested-With",
    ],
    supports_credentials=False,
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


# ==================== SECURITY HEADERS ====================
@app.after_request
def set_security_headers(response):
    response.headers["Server"]                       = "SecureServer"
    response.headers["X-Content-Type-Options"]       = "nosniff"
    response.headers["X-Frame-Options"]              = "DENY"
    response.headers["X-XSS-Protection"]             = "0"
    response.headers["Referrer-Policy"]              = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]           = (
        "geolocation=(), microphone=(), camera=(), payment=()"
    )
    response.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    response.headers["Content-Security-Policy"]      = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'none';"
    )
    return response


# ==================== FRONTEND ROUTES ====================
@app.route("/")
def index():
    return send_from_directory(str(Config.FRONTEND_DIR), "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    if filename.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(str(Config.FRONTEND_DIR), filename)


# ==================== VALIDATION MODELS ====================
class PredictionRequest(BaseModel):
    model_config = {"populate_by_name": True}
    method:  str = Field(..., min_length=1, max_length=10,
                         validation_alias=AliasChoices('method', 'Method'))
    url:     str = Field(..., min_length=1, max_length=Config.MAX_URL_LENGTH,
                         validation_alias=AliasChoices('url', 'URL'))
    content: str = Field(default="", max_length=Config.MAX_CONTENT_LENGTH)


# ==================== INPUT VALIDATOR ====================
class InputValidator:
    @staticmethod
    def validate_url(url: str):
        if not url or not isinstance(url, str):
            return False, ""
        if len(url) > Config.MAX_URL_LENGTH:
            return False, ""
        if re.search(r"[\x00-\x1f\x7f]", url):
            return False, ""
        try:
            parsed = urlparse(url)
            if parsed.scheme and parsed.scheme not in {"http", "https"}:
                return False, ""
            sanitized = (
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.scheme else parsed.path
            )
            if parsed.query:
                sanitized += f"?{parsed.query}"
            return True, sanitized[: Config.MAX_URL_LENGTH]
        except Exception:
            return False, ""

    @staticmethod
    def validate_content(content):
        if content is None:
            return True, ""
        if not isinstance(content, str):
            return False, ""
        if len(content) > Config.MAX_CONTENT_LENGTH:
            return False, ""
        sanitized = "".join(
            ch for ch in content if ord(ch) >= 32 or ch in "\n\t\r"
        )
        return True, sanitized

    @staticmethod
    def validate_method(method):
        valid = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if not method or not isinstance(method, str):
            return False, ""
        m = method.upper().strip()
        return (m in valid, m if m in valid else "")


# ==================== ATTACK PATTERN DETECTOR ====================
class AttackPatternDetector:
    """
    Weighted multi-pattern detector returning realistic threat
    probability percentage instead of a binary 0/1 result.
    """

    WEIGHTED_PATTERNS: dict = {
        "SQL_INJECTION": [
            (re.compile(r"\bUNION\b\s+\bSELECT\b",                    re.I), 0.97, "UNION SELECT"),
            (re.compile(r"\bDROP\b\s+\bTABLE\b",                      re.I), 0.97, "DROP TABLE"),
            (re.compile(r"\bINSERT\b\s+\bINTO\b.*\bVALUES\b",         re.I), 0.93, "INSERT INTO"),
            (re.compile(r"'?\s*\bOR\b\s*'?[0-9]",                     re.I), 0.92, "OR 1=1"),
            (re.compile(r"\bSELECT\b.+\bFROM\b",                      re.I), 0.90, "SELECT FROM"),
            (re.compile(r"--\s*$|--\s+",                               re.I), 0.72, "SQL comment --"),
            (re.compile(r"'[;'\s]|;['\s]",                             re.I), 0.68, "SQL quote/semi"),
            (re.compile(r"\bSLEEP\s*\(\d+\)",                         re.I), 0.88, "SLEEP() blind"),
            (re.compile(r"\bBENCHMARK\s*\(",                          re.I), 0.88, "BENCHMARK()"),
            (re.compile(r"\bWAITFOR\b",                                re.I), 0.87, "WAITFOR DELAY"),
            (re.compile(r"1\s*=\s*1|0\s*=\s*0",                       re.I), 0.60, "tautology 1=1"),
        ],
        "XSS": [
            (re.compile(r"<script[\s>]",                               re.I), 0.96, "<script>"),
            (re.compile(r"javascript\s*:",                             re.I), 0.95, "javascript:"),
            (re.compile(r"<iframe[\s>]",                               re.I), 0.92, "<iframe>"),
            (re.compile(r"on\w{1,20}\s*=\s*[\"']?[^\"'\s>]{2,}",      re.I), 0.90, "onXXX= handler"),
            (re.compile(r"\beval\s*\(",                                re.I), 0.87, "eval()"),
            (re.compile(r"\balert\s*\(",                               re.I), 0.83, "alert()"),
            (re.compile(r"document\s*\.\s*cookie",                     re.I), 0.93, "document.cookie"),
            (re.compile(r"<img[^>]+src\s*=\s*[\"']?javascript:",       re.I), 0.94, "img src=js"),
            (re.compile(r"&#x?[0-9a-f]{2,4};",                        re.I), 0.65, "HTML entity encode"),
            (re.compile(r"vbscript\s*:",                               re.I), 0.92, "vbscript:"),
            (re.compile(r"<svg[^>]*on\w",                              re.I), 0.91, "<svg onload"),
        ],
        "DIRECTORY_TRAVERSAL": [
            (re.compile(r"\.{2}[/\\]\.{2}[/\\]",                      re.I), 0.96, "../../.."),
            (re.compile(r"\.{2}[/\\]",                                 re.I), 0.80, "../"),
            (re.compile(r"%2e%2e[%2f%5c]",                            re.I), 0.95, "%2e%2e encoded"),
            (re.compile(r"\.\.%2f|\.\.%5c",                           re.I), 0.93, "..%2f encoded"),
            (re.compile(r"/etc/passwd",                                re.I), 0.99, "/etc/passwd"),
            (re.compile(r"/etc/shadow",                                re.I), 0.99, "/etc/shadow"),
            (re.compile(r"boot\.ini|win\.ini|system32",                re.I), 0.97, "Windows files"),
            (re.compile(r"/proc/self",                                 re.I), 0.95, "/proc/self"),
            (re.compile(r"~root|~admin",                               re.I), 0.88, "~root/~admin"),
        ],
        "COMMAND_INJECTION": [
            (re.compile(r";\s*(ls|cat|rm|bash|sh|nc|wget|curl)\b",     re.I), 0.97, "; cmd"),
            (re.compile(r"\|\s*(bash|sh|nc|python|perl|ruby)\b",       re.I), 0.97, "| shell"),
            (re.compile(r"`[^`]{1,100}`",                              re.I), 0.94, "backtick exec"),
            (re.compile(r"\$\([^)]{1,100}\)",                          re.I), 0.93, "$(cmd)"),
            (re.compile(r"&&\s*(cat|rm|wget|curl|bash)\b",             re.I), 0.92, "&& cmd"),
            (re.compile(r"\bping\b.*-[nc]\s+\d",                       re.I), 0.82, "ping -n"),
            (re.compile(r">\s*/dev/null",                              re.I), 0.80, ">/dev/null"),
            (re.compile(r"/bin/(bash|sh|dash|zsh)\b",                  re.I), 0.90, "/bin/bash"),
            (re.compile(r"wget\s+http|curl\s+-[soO]",                  re.I), 0.88, "wget/curl exfil"),
        ],
        "PATH_TRAVERSAL": [
            (re.compile(r"php://filter|php://input",                   re.I), 0.97, "php://wrapper"),
            (re.compile(r"file://",                                    re.I), 0.95, "file://"),
            (re.compile(r"phar://|zip://",                             re.I), 0.96, "phar/zip wrapper"),
            (re.compile(r"data:text/html",                             re.I), 0.91, "data:text/html"),
            (re.compile(r"expect://",                                  re.I), 0.95, "expect://"),
        ],
    }

    META = {
        "SQL_INJECTION":       {"description": "SQL Injection Attack",       "riskLevel": "CRITICAL"},
        "XSS":                 {"description": "Cross-Site Scripting (XSS)", "riskLevel": "CRITICAL"},
        "DIRECTORY_TRAVERSAL": {"description": "Directory Traversal",        "riskLevel": "HIGH"},
        "COMMAND_INJECTION":   {"description": "Command Injection Attack",   "riskLevel": "CRITICAL"},
        "PATH_TRAVERSAL":      {"description": "Path/File Inclusion Attack", "riskLevel": "CRITICAL"},
    }

    def detect(self, url: str, content: str, method: str):
        try:
            decoded_url     = unquote(url     or "")
            decoded_content = unquote(content or "")
        except Exception:
            decoded_url     = url     or ""
            decoded_content = content or ""

        combined = f"{decoded_url} {decoded_content}"

        best_type:     str | None = None
        best_conf:     float      = 0.0
        best_patterns: list       = []

        for attack_type, pattern_list in self.WEIGHTED_PATTERNS.items():
            matched_weights: list = []
            matched_labels:  list = []

            for regex, weight, label in pattern_list:
                if regex.search(combined):
                    matched_weights.append(weight)
                    matched_labels.append(label)

            if not matched_weights:
                continue

            matched_weights.sort(reverse=True)
            confidence = matched_weights[0]
            for i, w in enumerate(matched_weights[1:], start=1):
                confidence += w * (0.05 / i)
            confidence = float(min(confidence, 0.99))

            if confidence > best_conf:
                best_conf     = confidence
                best_type     = attack_type
                best_patterns = matched_labels

        if best_type:
            return best_type, best_conf, self.META[best_type], best_patterns
        return None, 0.0, None, []


# ==================== DATASET LOADER ====================
class DatasetLoader:
    @classmethod
    def load(cls, file_path):
        try:
            path = Path(file_path)
            if not path.exists():
                return None, "File not found"

            ext = path.suffix.lower()

            with open(path, "rb") as f:
                magic = f.read(2)
            is_gzip = magic == b"\x1f\x8b"

            if ext == ".csv":
                if is_gzip:
                    logger.info("dataset.csv is gzip-compressed -- decompressing on the fly")
                    df = pd.read_csv(file_path, compression="gzip")
                else:
                    df = pd.read_csv(file_path, encoding="utf-8")
            elif ext in (".xls", ".xlsx"):
                df = pd.read_excel(file_path)
            else:
                return None, f"Unsupported format: {ext}"

            if df is None or df.empty:
                return None, "Dataset is empty"
            return df, "success"

        except Exception as e:
            return None, f"Failed to load dataset: {e}"


def load_dataset(path):
    df, msg = DatasetLoader.load(path)
    if df is None:
        logger.warning("Dataset load issue: %s", msg)
    return df if df is not None else pd.DataFrame()


# ==================== ANOMALY DETECTOR ====================
class AnomalyDetector:
    def __init__(self):
        self._lock              = threading.Lock()
        self.total_requests     = 0
        self.anomalies_detected = 0
        self.normal_requests    = 0
        self.model_accuracy     = 0.0
        self.request_history    = collections.deque(maxlen=1000)
        self.attack_detector    = AttackPatternDetector()
        self.isolation_forest   = None
        self.scaler             = None
        self.imputer            = None
        self.model_trained      = False
        self.feature_columns    = []

        if not self._load_model():
            ds = load_dataset(Config.DATASET_PATH)
            if not ds.empty:
                self.train_on_dataset(ds)

    def _load_model(self):
        try:
            if Config.MODEL_PATH.exists():
                data = joblib.load(Config.MODEL_PATH)
                (
                    self.isolation_forest,
                    self.scaler,
                    self.imputer,
                    self.feature_columns,
                ) = data
                self.model_trained = True
                logger.info("Loaded existing model from %s", Config.MODEL_PATH)
                return True
        except Exception as e:
            logger.warning("Failed to load saved model: %s", e)
        return False

    def _save_model(self):
        try:
            Config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
            joblib.dump(
                (
                    self.isolation_forest,
                    self.scaler,
                    self.imputer,
                    self.feature_columns,
                ),
                Config.MODEL_PATH,
            )
            logger.info("Model saved to %s", Config.MODEL_PATH)
        except Exception as e:
            logger.error("Failed to save model: %s", e)

    def train_on_dataset(self, df):
        try:
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if "is_anomaly" in numeric_cols:
                numeric_cols.remove("is_anomaly")
            if not numeric_cols:
                self.model_trained = False
                return

            self.feature_columns = numeric_cols
            X = df[numeric_cols]

            self.imputer = SimpleImputer(strategy="mean")
            X_imputed    = self.imputer.fit_transform(X)

            self.scaler  = StandardScaler()
            X_scaled     = self.scaler.fit_transform(X_imputed)

            self.isolation_forest = IsolationForest(
                n_estimators=Config.IF_N_ESTIMATORS,
                contamination=Config.IF_CONTAMINATION,
                random_state=Config.IF_RANDOM_STATE,
                n_jobs=-1,
            )
            self.isolation_forest.fit(X_scaled)
            self.model_trained = True

            preds = self.isolation_forest.predict(X_scaled)

            if "is_anomaly" in df.columns:
                y_true = df["is_anomaly"].values
                y_pred = np.where(preds == -1, 1, 0)
                self.model_accuracy = float(np.mean(y_pred == y_true))
            else:
                normal_count = int(np.sum(preds == 1))
                self.model_accuracy = (normal_count / len(preds)) if len(preds) else 0.0

            self._save_model()
            logger.info(
                "Model trained | features=%d accuracy=%.4f",
                len(self.feature_columns),
                self.model_accuracy,
            )
        except Exception as e:
            logger.error("Training failed: %s", e, exc_info=True)
            self.model_trained  = False
            self.model_accuracy = 0.0

    def extract_features(self, method, url, content):
        url_str     = str(url)     if url     else ""
        content_str = str(content) if content else ""
        return [
            len(url_str),
            len(content_str),
            sum(not c.isalnum() for c in url_str),
            sum(c.isdigit() for c in url_str),
            {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4}.get(method.upper(), 0),
        ]

    def predict(self, method, url, content=""):
        start_time = time.time()
        try:
            is_anomaly       = False
            confidence       = 0.0
            attack_type      = None
            matched_patterns = []
            model_used       = "Rule-based"

            detected, pattern_conf, _, matched_patterns = self.attack_detector.detect(
                url, content, method
            )
            if detected:
                is_anomaly  = True
                confidence  = pattern_conf
                attack_type = detected

            extracted = self.extract_features(method, url, content)

            if not is_anomaly and self.model_trained:
                if len(extracted) == len(self.feature_columns):
                    try:
                        X_df = pd.DataFrame([extracted], columns=self.feature_columns)
                        X_i  = self.imputer.transform(X_df)
                        X_s  = self.scaler.transform(X_i)
                        pred = self.isolation_forest.predict(X_s)[0]
                        model_used = "ML-based"

                        if pred == -1:
                            is_anomaly  = True
                            raw_score   = float(self.isolation_forest.score_samples(X_s)[0])
                            confidence  = float(np.clip((0.5 - raw_score) / 1.0, 0.05, 0.99))
                            attack_type = "BEHAVIORAL_ANOMALY"
                    except Exception as e:
                        logger.warning("ML prediction error: %s", e)
                else:
                    logger.warning(
                        "Feature mismatch: expected=%d got=%d",
                        len(self.feature_columns),
                        len(extracted),
                    )

            threat_probability = (
                f"{int(round(confidence * 100))}% probability of {attack_type}"
                if is_anomaly and attack_type
                else "0% -- request appears clean"
            )

            with self._lock:
                self.total_requests += 1
                if is_anomaly:
                    self.anomalies_detected += 1
                else:
                    self.normal_requests += 1

                result = {
                    "prediction_code":    1 if is_anomaly else 0,
                    "is_anomaly":         is_anomaly,
                    "score":              round(confidence, 3),
                    "confidence":         round(confidence, 3),
                    "attack_type":        attack_type,
                    "threat_probability": threat_probability,
                    "matched_patterns":   matched_patterns,
                    "url":                url,
                    "method":             method,
                    "timestamp":          datetime.now().isoformat(),
                    "model_type":         model_used,
                    "latency_ms":         round((time.time() - start_time) * 1000, 2),
                }
                self.request_history.append(result)

            if is_anomaly:
                logger.warning(
                    "THREAT | attack=%s confidence=%.3f method=%s url=%s",
                    attack_type, confidence, method, url[:120],
                )

            return result

        except Exception as e:
            logger.error("Prediction error: %s", e, exc_info=True)
            return {
                "prediction_code": 0,
                "is_anomaly":      False,
                "score":           0.0,
                "confidence":      0.0,
                "attack_type":     None,
                "url":             url,
                "method":          method,
                "timestamp":       datetime.now().isoformat(),
                "model_type":      "Error",
                "latency_ms":      0,
            }


detector = AnomalyDetector()
_start_time = datetime.now()


# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found", "path": request.path}), 404


@app.errorhandler(429)
def ratelimited(_):
    return jsonify({"error": "Too many requests. Rate limit exceeded."}), 429


@app.errorhandler(500)
def internal(_):
    return jsonify({"error": "Internal server error"}), 500


# ==================== API ENDPOINTS ====================
@app.route("/api/v1/detect", methods=["POST", "OPTIONS"])
@limiter.limit("10000/hour")
def detect_anomaly():
    if request.method == "OPTIONS":
        return "", 204

    try:
        body = PredictionRequest(**(request.get_json(silent=True) or {}))
    except ValidationError as e:
        return jsonify({"error": "Validation Error", "details": e.errors()}), 400

    ok_m, method = InputValidator.validate_method(body.method)
    if not ok_m:
        return jsonify({"error": "Invalid HTTP method"}), 400

    ok_u, url = InputValidator.validate_url(body.url)
    if not ok_u:
        return jsonify({"error": "Invalid URL format"}), 400

    ok_c, content = InputValidator.validate_content(body.content)
    if not ok_c:
        return jsonify({"error": "Invalid content format"}), 400

    result = detector.predict(method, url, content)
    return jsonify(result), 200


@app.route("/api/v1/stats", methods=["GET", "OPTIONS"])
def get_stats():
    if request.method == "OPTIONS":
        return "", 204

    with detector._lock:
        total     = detector.total_requests
        anomalies = detector.anomalies_detected
        normal    = detector.normal_requests
        trained   = detector.model_trained
        accuracy  = detector.model_accuracy

    rate   = (anomalies / total * 100) if total > 0 else 0
    uptime = round((datetime.now() - _start_time).total_seconds(), 1)

    return jsonify({
        "total_requests":     total,
        "anomalies_detected": anomalies,
        "normal_requests":    normal,
        "detection_rate":     round(rate, 2),
        "model_trained":      trained,
        "model_accuracy":     round(accuracy, 4),
        "model_name":         "IsolationForest" if trained else "Not trained",
        "uptime":             uptime,
        "timestamp":          datetime.now().isoformat(),
    }), 200


@app.route("/api/v1/history", methods=["GET", "OPTIONS"])
def get_history():
    if request.method == "OPTIONS":
        return "", 204

    limit  = min(request.args.get("limit",  50, type=int), 500)
    offset = max(request.args.get("offset",  0, type=int), 0)

    with detector._lock:
        history_list  = list(detector.request_history)
        history_slice = history_list[offset: offset + limit]
        total         = len(history_list)

    return jsonify({
        "history": history_slice,
        "total":   total,
        "offset":  offset,
        "limit":   limit,
    }), 200


@app.route("/api/v1/health", methods=["GET"])
def health():
    """Simple health-check endpoint."""
    return jsonify({
        "status":        "ok",
        "model_trained": detector.model_trained,
        "version":       "3.0",
        "timestamp":     datetime.now().isoformat(),
    }), 200


# ==================== MAIN ====================
if __name__ == "__main__":
    sep  = "=" * 70
    dash = "-" * 70

    logger.info(sep)
    logger.info("AI Anomaly Detection System v3.0")
    logger.info("Server   : http://%s:%d", Config.FLASK_HOST, Config.FLASK_PORT)
    logger.info("Frontend : %s", Config.FRONTEND_DIR / "index.html")
    logger.info("Dataset  : %s", Config.DATASET_PATH)
    logger.info(
        "ML Model : %s",
        "trained" if detector.model_trained
        else "NOT trained -- run: python generate_dataset.py",
    )
    logger.info(dash)
    logger.info("Datadog  : disabled (removed)")
    logger.info("Env      : %s", Config.FLASK_ENV)
    logger.info("HTTPS    : %s", Config.ENFORCE_HTTPS)
    logger.info(sep)

    try:
        if Config.FLASK_ENV == "development":
            app.run(
                debug=True,
                host=Config.FLASK_HOST,
                port=Config.FLASK_PORT,
                use_reloader=False,
            )
        else:
            try:
                from waitress import serve
                logger.info("Starting with Waitress (production)...")
                serve(app, host=Config.FLASK_HOST, port=Config.FLASK_PORT, threads=4)
            except ImportError:
                logger.warning("Waitress not found -- falling back to Flask dev server")
                app.run(debug=False, host=Config.FLASK_HOST, port=Config.FLASK_PORT)
    except Exception as e:
        logger.critical("Failed to start server: %s", e, exc_info=True)
        sys.exit(1)