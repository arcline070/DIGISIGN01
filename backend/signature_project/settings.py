import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
#  Load .env (lightweight, no extra dependency)
# ---------------------------------------------------------------------------
_env_path = BASE_DIR / ".env"
if _env_path.is_file():
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ.setdefault(_key.strip(), _val.strip())

# ---------------------------------------------------------------------------
#  Issue #1 — SECRET_KEY from environment (fail-fast if missing/insecure)
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY.startswith("django-insecure"):
    raise RuntimeError(
        "SECRET_KEY is missing or insecure. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\" "
        "and set it in your .env file."
    )

# ---------------------------------------------------------------------------
#  Issue #2 — DEBUG from environment, default False
# ---------------------------------------------------------------------------
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
#  Issue #8 — ALLOWED_HOSTS from environment
# ---------------------------------------------------------------------------
_allowed = os.getenv("ALLOWED_HOSTS", "")
ALLOWED_HOSTS = [h.strip() for h in _allowed.split(",") if h.strip()] if _allowed else []

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "signature_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "signature_project.wsgi.application"

# ---------------------------------------------------------------------------
#  Database — PostgreSQL with connection pooling (Issue #9)
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "signature_engine"),
        "USER": os.getenv("DB_USER", "postgres"),
        "PASSWORD": os.getenv("DB_PASSWORD", "postgres"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
        # Issue #9 — Persistent connections: reuse for 10 minutes
        "CONN_MAX_AGE": 600,
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
#  Static files  (Issue #13)
# ---------------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
#  Issue #4 — File upload size limit (50 MB)
# ---------------------------------------------------------------------------
DATA_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024  # 50 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024  # 50 MB

# ---------------------------------------------------------------------------
#  Django REST Framework  (Issue #6 — Rate Limiting)
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.MultiPartParser",
        "rest_framework.parsers.FormParser",
    ],
    # Issue #6 — Throttling: prevent brute-force and abuse
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "20/minute",       # Unauthenticated (login, register)
        "user": "120/minute",      # Authenticated API calls
    },
}

# ---------------------------------------------------------------------------
#  CORS  (Issue #11 — env-driven origins)
# ---------------------------------------------------------------------------
_cors_raw = os.getenv("CORS_ALLOWED_ORIGINS", "")
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()] if _cors_raw else []
CORS_ALLOW_CREDENTIALS = True

# ---------------------------------------------------------------------------
#  Issue #7 — HTTPS / Security hardening (active when DEBUG is False)
# ---------------------------------------------------------------------------
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000          # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ---------------------------------------------------------------------------
#  Cryptographic key storage
# ---------------------------------------------------------------------------
# Base64 urlsafe 32-byte Fernet key. Set this in environment for production.
# Supports both FERNET_KEY (preferred) and PRIVATE_KEY_FERNET_KEY.
PRIVATE_KEY_FERNET_KEY = os.getenv("FERNET_KEY", "") or os.getenv("PRIVATE_KEY_FERNET_KEY", "")

# ---------------------------------------------------------------------------
#  Vulnerability #3 — Secure Genesis Block (H_0)
# ---------------------------------------------------------------------------
# Cryptographically fixed genesis hash used as the prev_chain_hash for the
# very first DocumentVersion in every hash chain.  This MUST be a 64-character
# lowercase hex string (the representation of a SHA-256 digest).
#
# Generate a production value once with:
#   python -c "import secrets; print(secrets.token_hex(32))"
#
# Store it in the .env file as HASH_CHAIN_GENESIS=<value>.
# ---------------------------------------------------------------------------
import re as _re

HASH_CHAIN_GENESIS = os.getenv(
    "HASH_CHAIN_GENESIS",
    # Default for local development — override in production .env
    "000000000000000000000000000000000000000000000000000000000000dead",
)

# Fail-fast: reject obviously invalid genesis values at startup.
assert (
    isinstance(HASH_CHAIN_GENESIS, str)
    and len(HASH_CHAIN_GENESIS) == 64
    and _re.fullmatch(r"[0-9a-f]{64}", HASH_CHAIN_GENESIS)
), (
    f"HASH_CHAIN_GENESIS must be a 64-character lowercase hex string. "
    f"Got: {HASH_CHAIN_GENESIS!r}"
)

# ---------------------------------------------------------------------------
#  Issue #10 — Structured Logging
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {module}:{lineno} — {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {name} — {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": BASE_DIR / "logs" / "signature_engine.log",
            "maxBytes": 10 * 1024 * 1024,  # 10 MB
            "backupCount": 5,
            "formatter": "verbose",
        },
    },
    "loggers": {
        # Application loggers
        "api": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        # Django internals
        "django": {
            "handlers": ["console", "file"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console", "file"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
}
