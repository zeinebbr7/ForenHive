import os
import sys
import pathlib

# Make backend/ importable when running pytest from repo root
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DISABLE_AUTH", "true")
os.environ.setdefault("ALERT_WATCHER_ENABLED", "false")
os.environ.setdefault("PG_PASSWORD", "test")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("SMTP_HOST", "localhost")
