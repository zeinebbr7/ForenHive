from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    app_env: str = "production"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "info"

    cors_origins: str = "http://localhost:3000,http://frontend:3000"

    # Auth
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 30
    jwt_refresh_ttl_days: int = 7
    bootstrap_admin_email: str = "admin@forenhive.local"
    bootstrap_admin_password: str = "ChangeMe!2026"
    disable_auth: bool = False

    # PostgreSQL
    pg_host: str = "forenhive-postgresql"
    pg_port: int = 5432
    pg_db: str = "forenhive"
    pg_user: str = "forenhive"
    pg_password: str = ""

    # Elasticsearch
    es_host: str = "http://elasticsearch:9200"
    es_index_cowrie: str = "cowrie-*"
    es_index_dionaea: str = "dionaea-*"
    es_index_galah: str = "galah-*"
    es_index_zeek: str = "zeek-*"
    es_index_honeypot: str = "honeypot-logs-*"
    es_index_alerts: str = "forenhive-alerts"
    es_index_profiles: str = "forenhive-profiles"
    es_index_reports: str = "forenhive-reports"
    es_request_timeout: int = 30

<<<<<<< HEAD
<<<<<<< HEAD
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

=======
>>>>>>> ismail
=======
>>>>>>> ismail
    ollama_host: str = "http://ollama:11434"
    ollama_model: str = "mistral:7b"
    ollama_timeout: int = 30
    ollama_cache_ttl: int = 3600

    risk_alert_threshold: int = 75
    alert_dedup_window_minutes: int = 15
    alert_watcher_enabled: bool = True
    alert_watcher_interval_seconds: int = 15

    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "ForenHive Alerts <alerts@example.com>"
    smtp_starttls: bool = True
    alert_recipients: str = ""

    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    iplocate_api_key: str = ""

    forensic_engine_url: str = "http://forensic-engine:8001"
    forensic_engine_timeout: int = 30

    tsa_url: str = "https://freetsa.org/tsr"
    tsa_cert_url: str = "https://freetsa.org/files/tsa.crt"

    reports_dir: str = "/reports"

    ratelimit_default: str = "200/minute"
    ratelimit_sensitive: str = "10/minute"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def alert_recipients_list(self) -> List[str]:
        return [r.strip() for r in self.alert_recipients.split(",") if r.strip()]

    @property
    def honeypot_indices(self) -> str:
        return ",".join([
            self.es_index_cowrie,
            self.es_index_dionaea,
            self.es_index_galah,
            self.es_index_zeek,
            self.es_index_honeypot,
        ])

    @property
    def pg_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.pg_user}:{self.pg_password}"
            f"@{self.pg_host}:{self.pg_port}/{self.pg_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
