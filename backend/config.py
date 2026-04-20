from functools import lru_cache
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    app_env: str = "production"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    log_level: str = "info"

    cors_origins: str = "http://localhost:3000,http://frontend:3000"

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

    ollama_host: str = "http://ollama:11434"
    ollama_model: str = "mistral:7b"
    ollama_timeout: int = 30
    ollama_cache_ttl: int = 3600

    risk_alert_threshold: int = 75
    alert_dedup_window_minutes: int = 15

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

    tsa_url: str = "https://freetsa.org/tsr"
    tsa_cert_url: str = "https://freetsa.org/files/tsa.crt"

    reports_dir: str = "/reports"

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
