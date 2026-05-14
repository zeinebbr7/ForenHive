from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AlertTrigger(str, Enum):
    HIGH_SEVERITY = "high_severity"
    BRUTE_FORCE = "brute_force"
    MALWARE_DETECTED = "malware_detected"
    C2_MATCH = "c2_match"
    NEW_IP = "new_ip"
    TOR_EXIT = "tor_exit"
    INSIDER_THREAT = "insider_threat"


class AlertConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    recipients: List[EmailStr]
    threshold: int = Field(75, ge=0, le=100)
    triggers: List[AlertTrigger] = Field(default_factory=lambda: [AlertTrigger.HIGH_SEVERITY])
    dedup_window_minutes: int = Field(15, ge=1, le=1440)
    enabled: bool = True


class AlertConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    recipients: Optional[List[EmailStr]] = None
    threshold: Optional[int] = Field(None, ge=0, le=100)
    triggers: Optional[List[AlertTrigger]] = None
    dedup_window_minutes: Optional[int] = Field(None, ge=1, le=1440)
    enabled: Optional[bool] = None


class AlertRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    timestamp: datetime
    severity: str
    threat_type: str
    source_ip: Optional[str] = None
    country: Optional[str] = None
    honeypot: Optional[str] = None
    risk_score: int
    attempts: int = 0
    mitre_tags: List[str] = []
    yara_match: Optional[str] = None
    abuseipdb_score: Optional[int] = None
    ioc_hash: Optional[str] = None
    tsa_timestamp: Optional[str] = None
    mistral_analysis: Optional[str] = None
    is_internal: bool = False
    network_class: Optional[str] = None
    recipients: List[str] = []
    dispatched: bool = False
    dispatch_error: Optional[str] = None


class AlertHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total: int
    items: List[AlertRecord]


class TestAlertResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sent: bool
    recipients: List[str]
    message: str
