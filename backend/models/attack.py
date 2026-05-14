from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HoneypotType(str, Enum):
    COWRIE = "cowrie"
    DIONAEA = "dionaea"
    GALAH = "galah"
    ZEEK = "zeek"
    UNKNOWN = "unknown"


class AttackFilter(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: Optional[str] = None
    country: Optional[str] = None
    severity: Optional[Severity] = None
    honeypot: Optional[HoneypotType] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)


class GeoInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    country_name: Optional[str] = None
    country_iso: Optional[str] = None
    city: Optional[str] = None
    location: Optional[Dict[str, float]] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None


class AttackEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    timestamp: datetime
    honeypot: HoneypotType
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    severity: Severity = Severity.LOW
    risk_score: Optional[int] = None
    event_type: Optional[str] = None
    session_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    user_agent: Optional[str] = None
    geo: Optional[GeoInfo] = None
    raw: Optional[Dict[str, Any]] = None


class AttackListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total: int
    page: int
    page_size: int
    items: List[AttackEvent]


class HourlyBucket(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hour: datetime
    count: int
    by_honeypot: Dict[str, int] = Field(default_factory=dict)


class LiveStats(BaseModel):
    model_config = ConfigDict(extra="ignore")

    window_seconds: int
    count: int
    events_per_second: float
    timestamp: datetime
