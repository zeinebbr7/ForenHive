from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReportScope(str, Enum):
    IP = "ip"
    SESSION = "session"
    TIME_RANGE = "time_range"


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    scope: ReportScope
    ip: Optional[str] = None
    session_id: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    title: Optional[str] = None
    include_stix: bool = False
    analyst: Optional[str] = None


class ReportMeta(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    title: str
    scope: ReportScope
    created_at: datetime
    created_by: Optional[str] = None
    path: str
    sha256: str
    tsa_timestamp: Optional[str] = None
    size_bytes: int
    event_count: int = 0
    stix_path: Optional[str] = None


class ReportListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total: int
    items: List[ReportMeta]


class ProfileGeo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    country: Optional[str] = None
    country_iso: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    as_org: Optional[str] = None
    is_tor: bool = False
    is_vpn: bool = False


class ProfileMITRE(BaseModel):
    model_config = ConfigDict(extra="ignore")

    technique_id: str
    technique_name: Optional[str] = None
    tactic: Optional[str] = None


class AttackerProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_count: int = 0
    session_count: int = 0
    honeypots: List[str] = []
    country: Optional[str] = None
    country_iso: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    as_org: Optional[str] = None
    is_tor: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    abuseipdb_score: Optional[int] = None
    abuseipdb_reports: Optional[int] = None
    usage_type: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    mitre_techniques: List[str] = []
    yara_matches: List[str] = []
    ioc_hashes: List[str] = []
    risk_score: int = 0
    mistral_analysis: Optional[str] = None
    top_usernames: List[str] = []
    top_passwords: List[str] = []
    top_commands: List[str] = []
    recent_events: List[Dict[str, Any]] = []
    sessions: List[Dict[str, Any]] = []
