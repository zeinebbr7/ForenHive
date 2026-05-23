from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class LoginAttempt(BaseModel):
    model_config = ConfigDict(extra="ignore")

    success: bool = False
    username: Optional[str] = None
    password: Optional[str] = None
    timestamp: Optional[str] = None


class CommandRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    timestamp: Optional[str] = None
    input: str = ""
    success: bool = True


class SessionSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    session_id: str
    honeypot: str
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    username: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    command_count: int = 0
    auth_attempts: int = 0
    status: str = "closed"
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None


class SessionDetail(SessionSummary):
    commands: List[CommandRecord] = []
    downloads: List[str] = []
    login_attempts: List[LoginAttempt] = []


class SessionListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total: int
    active: int
    items: List[SessionSummary]
