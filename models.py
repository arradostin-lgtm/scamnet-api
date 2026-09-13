"""Pydantic models for API request/response validation."""
from __future__ import annotations
from typing import List, Optional, Literal
from pydantic import BaseModel, EmailStr, Field


# ── Auth ──────────────────────────────────────────────────────────────────────

class GoogleAuthCallback(BaseModel):
    code: str
    state: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user: UserPublic


class UserPublic(BaseModel):
    id: str
    email: str
    name: Optional[str]
    avatar_url: Optional[str]
    plan: str
    checks_used: int
    checks_limit: int


# ── Check requests ────────────────────────────────────────────────────────────

class FaceCheckResult(BaseModel):
    risk_level: Literal["clean", "warning", "high", "confirmed"]
    risk_score: float = Field(ge=0, le=100)
    is_ai_generated: bool
    ai_confidence: Optional[float] = None
    detected_ai_model: Optional[str] = None
    match_found: bool
    match_confidence: Optional[float] = None
    profile: Optional[ProfilePublic] = None
    crowdsource: CrowdsourceSignal
    score_breakdown: ScoreBreakdown
    check_id: int


class VoiceCheckResult(BaseModel):
    risk_level: Literal["clean", "warning", "high", "confirmed"]
    risk_score: float
    match_found: bool
    match_confidence: Optional[float] = None
    is_synthetic: bool
    synthetic_confidence: Optional[float] = None
    profile: Optional[ProfilePublic] = None
    check_id: int


class CrowdsourceSignal(BaseModel):
    total_checks: int
    unique_sessions: int
    unique_users: int
    first_seen: Optional[str]
    last_seen: Optional[str]


class ScoreBreakdown(BaseModel):
    db_match: float        # 0–60
    crowdsource: float     # 0–25
    reports: float         # 0–20
    ai_flag: float         # 0 or 20
    total: float           # 0–100


# ── Profiles ──────────────────────────────────────────────────────────────────

class ProfilePublic(BaseModel):
    id: str
    type: str
    confidence: str
    real_name: Optional[str]
    known_as: Optional[str]
    nationality: Optional[str]
    current_status: Optional[str]
    charges: Optional[str]
    sentence: Optional[str]
    verdict_date: Optional[str]
    platforms: List[str] = []
    known_aliases: List[str] = []
    tags: List[str] = []
    victim_count: Optional[int]
    total_damage_usd: Optional[float]
    source: Optional[str]
    source_url: Optional[str]


class ProfileCreate(BaseModel):
    id: str
    type: Literal["convicted", "on_trial", "reported", "suspected"]
    confidence: Literal["high", "medium", "low"] = "medium"
    source: Optional[str] = None
    source_url: Optional[str] = None
    real_name: Optional[str] = None
    known_as: Optional[str] = None
    dob: Optional[str] = None
    nationality: Optional[str] = None
    current_status: Optional[str] = None
    charges: Optional[str] = None
    sentence: Optional[str] = None
    verdict_date: Optional[str] = None
    platforms: List[str] = []
    target_regions: List[str] = []
    known_aliases: List[str] = []
    tags: List[str] = []
    victim_count: Optional[int] = None
    total_damage_usd: Optional[float] = None


# ── Reports ───────────────────────────────────────────────────────────────────

class ReportCreate(BaseModel):
    scam_type: Literal["romance", "investment", "fake_job", "consummation", "gigolo", "other"]
    platform: Optional[str] = None
    amount_lost_usd: Optional[float] = None
    currency: str = "USD"
    description: str = Field(min_length=20, max_length=5000)
    evidence_urls: List[str] = []


class ReportPublic(BaseModel):
    id: int
    scam_type: str
    platform: Optional[str]
    amount_lost_usd: Optional[float]
    description: str
    status: str
    created_at: str


# ── Company check ─────────────────────────────────────────────────────────────

class CompanyCheckResult(BaseModel):
    found: bool
    status: str           # blacklisted | suspicious | unknown | clean
    company: Optional[CompanyPublic] = None
    regulator_flags: List[str] = []


class CompanyPublic(BaseModel):
    id: int
    name: str
    company_type: Optional[str]
    country: Optional[str]
    status: str
    reports_count: int
    regulator_flags: List[str] = []
    notes: Optional[str]
