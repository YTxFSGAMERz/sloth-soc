"""Data contracts for Sloth SOC.

Pydantic v2 schemas defining Events, Features, Findings, Briefs, and Digest structures.
Frozen after Phase 0.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Event Enums
EventSource = Literal["sshd", "nginx", "fail2ban", "ufw"]
EventKind = Literal[
    "auth_fail",
    "auth_ok",
    "invalid_user",
    "disconnect",
    "http_req",
    "ban",
    "unban",
    "fw_block",
]

FindingSeverity = Literal["info", "low", "medium", "high", "critical"]
DigestStatus = Literal["quiet", "attention", "urgent"]

ActionEnum = Literal[
    "NO_ACTION_MONITOR",
    "CONFIRM_LEGIT_LOGIN",
    "ROTATE_CREDENTIALS",
    "ENABLE_KEY_ONLY_AUTH",
    "BLOCK_IP_AT_FIREWALL",
    "REVIEW_AUTH_LOG",
    "REVIEW_WEB_LOGS",
]

# Mapping ActionEnum to human-reviewed, safe advisory text
ACTION_TEXT_MAP: dict[ActionEnum, str] = {
    "NO_ACTION_MONITOR": "Continue standard monitoring; no immediate remediation needed.",
    "CONFIRM_LEGIT_LOGIN": "Confirm whether this login was expected and authorized.",
    "ROTATE_CREDENTIALS": "If unrecognized, rotate account credentials and revoke active sessions.",
    "ENABLE_KEY_ONLY_AUTH": "Disable password authentication and enforce SSH key-only access.",
    "BLOCK_IP_AT_FIREWALL": "Block the source address at the host or edge firewall.",
    "REVIEW_AUTH_LOG": "Review authentication logs for surrounding unauthorized access attempts.",
    "REVIEW_WEB_LOGS": "Review web server access logs to verify sensitive endpoints are secured.",
}


class RawRef(BaseModel):
    """Pointer to the original log file and line number."""

    model_config = ConfigDict(frozen=True)

    file: str
    line_no: int


class Event(BaseModel):
    """Normalized, sanitized security log event."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="First 12 hex chars of sha1(source|file|line_no|ts)")
    ts: datetime = Field(description="Timezone-aware UTC timestamp")
    source: EventSource
    kind: EventKind
    host: str
    src_ip: str
    user: str | None = None
    port: int | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    ua: str | None = None
    bytes: int | None = None
    invalid_user: bool = False
    truncated: bool = False
    raw_ref: RawRef

    @field_validator("ts")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)

    @staticmethod
    def generate_id(source: str, file: str, line_no: int, ts: datetime) -> str:
        """Deterministic ID: first 12 hex characters of SHA-1."""
        utc_ts = ts.astimezone(UTC).isoformat() if ts.tzinfo else ts.isoformat()
        content = f"{source}|{file}|{line_no}|{utc_ts}".encode()
        return hashlib.sha1(content).hexdigest()[:12]


class Unparsed(BaseModel):
    """Record of a line that could not be parsed into an Event."""

    model_config = ConfigDict(frozen=True)

    reason: str
    raw_ref: RawRef
    snippet: str = ""


class ParseStats(BaseModel):
    """Statistics on parsed and unparsed lines."""

    lines_total: int = 0
    parsed_total: int = 0
    unparsed_by_reason: dict[str, int] = Field(default_factory=dict)

    @property
    def coverage(self) -> float:
        if self.lines_total == 0:
            return 1.0
        return self.parsed_total / self.lines_total


class FeatureRow(BaseModel):
    """Multi-scale features for a single (IP, UTC day) analysis unit.

    Labels and scenario names live outside this object.
    """

    src_ip: str
    day: str  # YYYY-MM-DD

    # Auth features
    auth_fail_total: int = 0
    auth_fail_max_5m: int = 0
    distinct_users: int = 0
    invalid_user_ratio: float = 0.0
    user_entropy: float = 0.0
    auth_ok_total: int = 0
    ok_after_fail: int = 0

    # Timing features
    iat_cv: float = 0.0
    active_hours: int = 0

    # Web features
    http_total: int = 0
    http_4xx_ratio: float = 0.0
    http_404_ratio: float = 0.0
    probe_hits: int = 0
    probe_2xx: int = 0
    distinct_paths: int = 0
    path_entropy: float = 0.0
    ua_suspicious: int = 0
    ua_distinct: int = 0

    # Firewall features
    fw_block_total: int = 0
    distinct_dst_ports: int = 0
    max_ports_5m: int = 0

    # Context features
    banned: int = 0
    sources_touched: int = 0
    first_seen_ever: int = 0
    new_source_for_user: int = 0

    # Safety / injection features
    inj_marker_hits: int = 0

    @classmethod
    def ml_feature_names(cls) -> list[str]:
        """Names of numeric features safe for ML models (excludes src_ip, day, labels)."""
        exclude = {"src_ip", "day"}
        return [name for name in cls.model_fields if name not in exclude]

    def to_ml_dict(self) -> dict[str, float]:
        """Extract only numeric feature columns for ML, strictly excluding identifiers."""
        features = {}
        for name in self.ml_feature_names():
            val = getattr(self, name)
            features[name] = float(val)
        return features


class FindingEvidence(BaseModel):
    """Structured evidence backing a finding."""

    counts: dict[str, int | float] = Field(default_factory=dict)
    first_ts: str | None = None
    last_ts: str | None = None
    blocked: bool = False
    failed_attempts: int | None = None
    distinct_users: int | None = None


class Finding(BaseModel):
    """Ranked security finding produced deterministically by the detection layer."""

    id: str = Field(description="Finding identifier, e.g. F1, F2")
    severity: FindingSeverity
    kind: str
    entity: str = Field(description="Primary entity, typically the src_ip")
    window: str = Field(description="Time window of activity")
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    reasons: list[str] = Field(default_factory=list, description="Detector codes or rule IDs")
    evidence_refs: list[RawRef] = Field(default_factory=list, max_length=20)
    blocked: bool = False
    score: float = 0.0
    action: ActionEnum = "NO_ACTION_MONITOR"


class BriefStats(BaseModel):
    """High-level summary counts for the LLM brief."""

    raw_lines: int = 0
    findings_total: int = 0
    handled_blocked: int = 0


class Brief(BaseModel):
    """Input payload to the LLM narrator.

    In hardened mode, contains only derived facts, counts, and enums.
    """

    date: str
    status: DigestStatus
    stats: BriefStats
    findings: list[Finding] = Field(default_factory=list)
    untrusted_context: dict[str, Any] | None = Field(
        default=None,
        description="Only used in naive/structured ablation testing; omitted in hardened mode.",
    )


class DigestItem(BaseModel):
    """Narrated summary of an individual finding."""

    finding_id: str = Field(pattern=r"^F[0-9]{1,3}$")
    explanation: str = Field(max_length=280)
    action: ActionEnum


class NarratorOutput(BaseModel):
    """Structured LLM response conforming to DIGEST_SCHEMA."""

    status_claim: DigestStatus
    tldr: str = Field(max_length=240)
    items: list[DigestItem] = Field(default_factory=list, max_length=10)
    noise_note: str | None = Field(default=None, max_length=200)


class DigestMeta(BaseModel):
    """Execution metadata and performance telemetry."""

    date: str
    host_label: str
    generated_at: datetime
    narrator: Literal["llm", "template", "fake"]
    model: str | None = None
    retries: int = 0
    latency_seconds: float = 0.0
    detectors_run: list[str] = Field(default_factory=list)
    parse_coverage: float = 1.0
    raw_lines: int = 0
    attention_items: int = 0
    lazy_ratio: float = 0.0
