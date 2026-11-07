"""Small typed contracts shared by VulnFlow's local backend modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ImportValidationError(ValueError):
    def __init__(self, message: str, item_index: int | None = None):
        super().__init__(message)
        self.item_index = item_index


class WorkflowConflict(ValueError):
    pass


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class ImportLimits:
    max_bytes: int = 10 * 1024 * 1024
    max_results: int = 5000
    max_depth: int = 32
    max_string: int = 16_384
    max_evidence: int = 32_768


DEFAULT_LIMITS = ImportLimits()
FINDING_STATES = frozenset({"reported", "investigating", "planned", "patching", "verifying", "resolved", "rejected"})


@dataclass
class NormalizedObservation:
    result_index: int
    title: str
    severity: str
    target: str
    rule_id: str
    tool_name: str
    tool_version: str = ""
    run_id: str = ""
    fingerprint: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    raw_location: dict[str, Any] = field(default_factory=dict)
    normalized_location: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, str]] = field(default_factory=list)
    observed_at: str = ""


@dataclass
class ImportRequest:
    format: str
    source_name: str
    source_sha256: str
    importer_version: str
    tool_name: str
    tool_version: str
    run_id: str
    observations: list[NormalizedObservation]
    raw: dict[str, Any]


@dataclass
class ImportResult:
    import_id: str
    created_findings: int
    observations: int
    duplicate_import: bool = False


@dataclass
class Finding:
    id: str
    dedup_key: str
    title: str
    severity: str
    state: str
    target: str
    rule_id: str
    version: int
    synthetic: bool
    created_at: str
    updated_at: str


@dataclass
class ApprovalRequest:
    id: str
    finding_id: str
    action: str
    target: str
    parameters: dict[str, Any]
    parameter_sha256: str
    requester: str
    approver: str | None
    state: str
    created_at: str
    expires_at: str
    decided_at: str | None
    version: int


@dataclass
class AuditEvent:
    id: int
    actor: str
    event_type: str
    entity_type: str
    entity_id: str
    occurred_at: str
    correlation_id: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str
