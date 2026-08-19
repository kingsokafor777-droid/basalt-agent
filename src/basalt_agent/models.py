"""Immutable contracts for safe remediation plans, validation, and review artifacts."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class PlanStatus(str, Enum):
    """Disposition of a finding under the narrow automated remediation policy."""

    PROPOSED = "proposed"
    REQUIRES_HUMAN_INPUT = "requires_human_input"
    REJECTED = "rejected"


class ValidationStatus(str, Enum):
    """Outcome of Basalt IaC re-analysis over an isolated staged copy."""

    PASSED = "passed"
    FAILED = "failed"


class LineMutation(BaseModel):
    """One exact Terraform assignment substitution guarded by its expected source line."""

    model_config = ConfigDict(frozen=True)

    line_number: int = Field(ge=1)
    expected_text: str = Field(min_length=1)
    replacement_text: str = Field(min_length=1)
    rationale: str = Field(min_length=1)


class RemediationPlan(BaseModel):
    """A reviewable, source-bound remediation request; it never executes the edit in place."""

    model_config = ConfigDict(frozen=True)

    finding_fingerprint: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    control_ids: list[str] = Field(default_factory=list)
    resource_urn: str = Field(min_length=1)
    source_relative_path: str = Field(min_length=1)
    source_sha256: str = Field(min_length=64, max_length=64)
    status: PlanStatus
    summary: str = Field(min_length=1)
    human_review_reason: str | None = None
    mutations: list[LineMutation] = Field(default_factory=list)
    safety_notes: list[str] = Field(min_length=1)

    @property
    def plan_id(self) -> str:
        """Stable identifier bound to finding, source hash, and exact intended mutations."""
        material = "\n".join(
            [
                self.finding_fingerprint,
                self.rule_id,
                self.source_relative_path,
                self.source_sha256,
                *[
                    f"{item.line_number}:{item.expected_text}->{item.replacement_text}"
                    for item in self.mutations
                ],
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class ValidationRecord(BaseModel):
    """Evidence that a staged patch was rechecked by Basalt IaC before review artifacts exist."""

    model_config = ConfigDict(frozen=True)

    plan_id: str = Field(min_length=1)
    status: ValidationStatus
    original_target_count: int = Field(ge=0)
    staged_target_count: int = Field(ge=0)
    scanner_errors: list[str] = Field(default_factory=list)
    message: str = Field(min_length=1)


class PullRequestDraft(BaseModel):
    """A local review draft. It is deliberately not a GitHub pull-request payload."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    body_markdown: str = Field(min_length=1)
    proposed_branch: str = Field(min_length=1)
