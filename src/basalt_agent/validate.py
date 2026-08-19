"""Isolated staging and Basalt IaC re-analysis for proposed remediation plans."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path

from basalt_core import Finding, ScanContext, ScanResult
from basalt_iac.scanner import IacScanner

from .models import PlanStatus, RemediationPlan, ValidationRecord, ValidationStatus
from .planner import SourceGuardError


class ValidationError(ValueError):
    """Raised when a plan cannot be safely staged or fails Basalt IaC re-analysis."""


def apply_plan_to_source(plan: RemediationPlan, source: str) -> str:
    """Apply exact plan lines in memory, failing closed on hash or source-text drift."""
    if plan.status is not PlanStatus.PROPOSED:
        raise ValidationError("only proposed plans with explicit mutations may be staged")
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != plan.source_sha256:
        raise SourceGuardError(
            "Terraform source changed after planning; regenerate the remediation plan"
        )
    lines = source.splitlines(keepends=True)
    for mutation in plan.mutations:
        index = mutation.line_number - 1
        if index < 0 or index >= len(lines):
            raise SourceGuardError("planned source line no longer exists")
        current = lines[index].rstrip("\r\n")
        if current != mutation.expected_text:
            raise SourceGuardError("planned source line no longer matches the expected literal")
        ending = "\r\n" if lines[index].endswith("\r\n") else "\n"
        lines[index] = f"{mutation.replacement_text}{ending}"
    return "".join(lines)


class PatchValidator:
    """Stages a plan in a temporary copy and checks the target rule with Basalt IaC."""

    def validate(self, plan: RemediationPlan, source_root: Path) -> tuple[ValidationRecord, str]:
        """Return a validation record and staged source; never change the original workspace."""
        source_root = source_root.resolve()
        original_path = (source_root / plan.source_relative_path).resolve()
        try:
            original_path.relative_to(source_root)
        except ValueError as exc:
            raise SourceGuardError("plan source path escapes the requested source root") from exc
        source = original_path.read_text(encoding="utf-8")
        patched = apply_plan_to_source(plan, source)
        original_result = self._scan(source_root, plan.rule_id)
        with tempfile.TemporaryDirectory(prefix="basalt-agent-") as temporary:
            staged_root = Path(temporary) / "workspace"
            shutil.copytree(source_root, staged_root)
            staged_path = staged_root / plan.source_relative_path
            staged_path.write_text(patched, encoding="utf-8")
            staged_result = self._scan(staged_root, plan.rule_id)
        original_targets = self._matching_findings(original_result.findings, plan)
        staged_targets = self._matching_findings(staged_result.findings, plan)
        errors = [*original_result.metadata.errors, *staged_result.metadata.errors]
        if not original_targets:
            return (
                ValidationRecord(
                    plan_id=plan.plan_id,
                    status=ValidationStatus.FAILED,
                    original_target_count=0,
                    staged_target_count=len(staged_targets),
                    scanner_errors=errors,
                    message="Basalt IaC did not reproduce the target finding before staging.",
                ),
                patched,
            )
        if errors or staged_targets:
            return (
                ValidationRecord(
                    plan_id=plan.plan_id,
                    status=ValidationStatus.FAILED,
                    original_target_count=len(original_targets),
                    staged_target_count=len(staged_targets),
                    scanner_errors=errors,
                    message=(
                        "Basalt IaC validation failed: target finding persists or the scanner "
                        "reported errors."
                    ),
                ),
                patched,
            )
        return (
            ValidationRecord(
                plan_id=plan.plan_id,
                status=ValidationStatus.PASSED,
                original_target_count=len(original_targets),
                staged_target_count=0,
                message=(
                    "Basalt IaC no longer detected the target rule in the isolated staged copy."
                ),
            ),
            patched,
        )

    @staticmethod
    def _matching_findings(findings: list[Finding], plan: RemediationPlan) -> list[Finding]:
        """Match the rule and Terraform resource, excluding copied-workspace location paths."""
        return [
            finding
            for finding in findings
            if finding.rule_id == plan.rule_id and finding.resource.urn == plan.resource_urn
        ]

    @staticmethod
    def _scan(source_root: Path, rule_id: str) -> ScanResult:
        return IacScanner().run(ScanContext(paths=[str(source_root)], rule_filter=[rule_id]))
