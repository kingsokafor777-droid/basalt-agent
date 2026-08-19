"""Source-bound remediation planning that never changes the caller's Terraform workspace."""

from __future__ import annotations

import hashlib
from pathlib import Path

from basalt_core import Finding, load_catalog

from .models import LineMutation, PlanStatus, RemediationPlan
from .policy import RulePolicy, policy_for


class UnsupportedRemediationError(ValueError):
    """Raised when a finding cannot be safely planned under the explicit policy catalogue."""


class SourceGuardError(ValueError):
    """Raised when a plan cannot prove an exact, contained, single-occurrence source mutation."""


_SAFETY_NOTES = [
    "No Terraform command, provider, cloud API, Git, GitHub, credential, or network call is made.",
    "The original Terraform workspace is never edited; validation uses an isolated temporary copy.",
    "A human must inspect the patch and run environment-specific validation before "
    "publishing or applying it.",
]


def _contained_path(root: Path, path_value: str) -> tuple[Path, str]:
    root_resolved = root.resolve()
    candidate = (root_resolved / path_value).resolve()
    try:
        relative = candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise SourceGuardError("finding location escapes the requested source root") from exc
    if candidate.suffix != ".tf" or not candidate.is_file():
        raise SourceGuardError(
            "finding location must resolve to an existing native Terraform .tf file"
        )
    return candidate, relative.as_posix()


def _resource_block(source_lines: list[str], start_line: int) -> tuple[int, int]:
    """Return zero-based inclusive bounds for the finding's resource block using brace balance."""
    start = start_line - 1
    if start < 0 or start >= len(source_lines) or "resource" not in source_lines[start]:
        raise SourceGuardError("finding source location is not a Terraform resource header")
    depth = 0
    for index in range(start, len(source_lines)):
        depth += source_lines[index].count("{") - source_lines[index].count("}")
        if depth == 0 and index > start:
            return start, index
    raise SourceGuardError("could not determine the end of the Terraform resource block")


class RemediationPlanner:
    """Creates immutable plans for explicit literal mutations supported by Basalt IaC."""

    def plan(self, finding: Finding, source_root: Path) -> RemediationPlan:
        """Plan a safe patch from one Basalt IaC finding without modifying any source file."""
        if finding.scanner != "basalt-iac":
            raise UnsupportedRemediationError("agent accepts findings emitted by basalt-iac only")
        unknown_controls = load_catalog().unknown(finding.control_ids)
        if unknown_controls:
            raise UnsupportedRemediationError(
                f"finding includes unknown Basalt controls: {', '.join(unknown_controls)}"
            )
        if finding.location is None or finding.location.start_line is None:
            raise SourceGuardError("IaC finding is missing an actionable Terraform source location")
        policy = policy_for(finding.rule_id)
        if policy is None:
            raise UnsupportedRemediationError(f"no remediation policy exists for {finding.rule_id}")
        path, relative_path = _contained_path(source_root, finding.location.path)
        source = path.read_text(encoding="utf-8")
        source_lines = source.splitlines()
        block_start, block_end = _resource_block(source_lines, finding.location.start_line)
        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if not policy.supports_automatic_patch:
            return RemediationPlan(
                finding_fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                control_ids=finding.control_ids,
                resource_urn=finding.resource.urn,
                source_relative_path=relative_path,
                source_sha256=source_hash,
                status=PlanStatus.REQUIRES_HUMAN_INPUT,
                summary=policy.summary,
                human_review_reason=policy.human_review_reason,
                safety_notes=_SAFETY_NOTES,
            )
        mutations = self._mutations(source_lines, block_start, block_end, policy)
        if not mutations:
            raise SourceGuardError(
                "no exact insecure literal assignment was found in the target resource"
            )
        return RemediationPlan(
            finding_fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            control_ids=finding.control_ids,
            resource_urn=finding.resource.urn,
            source_relative_path=relative_path,
            source_sha256=source_hash,
            status=PlanStatus.PROPOSED,
            summary=policy.summary,
            mutations=mutations,
            safety_notes=_SAFETY_NOTES,
        )

    @staticmethod
    def _mutations(
        source_lines: list[str], block_start: int, block_end: int, policy: RulePolicy
    ) -> list[LineMutation]:
        mutations: list[LineMutation] = []
        for assignment in policy.assignments:
            matches = [
                (line_number, assignment.match(source_lines[line_number]))
                for line_number in range(block_start, block_end + 1)
                if assignment.match(source_lines[line_number]) is not None
            ]
            if len(matches) > 1:
                raise SourceGuardError(
                    f"{assignment.argument} has multiple insecure literals in one resource block"
                )
            if not matches:
                continue
            line_number, match = matches[0]
            assert match is not None
            mutations.append(
                LineMutation(
                    line_number=line_number + 1,
                    expected_text=source_lines[line_number],
                    replacement_text=assignment.replacement(match),
                    rationale=assignment.rationale,
                )
            )
        return mutations
