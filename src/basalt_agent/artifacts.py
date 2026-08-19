"""Local pull-request artifact generation; no Git or GitHub operation exists here."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path

from .models import PullRequestDraft, RemediationPlan, ValidationRecord, ValidationStatus


@dataclass(frozen=True)
class ArtifactBundle:
    """Locations for one self-contained local review bundle."""

    directory: Path
    patch: Path
    plan: Path
    validation: Path
    pull_request: Path
    manifest: Path


def _draft(plan: RemediationPlan, validation: ValidationRecord) -> PullRequestDraft:
    control_list = ", ".join(plan.control_ids) or "No mapped control IDs"
    body = "\n".join(
        [
            "## Summary",
            plan.summary,
            "",
            "## Finding evidence",
            f"- Plan ID: `{plan.plan_id}`",
            f"- Fingerprint: `{plan.finding_fingerprint}`",
            f"- Rule: `{plan.rule_id}`",
            f"- Controls: {control_list}",
            f"- Source: `{plan.source_relative_path}`",
            "",
            "## Basalt IaC staged validation",
            f"- Status: **{validation.status.value}**",
            f"- Original target findings: {validation.original_target_count}",
            f"- Staged target findings: {validation.staged_target_count}",
            f"- Result: {validation.message}",
            "",
            "## Required human review",
            "- Inspect `remediation.patch` against the target workspace and organizational policy.",
            "- Run appropriate Terraform and environment validation before merging or applying.",
            "- This artifact was generated locally; no branch, commit, GitHub pull request, "
            "or apply occurred.",
        ]
    )
    return PullRequestDraft(
        title=f"fix(terraform): remediate {plan.rule_id}",
        proposed_branch=f"basalt/remediate-{plan.plan_id}",
        body_markdown=body,
    )


def write_artifact_bundle(
    plan: RemediationPlan,
    validation: ValidationRecord,
    original_source: str,
    patched_source: str,
    output_root: Path,
) -> ArtifactBundle:
    """Write immutable local review files only after a staged validator has passed."""
    if validation.status is not ValidationStatus.PASSED:
        raise ValueError("cannot create a pull-request artifact from a failed validation")
    directory = output_root / f"remediation-{plan.plan_id}"
    directory.mkdir(parents=True, exist_ok=False)
    diff = "".join(
        unified_diff(
            original_source.splitlines(keepends=True),
            patched_source.splitlines(keepends=True),
            fromfile=f"a/{plan.source_relative_path}",
            tofile=f"b/{plan.source_relative_path}",
        )
    )
    draft = _draft(plan, validation)
    patch = directory / "remediation.patch"
    plan_path = directory / "plan.json"
    validation_path = directory / "validation.json"
    pull_request = directory / "PULL_REQUEST.md"
    manifest = directory / "manifest.json"
    patch.write_text(diff, encoding="utf-8")
    plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    validation_path.write_text(validation.model_dump_json(indent=2), encoding="utf-8")
    pull_request.write_text(f"# {draft.title}\n\n{draft.body_markdown}\n", encoding="utf-8")
    manifest.write_text(
        "{\n"
        f'  "plan_id": "{plan.plan_id}",\n'
        f'  "proposed_branch": "{draft.proposed_branch}",\n'
        f'  "patch_sha256": "{hashlib.sha256(diff.encode("utf-8")).hexdigest()}"\n'
        "}\n",
        encoding="utf-8",
    )
    return ArtifactBundle(directory, patch, plan_path, validation_path, pull_request, manifest)
