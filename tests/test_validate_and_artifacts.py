from __future__ import annotations

import pytest

from basalt_agent.artifacts import write_artifact_bundle
from basalt_agent.models import ValidationStatus
from basalt_agent.planner import RemediationPlanner, SourceGuardError
from basalt_agent.validate import PatchValidator, apply_plan_to_source

from .helpers import AZURE_STORAGE, scan_one, write_fixture


def test_staged_iac_reanalysis_clears_only_the_target_rule_and_writes_review_artifacts(
    tmp_path,
) -> None:
    root = tmp_path / "terraform"
    source_path = write_fixture(root, "storage.tf", AZURE_STORAGE)
    finding = scan_one(root, "azure.storage-public-blob-access-enabled")
    plan = RemediationPlanner().plan(finding, root)

    validation, patched = PatchValidator().validate(plan, root)
    bundle = write_artifact_bundle(
        plan,
        validation,
        source_path.read_text(encoding="utf-8"),
        patched,
        tmp_path / "artifacts",
    )

    assert validation.status is ValidationStatus.PASSED
    assert validation.original_target_count == 1
    assert validation.staged_target_count == 0
    assert source_path.read_text(encoding="utf-8") == AZURE_STORAGE
    assert "allow_nested_items_to_be_public = false" in bundle.patch.read_text(encoding="utf-8")
    assert plan.plan_id in bundle.pull_request.read_text(encoding="utf-8")
    assert (
        "no branch, commit, GitHub pull request, or apply occurred"
        in bundle.pull_request.read_text(encoding="utf-8")
    )


def test_source_hash_guard_rejects_stale_plan_before_mutation(tmp_path) -> None:
    root = tmp_path / "terraform"
    path = write_fixture(root, "storage.tf", AZURE_STORAGE)
    finding = scan_one(root, "azure.storage-public-blob-access-enabled")
    plan = RemediationPlanner().plan(finding, root)
    path.write_text(f"# changed after planning\n{AZURE_STORAGE}", encoding="utf-8")

    with pytest.raises(SourceGuardError, match="changed after planning"):
        apply_plan_to_source(plan, path.read_text(encoding="utf-8"))


def test_exact_line_guard_rejects_drift_even_with_matching_source_hash_contract(tmp_path) -> None:
    root = tmp_path / "terraform"
    write_fixture(root, "storage.tf", AZURE_STORAGE)
    finding = scan_one(root, "azure.storage-public-blob-access-enabled")
    plan = RemediationPlanner().plan(finding, root)
    altered = AZURE_STORAGE.replace(
        "allow_nested_items_to_be_public = true", "allow_nested_items_to_be_public = false"
    )

    with pytest.raises(SourceGuardError):
        apply_plan_to_source(plan, altered)
