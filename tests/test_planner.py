from __future__ import annotations

import pytest

from basalt_agent.models import PlanStatus
from basalt_agent.planner import RemediationPlanner, SourceGuardError, UnsupportedRemediationError

from .helpers import AZURE_STORAGE, PUBLIC_S3_ACL, PUBLIC_SSH, scan_one, write_fixture


def test_plans_exact_literal_without_mutating_the_original_workspace(tmp_path) -> None:
    root = tmp_path / "terraform"
    path = write_fixture(root, "storage.tf", AZURE_STORAGE)
    finding = scan_one(root, "azure.storage-public-blob-access-enabled")

    plan = RemediationPlanner().plan(finding, root)

    assert plan.status is PlanStatus.PROPOSED
    assert plan.rule_id == finding.rule_id
    assert plan.source_relative_path == "storage.tf"
    assert len(plan.mutations) == 1
    assert plan.mutations[0].expected_text.endswith("= true")
    assert plan.mutations[0].replacement_text.endswith("= false")
    assert path.read_text(encoding="utf-8") == AZURE_STORAGE
    assert plan.control_ids == ["cis-azure:storage.public-blob-access"]


def test_public_acl_policy_replaces_only_the_explicit_public_acl_literal(tmp_path) -> None:
    root = tmp_path / "terraform"
    write_fixture(root, "s3.tf", PUBLIC_S3_ACL)
    finding = scan_one(root, "aws.s3-bucket-acl-public")

    plan = RemediationPlanner().plan(finding, root)

    assert plan.status is PlanStatus.PROPOSED
    assert plan.mutations[0].replacement_text.strip() == 'acl = "private"'


def test_open_management_ingress_requires_human_input_instead_of_guessing_a_cidr(tmp_path) -> None:
    root = tmp_path / "terraform"
    write_fixture(root, "network.tf", PUBLIC_SSH)
    finding = scan_one(root, "aws.security-group-open-admin-ports")

    plan = RemediationPlanner().plan(finding, root)

    assert plan.status is PlanStatus.REQUIRES_HUMAN_INPUT
    assert plan.mutations == []
    assert plan.human_review_reason is not None
    assert "CIDR" in plan.human_review_reason


def test_rejects_non_iac_findings_before_source_access(tmp_path) -> None:
    root = tmp_path / "terraform"
    write_fixture(root, "s3.tf", PUBLIC_S3_ACL)
    finding = scan_one(root, "aws.s3-bucket-acl-public").model_copy(
        update={"scanner": "basalt-aws"}
    )

    with pytest.raises(UnsupportedRemediationError, match="basalt-iac"):
        RemediationPlanner().plan(finding, root)


def test_rejects_location_outside_source_root(tmp_path) -> None:
    root = tmp_path / "terraform"
    write_fixture(root, "s3.tf", PUBLIC_S3_ACL)
    finding = scan_one(root, "aws.s3-bucket-acl-public")
    assert finding.location is not None
    escaped = finding.model_copy(
        update={"location": finding.location.model_copy(update={"path": "../x.tf"})}
    )

    with pytest.raises(SourceGuardError, match="escapes"):
        RemediationPlanner().plan(escaped, root)
