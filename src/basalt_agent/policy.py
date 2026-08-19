"""Narrow, deterministic Terraform remediation policies for supported Basalt IaC rules."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class AssignmentPolicy:
    """One exact literal Terraform assignment mutation permitted by the agent."""

    argument: str
    expected_literal_pattern: str
    replacement_literal: str
    rationale: str

    def match(self, line: str) -> re.Match[str] | None:
        expression = (
            rf"^(?P<indent>\s*){re.escape(self.argument)}\s*=\s*"
            rf"(?P<value>{self.expected_literal_pattern})(?P<trailer>\s*(?:#.*)?)$"
        )
        return re.fullmatch(expression, line)

    def replacement(self, match: re.Match[str]) -> str:
        return (
            f"{match.group('indent')}{self.argument} = {self.replacement_literal}"
            f"{match.group('trailer')}"
        )


@dataclass(frozen=True)
class RulePolicy:
    """A remediation decision for one stable Basalt IaC rule identifier."""

    rule_id: str
    summary: str
    assignments: tuple[AssignmentPolicy, ...] = ()
    human_review_reason: str | None = None

    @property
    def supports_automatic_patch(self) -> bool:
        return bool(self.assignments)


_TRUE = "true"
_POLICIES: tuple[RulePolicy, ...] = (
    RulePolicy(
        rule_id="aws.s3-bucket-acl-public",
        summary="Replace an explicit public S3 ACL with the private ACL literal.",
        assignments=(
            AssignmentPolicy(
                argument="acl",
                expected_literal_pattern=r'"(?:public-read|public-read-write)"',
                replacement_literal='"private"',
                rationale="Public ACLs grant access outside the intended identity boundary.",
            ),
        ),
    ),
    RulePolicy(
        rule_id="aws.s3-public-access-block-disabled",
        summary="Enable each explicitly disabled S3 Block Public Access safeguard.",
        assignments=tuple(
            AssignmentPolicy(
                argument=argument,
                expected_literal_pattern="false",
                replacement_literal=_TRUE,
                rationale="Every S3 Block Public Access safeguard must be explicitly enabled.",
            )
            for argument in (
                "block_public_acls",
                "ignore_public_acls",
                "block_public_policy",
                "restrict_public_buckets",
            )
        ),
    ),
    RulePolicy(
        rule_id="azure.storage-secure-transfer-disabled",
        summary="Require HTTPS-only traffic for the Azure Storage Account.",
        assignments=(
            AssignmentPolicy(
                argument="https_traffic_only_enabled",
                expected_literal_pattern="false",
                replacement_literal=_TRUE,
                rationale="Storage traffic should require HTTPS.",
            ),
        ),
    ),
    RulePolicy(
        rule_id="azure.storage-public-blob-access-enabled",
        summary="Disable nested public blob and container access.",
        assignments=(
            AssignmentPolicy(
                argument="allow_nested_items_to_be_public",
                expected_literal_pattern="true",
                replacement_literal="false",
                rationale="Public blob access must be disabled at the storage account boundary.",
            ),
        ),
    ),
    RulePolicy(
        rule_id="azure.storage-minimum-tls-weak",
        summary="Require TLS 1.2 as the Azure Storage Account minimum TLS version.",
        assignments=(
            AssignmentPolicy(
                argument="min_tls_version",
                expected_literal_pattern=r'"(?:TLS1_0|TLS1_1|TLS1_3)"',
                replacement_literal='"TLS1_2"',
                rationale="The Basalt IaC policy requires the explicit TLS1_2 literal.",
            ),
        ),
    ),
    RulePolicy(
        rule_id="aws.security-group-open-admin-ports",
        summary="Administrative ingress requires an organization-approved source range.",
        human_review_reason=(
            "No automatic CIDR can be selected safely. Supply an approved private network, VPN, "
            "or bastion source range through a human-reviewed change."
        ),
    ),
)


def policies() -> Iterable[RulePolicy]:
    """Yield the complete static policy catalogue in deterministic order."""
    return _POLICIES


def policy_for(rule_id: str) -> RulePolicy | None:
    """Return a rule policy by stable Basalt IaC rule ID."""
    return next((policy for policy in _POLICIES if policy.rule_id == rule_id), None)
