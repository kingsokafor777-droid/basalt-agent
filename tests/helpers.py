"""Terraform fixture and Basalt IaC helper functions for agent safety tests."""

from __future__ import annotations

from pathlib import Path

from basalt_core import Finding, ScanContext
from basalt_iac.scanner import IacScanner

AZURE_STORAGE = """resource "azurerm_storage_account" "exports" {
  name                          = "customerexportprod"
  resource_group_name           = "security"
  location                      = "eastus"
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  https_traffic_only_enabled    = false
  allow_nested_items_to_be_public = true
  min_tls_version               = "TLS1_0"
}
"""


PUBLIC_S3_ACL = """resource "aws_s3_bucket_acl" "exports" {
  bucket = aws_s3_bucket.exports.id
  acl    = "public-read"
}
"""


PUBLIC_SSH = """resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
}
"""


def write_fixture(root: Path, name: str, content: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(content, encoding="utf-8")
    return path


def scan_one(root: Path, rule_id: str) -> Finding:
    result = IacScanner().run(ScanContext(paths=[str(root)], rule_filter=[rule_id]))
    assert result.metadata.errors == []
    assert len(result.findings) == 1
    return result.findings[0]
