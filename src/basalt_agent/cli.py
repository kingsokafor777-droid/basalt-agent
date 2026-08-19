"""CLI for planning and writing local Basalt Agent remediation review artifacts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from basalt_core import Finding

from .artifacts import write_artifact_bundle
from .models import PlanStatus
from .planner import RemediationPlanner
from .validate import PatchValidator


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="basalt-agent", description="Safety-first Terraform remediation"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, description in (
        ("plan", "Print an immutable remediation plan without writing Terraform source."),
        ("artifact", "Write a local patch and review bundle after staged Basalt IaC validation."),
    ):
        command = commands.add_parser(name, help=description)
        command.add_argument(
            "finding", type=Path, help="Native Basalt Finding JSON from basalt-iac"
        )
        command.add_argument("--source-root", type=Path, required=True)
        if name == "artifact":
            command.add_argument("--output", type=Path, required=True)
    return parser


def _finding(path: Path) -> Finding:
    return Finding.model_validate_json(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    """Plan or bundle a local remediation. No command performs GitHub or Terraform actions."""
    args = _parser().parse_args(argv)
    finding = _finding(args.finding)
    plan = RemediationPlanner().plan(finding, args.source_root)
    if args.command == "plan":
        print(plan.model_dump_json(indent=2))
        return 0
    if plan.status is not PlanStatus.PROPOSED:
        print(plan.model_dump_json(indent=2))
        return 3
    validation, patched_source = PatchValidator().validate(plan, args.source_root)
    if validation.status.value != "passed":
        print(validation.model_dump_json(indent=2))
        return 2
    original_path = args.source_root / plan.source_relative_path
    bundle = write_artifact_bundle(
        plan,
        validation,
        original_path.read_text(encoding="utf-8"),
        patched_source,
        args.output,
    )
    print(
        json.dumps({"artifact_directory": str(bundle.directory), "plan_id": plan.plan_id}, indent=2)
    )
    return 0
