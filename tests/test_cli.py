from __future__ import annotations

import json

from basalt_agent.cli import main

from .helpers import AZURE_STORAGE, scan_one, write_fixture


def test_cli_writes_a_local_artifact_bundle_without_creating_source_changes(
    tmp_path, capsys
) -> None:
    root = tmp_path / "terraform"
    source_path = write_fixture(root, "storage.tf", AZURE_STORAGE)
    finding = scan_one(root, "azure.storage-public-blob-access-enabled")
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(finding.model_dump_json(), encoding="utf-8")
    output = tmp_path / "artifacts"

    assert main(["plan", str(finding_path), "--source-root", str(root)]) == 0
    planned = json.loads(capsys.readouterr().out)
    assert planned["status"] == "proposed"

    assert (
        main(["artifact", str(finding_path), "--source-root", str(root), "--output", str(output)])
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    artifact_path = output / f"remediation-{created['plan_id']}"
    assert (artifact_path / "remediation.patch").is_file()
    assert source_path.read_text(encoding="utf-8") == AZURE_STORAGE
