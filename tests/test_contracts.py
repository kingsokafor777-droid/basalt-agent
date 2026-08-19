from __future__ import annotations

from basalt_core import load_catalog
from basalt_iac.registry import get_check
from basalt_iac.scanner import IacScanner

from basalt_agent.policy import policies


def test_every_agent_policy_maps_to_a_real_iac_rule_and_core_control() -> None:
    IacScanner()  # Imports the IaC rule registry through the supported scanner entry point.
    catalog = load_catalog()

    for policy in policies():
        check = get_check(policy.rule_id)
        assert catalog.unknown(check.control_ids) == []
