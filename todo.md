# Project TODO

- [x] Inspect Basalt Core, IaC, RAG, and package conventions for remediation integration points.
- [x] Define immutable remediation-plan, patch, validation, and pull-request artifact contracts.
- [x] Implement a deterministic Terraform remediation policy for supported Basalt IaC findings.
- [x] Enforce explicit safety rules: no apply, no credentials, no destructive resource operations, and no automatic PR submission.
- [x] Implement patch generation with exact source-location and expected-before-state guards.
- [x] Implement Basalt IaC re-analysis of staged Terraform patches and fail closed if the target rule persists.
- [x] Implement a CLI that creates local pull-request artifact bundles and requires explicit user review for any publishing step.
- [x] Add deterministic tests for supported remediation, unsupported findings, mutation guards, analysis regression, and PR artifact rendering.
- [x] Add strict package quality gates, CI, distribution validation, ADRs, security documentation, and examples.
- [x] Verify all rule IDs and control IDs in remediation policies match Basalt Core and Basalt IaC contracts.
- [x] Commit and push basalt-agent to GitHub.
