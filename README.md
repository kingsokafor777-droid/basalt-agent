# Basalt Agent

**Basalt Agent** turns a supported, normalized Basalt IaC finding into a **local, reviewable Terraform remediation pull-request artifact**. It plans a strictly limited literal assignment edit, stages it in an isolated temporary copy, reruns the actual `basalt-iac` scanner, and emits a patch, validation report, and pull-request markdown for a human reviewer.

It is deliberately not an autonomous deployment system. It does **not** execute `terraform`, run `terraform plan` or `apply`, obtain cloud credentials, change the source workspace, create Git branches or commits, contact GitHub, or submit a pull request. Publishing remains an explicit, human-controlled step outside this package.

## Supported remediation policy

| Basalt IaC rule | Guarded mutation | Agent behavior |
|---|---|---|
| `aws.s3-bucket-acl-public` | Replace a literal public ACL with `acl = "private"`. | Generates and rechecks a patch. |
| `aws.s3-public-access-block-disabled` | Replace explicitly false Block Public Access arguments with `true`. | Generates and rechecks a patch. |
| `azure.storage-secure-transfer-disabled` | Replace `https_traffic_only_enabled = false` with `true`. | Generates and rechecks a patch. |
| `azure.storage-public-blob-access-enabled` | Replace `allow_nested_items_to_be_public = true` with `false`. | Generates and rechecks a patch. |
| `azure.storage-minimum-tls-weak` | Replace the explicit value with `min_tls_version = "TLS1_2"`. | Generates and rechecks a patch. |
| `aws.security-group-open-admin-ports` | No automatic patch. | Returns `requires_human_input`: an organization-approved CIDR must never be guessed. |

## Safety contract

Every remediation plan is immutable and contains the finding fingerprint, source location, expected before-state, replacement text, controls, source hash, validation result, and review requirements. A patch is rejected if its path escapes the requested source root, the expected literal occurs zero or multiple times, the original scanner no longer detects the referenced rule, the staged scan errors, or the target rule remains after applying the patch.

> **No automatic merge or pull-request submission exists in Basalt Agent.** The generated PR artifact is a draft for review. A human must inspect the diff, run environment-specific Terraform validation, and independently authorize any GitHub or infrastructure action.

## Architecture

```text
Basalt IaC Finding ──> policy lookup ──> immutable remediation plan
                                               │
Terraform source root ──> isolated staged copy ┼─> exact guarded patch
                                               │
                                               └─> Basalt IaC re-analysis
                                                          │
                                                          ▼
                                         local PR artifact: patch + report + markdown
```

## Quick start

```bash
pip install basalt-agent

# Analyze a native Basalt finding JSON and create a local review bundle.
basalt-agent artifact finding.json --source-root ./infrastructure --output ./basalt-agent-artifacts

# Print an immutable plan without creating files.
basalt-agent plan finding.json --source-root ./infrastructure
```

The input must be a single native `basalt_core.Finding` JSON document from `basalt-iac`. The output directory may be committed to a review branch by a human, but the agent never invokes Git or GitHub.

## Validation

```bash
make install
make check
make build
python -m twine check dist/*
```

The suite exercises safe remediation, unsupported-policy handling, source mutation guards, source-root path confinement, Basalt IaC re-analysis, deterministic artifacts, and CLI behavior.

## Integration boundary

Basalt Agent consumes findings from Basalt Core, uses the scanner remediation metadata as source material, and invokes Basalt IaC only on an isolated copy of Terraform sources. It never reads secrets, modifies a user’s source workspace, or makes a cloud, Terraform, GitHub, or LLM call.

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
