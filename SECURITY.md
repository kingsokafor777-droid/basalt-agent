# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories for this repository. Do not include customer Terraform, state files, credentials, or exploit details in public issues.

## Safety model

Basalt Agent intentionally has no cloud, Terraform CLI, Git, GitHub, shell-execution, credential, or network capability. It operates on a temporary local copy and outputs review artifacts only. Treat finding inputs and generated artifacts as security-sensitive because they may include resource identifiers and source locations.

## Limitations

Passing Basalt IaC re-analysis proves only that the targeted static rule no longer matches the staged source. It does not prove provider validity, deployment safety, application behavior, or organizational policy compliance. A human reviewer must still run appropriate Terraform and environment validation.
