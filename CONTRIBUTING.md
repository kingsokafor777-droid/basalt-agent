# Contributing

New remediation policies must be narrow, deterministic, reversible as a source diff, and explicitly revalidated by Basalt IaC. Policies may not guess organization-specific values, remove resources, execute commands, alter state, or introduce network or credential access.

Each policy requires tests covering a successful recheck, an expected-before-state mismatch, a source-root escape attempt, and an unsupported or human-input outcome where relevant. Run `make check` before submitting a pull request.
