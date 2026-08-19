# ADR 0002: Exact literal mutations only

## Context

Terraform allows expressions, variables, dynamic blocks, modules, and provider defaults. Guessing intended behavior from these constructs would create speculative remediations.

## Decision

The initial policies alter only a single, explicit Terraform assignment that matches an exact expected literal. The source must contain exactly one matching assignment in the expected file. Ambiguous, absent, dynamic, or duplicated assignments fail closed.

## Consequences

Some otherwise remediable findings become `requires_human_input` or `rejected`. This trade-off is intentional: a safe agent should prefer an actionable review queue over a confident but ungrounded patch.
