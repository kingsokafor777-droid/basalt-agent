# ADR 0001: Generate local review artifacts, never autonomous pull requests

## Context

Infrastructure remediation can alter production behavior. Generating and submitting a pull request without human inspection compounds the risk of an incorrectly grounded finding, an invalid source edit, or an unsafe organizational assumption.

## Decision

Basalt Agent writes only a local patch, machine-readable plan and validation documents, and reviewer-facing pull-request markdown. It neither initializes Git state nor calls a GitHub API. A source workspace is copied to an isolated temporary directory for re-analysis, leaving the original workspace untouched.

## Consequences

The package cannot close the final human approval loop by itself. In exchange, it has a clear operational trust boundary: every source mutation is reviewable, deterministic, and linked to a verified static-analysis result.
