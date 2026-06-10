# Security Policy

VERDICT is a read-only DFIR analysis tool: it opens evidence read-only, drives a
narrow typed tool surface (no `execute_shell`), and never mutates the evidence
under examination.

## Reporting a vulnerability

Please report security issues **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than opening a
public issue. Include reproduction steps and the affected version/commit. We aim
to acknowledge within 7 days.

## Scope

In scope: the MCP tool surface, the cryptographic chain of custody
(audit log → Merkle root → signature), the read-only evidence-handling
guarantees, and the agent orchestration.

Out of scope: the optional, post-verdict n8n automation sidecar — it runs
outside the audit chain and never touches evidence.
