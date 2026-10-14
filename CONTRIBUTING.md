# Contributing

## Setup

```bash
uv sync
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, contract drift
  check, tests with at least 90% branch coverage.
- New behaviour has tests. Security controls need adversarial cases in
  `tests/security`, mapped to a threat ID in `docs/security/threat-model.md`.
- Public API or contract changes regenerate `schemas/` and
  `docs/api/openapi.json` (`uv run python -m mcp_a2a_gateway.contracts`) and
  are recorded in `CHANGELOG.md`.
- Architecturally significant decisions get an ADR in
  `docs/architecture/adr/`.
- No credentials, customer data or PHI in code, tests or fixtures. Use
  synthetic data and `*.test` names only.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`). Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `src/mcp_a2a_gateway/security`, `policies/` or `deployments/` need
approval from a member of the security code owners group (see `CODEOWNERS`).
