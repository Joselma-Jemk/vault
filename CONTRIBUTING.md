# Contributing

Thanks for your interest in Vault.

## Setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The tests run without a screen (Qt uses the `offscreen` platform).

## Before opening a pull request

- Run `python -m pytest` and make sure everything passes.
- Run `python -m ruff check src tests` and fix what it reports.
- Keep a change focused. One pull request should do one thing.
- Add a test for every behaviour you change, especially anything touching the crypto, the broker,
  or the approval logic.
- Do not weaken the rules in [THREAT_MODEL.md](THREAT_MODEL.md) (for example: no command prints a
  value, approvals stay visible, values never go to the audit log) without discussing it first in an issue.

## Security-sensitive changes

If you find a security problem, report it privately as described in [SECURITY.md](SECURITY.md),
not in a pull request.

## Commit messages

Short and in the imperative mood, for example `Add temporary grants to the broker`.
