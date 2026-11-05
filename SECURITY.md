# Security policy

This repository is a **lab project, not production software**. The runbook and KQL queries are untested drafts. Test them in a lab workspace before relying on them.

## Reporting a problem

If you find a security issue (for example a query, script or config that could cause harm if copied as is, or anything that looks like an exposed secret), please report it privately through GitHub's **[Report a vulnerability](https://github.com/mikedsosa/entra-account-compromise-ir/security/advisories/new)** form rather than opening a public issue. Ordinary bugs and corrections can go in a normal issue.

Please include the file and line, what you expected and what happened. Reports are handled on a best-effort basis; there is no SLA.

## Secrets and data

- Never include credentials, tokens, tenant IDs or real user data in an issue, pull request or report.
- This repo is meant to contain no secrets. Commits are scanned with `gitleaks`.
- Never commit query exports or evidence from a real tenant (they are git-ignored).

## Supported versions

Only the latest commit on `main` is maintained.
