## What changed

Describe the smallest useful behavior change.

## Security impact

Explain changes to trust boundaries, fail-open/fail-closed behavior, private data,
CA handling, proxying, scanner verdicts, or bypasses. Write “none” when applicable.

## Verification

- [ ] `make lint` (rustfmt and clippy)
- [ ] `make test`
- [ ] Documentation and tests cover changed behavior
- [ ] No credentials, private payloads, registry URLs, or CA material are included
