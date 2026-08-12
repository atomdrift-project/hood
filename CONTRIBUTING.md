# Contributing

Thanks for helping improve `hood`. Small, focused changes with tests are easiest to
review.

## Before opening a pull request

1. Discuss large design or security-boundary changes in an issue first.
2. Never include package credentials, intercepted payloads, private registry URLs,
   model data, or ephemeral CA material in fixtures or logs.
3. Run the same checks as CI:

   ```sh
   cargo fmt --check
   make lint
   make test
   ```

4. Update the README when behavior, coverage, security boundaries, or bypasses change.
5. Explain the threat model and failure behavior for security-sensitive changes.

By submitting a contribution, you agree that it is licensed under Apache-2.0.
Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.
