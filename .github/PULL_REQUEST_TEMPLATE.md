<!-- Place this file at .github/PULL_REQUEST_TEMPLATE.md -->

## Summary

<!-- What does this change, and why? Link the issue it addresses. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor or cleanup (no behavior change)
- [ ] Documentation or tests only
- [ ] Dependency or CI change

## How it was tested

<!-- Commands you ran, pages you tried, platforms you checked. -->

## Checklist

- [ ] I read `CONTRIBUTING.md` and this follows the project rules (no telemetry, `app` does not depend on `network`, `account` and `sync` stay independent, no C/C++ parsers on the untrusted path)
- [ ] `cargo fmt --all -- --check`, `cargo build --workspace --all-targets`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets` pass locally
- [ ] Tests added or updated
- [ ] Module `//!` docs, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `README.md`, and `CHANGELOG.md` updated where relevant
- [ ] No secrets, personal data, or local paths are included

## Security-sensitive changes

<!-- Delete this section if it does not apply. -->

- [ ] This touches the sandbox, IPC, account/crypto, sync, file writes, or privacy logic
- [ ] If the renderer now does new I/O, I re-checked the seccomp allowlist
- [ ] I described any new attack surface in `THREAT_MODEL.md`

## Notes for the reviewer

<!-- Tradeoffs, known limitations, follow-ups. -->
