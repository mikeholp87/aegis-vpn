# Contributing

1. Read `AGENTS.md` (project rules) and `docs/architecture/ARCHITECTURE.md`.
2. Build: see `docs/development/LINUX.md` or `WINDOWS.md`.
3. Before opening a PR, run:
   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cd apps/desktop && pnpm lint && pnpm typecheck && pnpm test
   ```
4. Add tests with behaviour changes. Security-relevant code (parsing, IPC,
   secrets, firewall, routing) needs tests that would fail if it regressed.
5. Record real results in `docs/testing/TEST_RESULTS.md` when you run live or
   platform tests. Never mark something tested that was not run.
6. Never commit real WireGuard profiles or keys (`*.conf` is git-ignored
   outside `tests/fixtures`).

Contributions are dual-licensed MIT OR Apache-2.0.
