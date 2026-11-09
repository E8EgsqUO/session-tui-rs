# Engineering audit and incremental improvement — 2026-11-09

Scope: clean repository at `af553ef` (0.11.0). Changes are intentionally incremental. No account data, production database, or real contact was used in tests. No live multi-device session, public release, or remote exploit was exercised.

## Findings, ordered by severity

| Severity | Classification | Finding | Outcome |
|---|---|---|---|
| High | Confirmed defect, reproduced with negative tests | Both custom TLS verifiers returned success for TLS 1.2/1.3 handshake signatures without checking them. Copying a pinned certificate did not require possession of its private key. | Fixed using rustls provider signature verification; valid, forged-transcript, and mismatched-key tests cover both versions. |
| Medium | Confirmed defect in failure handling | Structurally invalid HTTP 200 expiry replies could become `None`, indistinguishable from an actually expired hash, causing premature local deletion. | Added a validated parser. Valid absent-hash semantics remain unchanged; malformed results now fail for outbox retry. |
| Medium | Confirmed engineering defect | Cargo auto-discovered helper files in `src/bin` as runnable programs. Baseline `cargo clippy --all-targets` failed on a helper with no `main`. | `autobins = false`; the explicitly declared `session-tui` binary retains all helper modules and their tests. |
| Medium | Confirmed engineering gap | CI built artifacts without running format, Clippy, tests, or an advisory audit. Existing formatting was inconsistent. | Added quality/security jobs; release depends on them. Established a separate mechanical rustfmt baseline. |
| Medium | Potential dependency risk, not demonstrated application exploit | `lru 0.12.5`, through ratatui, has two informational unsoundness advisories. | Recorded below; no blanket advisory ignores or risky UI dependency migration. |
| Medium | Coverage/compatibility risk | Real multi-device disappearance, group key rotation, storage-node failover and platform TLS remain more complex than offline tests can establish. | Added failure/restart tests; keep a live compatibility checklist. No speculative protocol changes. |
| Low | Confirmed maintainability/documentation issues | Main binary couples UI, commands, persistence, network operations, cryptography orchestration and state reconciliation. Recovery claims were broader than retry limits and attachment support. | First pure-logic module extracted; README scope corrected; phased plan below. |

## Batch boundaries and evidence

| Batch | Change | Core tests | TUI tests |
|---|---|---:|---:|
| Baseline | Original unique core/TUI suites | 414 | 50 |
| 1 | Extract pure helpers; declare Cargo binary scope | 414 | 50 |
| 2 | Require valid TLS handshake signatures | 416 | 50 |
| 3 | Migration/restart/commit failure/HTTP boundaries; classify body timeouts | 420 | 59 |
| 4 | Mechanical formatting baseline; quality/security CI and README scope | 420 | 59 |
| 5 | Validate expiry reply structure; final documented checks | 420 | 60 |
| 6 | Share the existing store-test environment lock with new fixtures | 420 | 60 |

Baseline Cargo additionally ran duplicated helper-module test binaries; those are no longer independent targets. Their tests still run under the real TUI binary. Test counts above count the core and TUI suites once.

The two new TLS security tests were also executed against an isolated copy of the original verifier: **both failed**. Against the fixed verifier they pass. The test certificate/private key fixtures are deliberately public test material, not application credentials.

## Invariants kept

- No changes to Session protobuf definitions, signature canonical strings, namespaces, TTL policy, receipt policy, message identities, or expiry lifecycle for valid protocol messages.
- No changes to production schema, SQLCipher parameters, history key derivation, serialized message compatibility, attachment encryption, or saved-seed formats. Cargo.lock stays byte-identical.
- Self-signed storage-node certificate acceptance and seed DER pin selection stay as before. TLS now additionally checks handshake signatures using the presented certificate; the advertised signature schemes match the installed provider.
- For an authenticated **valid** expiry map, an absent hash still means expired. An invalid/malformed reply is now an error, not evidence of expiry.
- No feature was removed. Helper files remain modules of `session-tui`; they never had executable entry points.
- Formatting changes outside explicitly described runtime/test changes are mechanical. Review with whitespace hidden to separate the logic changes from the formatting baseline.

## Protocol and TLS references

Expiry behavior was checked against Session Desktop commit `90473865400c8b5f6eae6a2aaca4db50bc75835e`:

- [getExpiriesRequest.ts](https://github.com/session-foundation/session-desktop/blob/90473865400c8b5f6eae6a2aaca4db50bc75835e/ts/session/apis/snode_api/getExpiriesRequest.ts): valid successful replies with absent hashes force expiry; network/invalid-result failures follow retry handling.
- [FetchMsgExpirySwarmJob.ts](https://github.com/session-foundation/session-desktop/blob/90473865400c8b5f6eae6a2aaca4db50bc75835e/ts/session/utils/job_runners/jobs/FetchMsgExpirySwarmJob.ts): persisted expiry reconciliation and applying the fetched deadline.
- [Official architecture](https://github.com/session-foundation/session-desktop/blob/90473865400c8b5f6eae6a2aaca4db50bc75835e/ARCHITECTURE.md): namespace authentication, polling, and expiry jobs. These references do not establish live interoperation by themselves.
- [rustls ServerCertVerifier](https://docs.rs/rustls/0.23.46/rustls/client/danger/trait.ServerCertVerifier.html): certificate acceptance and handshake signature verification are separate responsibilities. Pinning alone is insufficient if signature callbacks unconditionally succeed.

## State consistency audit

### Sync and database transactions

The existing `begin_batch`/`exec`/`end_batch` design records ignored SQL errors, rolls the entire batch back, and restores application state. Candidate per-node cursors are published only after commit. Attachment deletion is deferred until commit. Keep these rules together when extracting storage code.

New tests cover deferred **COMMIT** failure (not only statement failure), rollback of seen hashes and node cursors, retry after the failure is removed, and preservation of deferred attachment cleanup on rollback.

The old sender-key table migration is tested twice for idempotence, with an actual SQLCipher file closed and reopened. Two group authors sharing a timestamp remain distinct. The test also checks ciphertext database headers and rejection of a wrong key.

### Outbox and restart recovery

Text, sync copy, receipt, and expiry phases remain persisted and retried according to their existing budgets. A new disk-backed test closes/reopens between Text and SyncCopy phases and verifies no new Text phase appears. Existing tests cover exhausted budgets, `/retry`, blocked/read-only/expired work, completion-save failure, and atomic read-state/receipt enqueue.

Remaining limitation: attachment **uploads** are not durable outbox phases. Exit warns before interruption; this work does not turn them into resumable uploads.

### De-duplication, receipts, withdraw and expiry

New coverage applies a pending read receipt after a database restart, then replays the same message and checks that only one message and the maximum receipt state remain. Existing tests cover new-message timestamp uniqueness and group sender keys.

An explicit forged-unsend test checks that author mismatch cannot delete another author's message. Existing group deletion signature and scope tests remain. Expiry reply validation now distinguishes malformed data from a valid absent hash. Sending/expiry semantics and network signing inputs were not rewritten.

Open compatibility work: simultaneous device actions, group key rotation/revocation, asynchronous node replication, clock skew, and real storage-node expiry replies. Do not mark these proven by unit tests.

## Network, crypto and terminal boundaries

- Public endpoints use normal CA validation; seed requests use bundled exact DER pins; self-signed guard-node TLS still relies on the onion layer for destination authentication. A caller must not use the self-signed policy as generic public HTTPS authentication.
- Custom verifiers now check TLS 1.2 and TLS 1.3 signatures; provider-supported schemes are advertised. Pin rotation and the existing shared three-certificate pin set remain maintenance responsibilities.
- HTTP redirects remain disabled. The 32 MiB body budget is tested both with Content-Length and with chunked bodies. A stalled response body is now consistently `TransportError::Timeout`.
- AES-CBC attachment MAC/digest checks remain before decryption. Stream attachment code and algorithms are unchanged. Image limits remain bounded. Existing attachment/tampering tests continue to pass.
- The final terminal buffer strips C0/C1 control characters; clipboard OSC 52 payloads are base64, and desktop clipboard helpers receive arguments through `Command`, not a shell. The application's image protocol output is intentionally exempt within its image rectangle. Bidi/invisible Unicode visual spoofing and terminal-emulator bugs are not solved by ANSI filtering.
- QUIC is a stub and is not used by the TUI. No claim of functional QUIC support should be added without implementation and integration testing.

## Module plan: small extractions, not a rewrite

1. **Done: `session_tui_logic.rs`.** Command tokenization, duration parsing/formatting, retry delay calculation, and expiry reply parsing/validation. Pure functions have no account secrets, file or database access.
2. **Next: presentation-only logic.** Message layout keys, labels and formatting into a module behind existing `Message` inputs. Preserve terminal snapshot and scroll tests; do not move mutable UI state yet.
3. **Then: storage facade.** Move `LocalStore` with its batch/error aggregation and migration code as a single unit. Inject an explicit root/connection into tests to reduce global environment mutation. Keep all schema SQL and serialization bytes unchanged.
4. **Then: outbox coordinator.** Separate task selection/result application from network execution, preserving the exact phase/budget/idempotence rules. Test every transition, including interrupted saves and expired/deleted work.
5. **Then: sync reducer.** Stage database and view changes at an explicit boundary. Preserve candidate/committed cursors and rollback guarantees. Only after this can full-history snapshots be replaced by incremental state changes.
6. **Last: event-loop commands.** Extract commands after storage/outbox interfaces stabilize. Keep input, focus, scroll, image rendering and keyboard behavior covered. Avoid simultaneously restructuring group crypto or networking.

## CI policy

`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D clippy::correctness`, and `cargo test --locked --all-targets` run with Rust 1.93. Existing style/complexity warnings remain visible; there are no global lint suppressions or claims of zero warnings. Raise the lint gate gradually after specific cleanup batches.

A separate job runs `cargo audit` 0.22.2 on pushes/PRs/tags and weekly. Tag publication requires both quality/security and all three binary builds. Scheduled runs only audit dependencies. No advisory IDs are ignored. GitHub-hosted jobs themselves have not been run for this unpushed change.

## Dependency audit snapshot

RustSec database commit `7a40350e1b8ba5b656d909f88222a8059a83d88d` (2026-11-08): **0 vulnerability-category findings; 4 informational warnings**. A successful exit does not mean the dependency tree is free of risk.

| Package | Advisory | Classification / follow-up |
|---|---|---|
| lru 0.12.5 (via ratatui 0.29) | [RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002.html) | Unsound IterMut; patched upstream in >=0.16.3. Application exploitability not established. |
| lru 0.12.5 | [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) | Panic-safety use-after-free; patched in >=0.18.2. Special panicking-drop/unwind prerequisites; application exploitability not established. |
| paste 1.0.15 | [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | Unmaintained; remove through a tested ratatui/image dependency migration. |
| rustls-pemfile 2.2.0 | [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html) | Unmaintained; later migrate to rustls-pki-types PEM API. |

Do not suppress these warnings to make a stronger audit claim. Upgrade the UI dependency graph in a separate compatibility batch; forcing an incompatible transitive lru major or vendoring unreviewed crypto/network code is outside this low-risk change.

## Final verification

Final Linux/Debian checks using **rustc 1.93.0**:

- `cargo +1.93.0 fmt --all -- --check`: passed.
- `cargo +1.93.0 clippy --locked --all-targets -- -D clippy::correctness`: passed, with existing style/complexity warnings still visible.
- `cargo +1.93.0 test --locked --all-targets`: **420 core + 60 TUI = 480 passed**, zero failures.
- `cargo audit --json` (cargo-audit 0.22.2): successful exit, zero vulnerability-category findings, four informational warnings recorded above.
- The earlier stable Rust 1.99 batch tests also passed. The final MSRV build disabled debug symbols and incremental compilation only to limit disk use; it retained the normal test profile and debug assertions.
- Cargo.lock SHA-256 remained `a5c64f2b37524b4a4da4f9866a66a63f6181bdf182055531f8bf733195bdae60`.
- New TLS tests fail against the original implementation (2/2 expected failures), and pass after the fix.

Checks ran on Debian, not native macOS or Windows. The existing platform build jobs are retained and release now waits for the quality/security jobs. The updated GitHub-hosted workflow has not been triggered because these changes have not been pushed. Live Session interoperability, group key rotation, platform terminal/clipboard behavior and storage-node expiry propagation remain integration checks, not claims established by these results.

No production database schema, encryption settings, or lockfile dependency resolution changed.
