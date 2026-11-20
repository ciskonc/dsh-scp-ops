# Changelog

## 0.2.2 — 2026-11-20

Security & robustness release after a three-perspective adversarial audit
(protocol/security, contract/resources, dynamic verification on an isolated
profile) plus an adversarial review of the fix plan itself.

- **Fixed (P0)**: download containment is now anchored at real paths —
  directories entering the stack are `realpath`-resolved after creation and
  re-checked against the root's real path, and file writes refuse to overwrite
  through an existing symlink/junction. A pre-planted junction inside the
  destination can no longer redirect writes outside the boundary.
- **Fixed**: transfer completion is reconciled against the declared byte
  counts — a finished single/recursive transfer or a cleanly-exited glob batch
  must leave the wire empty, otherwise a `byte-count mismatch` error is raised
  instead of silently accepting size lies (±1-byte ambiguity remains inherent
  to the SCP protocol; documented).
- **Fixed**: a signal-killed remote (`exit(null, signal)`) is no longer mapped
  to success — glob batches now fail with the signal in the message, and
  unknown exit outcomes report `truncated: true`.
- **Fixed**: a fatal (0x02) frame in a glob batch now forces `truncated: true`
  and is counted separately (`fatal error(s)` in the summary; warning entries
  carry a `fatal error` prefix). Legacy summary shape is preserved when only
  warnings are present.
- **Fixed**: a failed ssh2 resolution is no longer cached forever — the
  three-step resolution chain retries on the next call after the environment
  is repaired; the failure message now includes the `DSH_PROFILE_DIR` state.
- **Fixed**: `private_key` given as a file path is stat-checked before reading
  (regular file only, 64 KiB limit) — a huge path can no longer balloon memory.
- **Fixed**: `ws.end()` completion is raced against the abort signal — a hung
  end (AV hooks, file locks) can no longer wedge the call and the per-host
  gate forever. The Wire constructor now actually stores the abort signal,
  activating abort propagation in `writeAll`/`writeToWriteStream`/`drainToFile`.
- **Fixed**: `private_key` error messages no longer echo the first characters
  of the argument (length only).
- **Changed**: timeout errors name the current phase
  (`phase: draining "<file>" (consumed/declared bytes)`) for protocol-level
  diagnosis; `truncated` semantics widened to "completeness unconfirmed"
  (early close / signal kill / remote fatal); tool descriptions declare that
  parallel same-destination writes are a caller-side input conflict.
- **Docs**: npm/pnpm install notes for the lazy `ssh2` dependency,
  `timeout_ms` valid range, glob `--` separator and POSIX-remote-shell
  assumptions, and the symlink/size-ambiguity security model.

## 0.2.1 — 2026-11-17

- **Fixed**: ssh2 resolution no longer assumes the bundle's installed directory
  name. `loadSsh2()` now tries three anchors in order — the module's own ESM
  resolution chain, this file's real location via `import.meta.url` (survives
  symlinked, renamed or relocated installs), and `DSH_PROFILE_DIR` anchored at
  `package.json` — instead of the old hard-coded
  `node_modules/dsh-scp-ops/index.js` fallback path.
- **Changed**: package prepared for its first npm publication (`private`
  flag removed); profile-installed bundles remain unaffected.

## 0.2.0 — 2026-11-12

Security & robustness release after a 7-perspective adversarial code review
(security, protocol correctness, host contract, tool/agent experience,
performance, cross-device compatibility, plus a dedicated attacker with live
reproduction).

- **Fixed**: recursive-download path escape — dot segments (`..`) in wire entry
  names are refused and every write is containment-checked against the resolved
  destination root
- **Fixed**: profile rows now LOCK their endpoint — inline `host`/`port`/`username`
  overrides that conflict with a matched profile are rejected (credential
  forwarding guard); unknown-profile errors no longer enumerate profile names
- **Fixed**: private key material is never echoed in errors (redacted summary;
  PuTTY PPK detection with a re-export hint)
- **Added**: inbound wire buffer cap (64 MiB) and protocol line cap (8 KiB) with
  hard failure — a desyncing or runaway remote can no longer balloon host memory
- **Added**: per-file (4 GiB) and per-call (64 GiB) declared-size limits
- **Changed**: streaming transfers in both directions (constant memory) with
  byte-count verification
- **Added**: per-host transfer serialization (`config.max_concurrent_per_host`,
  default 1) — prevents interleaved writes to the same destination and plays
  nicely with single-session embedded devices
- **Fixed**: `preserve` (-p) interoperates with OpenSSH — four-field T frames
  are now sent and parsed (mtime microseconds included)
- **Added**: `literal` parameter for exact-name downloads containing glob
  characters (`*`, `?`, `[`)
- **Changed**: glob batches continue past per-file remote errors and report
  `truncated` plus sanitized `warnings` instead of aborting silently
- **Added**: legacy device hooks — `algorithms` override and `try_keyboard`
  with password auto-answer (keyboard-interactive)
- **Added**: downloaded-name neutralization on Windows (NTFS ADS colons,
  reserved device names, trailing dots/spaces)
- **Added**: `local_path` must be absolute (relative paths resolved against the
  harness process cwd were silently misplaced); results now include
  `local_path_resolved`
- **Fixed**: remote-originated text is control-character sanitized and
  delimited (`[remote]`) before reaching error messages; declared as data,
  not instructions
- **Changed**: non-atomic failure semantics are documented (already-transferred
  files remain; counts reported)
- **Docs**: bilingual README with an honest security model (including the
  missing host-key verification gap), destination-semantics reference, and
  legacy-device algorithm notes

## 0.1.1 — 2026-11-11

- Bilingual release README; packaging metadata alignment

## 0.1.0 — 2026-11-11

- Initial release: `scp_upload` / `scp_download` — exact single file, recursive
  directory, and remote glob batch modes
- Legacy SCP wire protocol (`scp -t` / `scp -f`) over ssh2 exec — works without
  a remote SFTP subsystem
- Password / private-key auth, named profiles, `recursive`, `preserve`,
  `timeout_ms`
