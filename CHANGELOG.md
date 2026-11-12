# Changelog

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
