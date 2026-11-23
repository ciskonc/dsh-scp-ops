# Changelog

## 0.4.0 — 2026-11-23

Connection pooling release (N6, the last major audit suggestion): transfers
to the same host|port|username reuse a pooled live SSH connection instead of
paying a fresh handshake per call.

- **Added (N6)**: per-target connection pool — pooled connections are
  keepalive-kept, health-checked on take-over (a trivial exec replaces a
  dead or MaxSessions-capped connection with a fresh one), idle-closed after
  60 seconds, and never return to the pool after a failed or aborted
  transfer. Results report `pooled_connection`.
- **Fixed (R5)**: UNC glob patterns (`\\server\share\*.txt`) pass the
  whitelist; the `..` segment check now covers both separators.
- **Docs (R2/R3)**: `file_names_total` schema wording clarified (uploads cap
  name collection at 100 — `files` is the true count); `file_names`
  described as paths relative to the transfer root (top-level basename
  included).
- **Docs**: connection-pool semantics documented (pooled connections are
  pre-authenticated — a later call with a wrong password still succeeds on
  the pooled connection).

## 0.3.1 — 2026-11-23

Adversarial-review fixes for 0.3.0 plus the definitive retest findings
(out-of-process harness against the real Windows remote: all three legacy
suspicions from the first audit round closed as artifacts of the old quoting
defect — downloads work, non-ASCII names round-trip byte-perfect, no
intermittent failures).

- **Fixed (review M1)**: remote directory listings and the attempted command
  in error messages are sanitized through cleanRemoteText — the "sanitized"
  claim now matches the code.
- **Fixed (review M2)**: Windows glob enumeration skips names containing `%`
  or control characters before they are forwarded into a cmd command string.
- **Fixed (P1/N2)**: Windows glob matching is case-insensitive (NTFS
  semantics) — `fin_*.TXT` now matches fin_1.txt.
- **Fixed (P2/N1)**: Windows glob patterns allow spaces — the pattern is
  matched locally against a remote listing, never executed by a shell; the
  whitelist stays strict for POSIX remotes.
- **Fixed (P3/N7)**: a rejected transfer now reads as a failure
  ("remote rejected the transfer (fatal/error)") instead of a headline
  saying "warning".
- **Added (P4/N3)**: uploads report `file_names` too (paths relative to the
  transfer root), and results carry `remote_path_requested` — the original
  input before directory-shape rewriting.
- **Added (P5/N5)**: when reused cached credentials fail authentication, the
  error explains the cache may be stale and how to refresh.
- **Added (N8/N9/N10)**: `file_names_total`, Windows glob `glob_scanned` /
  `glob_matched` stats, and `remote_landing` in the remote's own separator
  style.
- **Fixed (review S-b/S-c)**: unbalanced `[` in glob patterns fails with a
  readable message instead of a raw RegExp error; glob length (256) and
  wildcard count (8) bounded.
- **Fixed (review S-d)**: the credential-reuse cache clears when the plugin
  is disposed; process-lifetime scope documented.
- **Fixed (review S-e)**: host-originated abort reasons are no longer
  message-enriched (they are shared Error instances).
- **Fixed (review S-a)**: empty-directory-tree messages distinguish "created
  on the remote" (upload) from "created locally" (download).
- **Docs (M3/P6/S-f)**: compatibility table lists 0.2.5/0.3.0/0.3.1; the
  non-ASCII name guidance now recommends PowerShell UTF-8 listing (the
  plugin's own method) over SFTP; Windows glob notes cover spaces,
  case-insensitivity and files-only matching.

## 0.3.0 — 2026-11-23

Usability release: every suggestion from the two real-world audit rounds
(27 items collected) triaged and implemented, reviewed, and verified on an
in-process ssh2 server harness (11/11 scenarios).

- **Added (S1/S5/S11)**: remote errors now carry actionable hints — the
  plugin compares the echoed path for quote残留-style mangling, translates
  ENOENT into "parent directory may not exist — the plugin never creates
  remote directories", and explains `ambiguous target`; failures name the
  remote shell mode and the exact attempted command.
- **Added (S2)**: results echo `plugin_version` (`dsh-scp-ops@x.y.z`) so
  stale-host mismatches are self-evident.
- **Added (S3)**: glob batches against Windows remotes enumerate the remote
  directory over the same connection (PowerShell UTF-8 listing), filter with
  a glob→regex translation, and download the matched files exactly — cmd.exe
  has no shell glob to rely on.
- **Added (S4)**: ENOENT-style download failures attach a sanitized listing
  of the remote directory, so wrong names are self-evident.
- **Added (S7)**: recursive uploads report `remote_landing` — the predicted
  remote landing directory (target/basename when the target exists, the
  target itself when it does not), checked live over the connection.
- **Added (S8)**: single-file uploads aimed at a directory-shaped
  destination (`dir/`) automatically append the local basename.
- **Added (S9)**: omitting auth material reuses the last successful
  connection's credentials for the exact same host|port|username
  (`credentials_reused: true`); credentials never travel to another target.
- **Added (S10)**: remote console text decodes as GBK when UTF-8 fails
  (Node full-ICU), fixing mojibake in Windows remote error messages.
- **Added (S11)**: results and summaries declare the quoting mode
  (`remote_shell_mode`, `[win quoting]`).
- **Added (S13)**: empty directory tree uploads report "empty directory tree
  created" instead of a bare count.
- **Added (S14)**: downloads report `file_names` (sanitized, first 100) in
  transfer order.
- **Changed (S12)**: descriptions now state the tool-selection rule —
  remotes with SFTP prefer sftp_*; scp_* is for remotes without one.
- **Docs (S16)**: troubleshooting note for manual SCP protocol testing on
  Windows (file redirection; pipes never terminate under cmd).

## 0.2.5 — 2026-11-23

Patch release from the second retest round (three MiniMax-M3.1-Flash agents;
the first round proved the live host had not reloaded 0.2.4, so one agent
built an out-of-process harness driving the 0.2.4 source directly against the
real Windows remote — its findings feed this release).

- **Fixed (security)**: on Windows remotes every remote path is now
  double-quoted unconditionally (with `"` escaped as `""`) — the previous
  quote-only-if-space heuristic left paths containing cmd metacharacters
  (`& | ^ % < > ( )`) bare, where `&` acts as a command separator. cmd strips
  the surrounding quotes and treats the quoted content as inert.
- **Docs**: recursive-upload landing wording corrected (a not-yet-existing
  target is created as-is at the requested path — no extra basename level;
  verified against real transfers); download landing rules (into-existing-
  directory vs exact path, asymmetric with uploads by design) moved into both
  READMEs; empty-directory-tree uploads documented (creates all empty dirs,
  result reports files=0/dirs=N).

## 0.2.4 — 2026-11-23

Windows-remote adaptation release, driven by a three-agent real-world usage
audit (MiniMax-M3.1-Flash) against a Windows OpenSSH 9.5 target.

- **Fixed (P0)**: `ssh2` resolution now walks UP from this file's real
  location looking for any hoisted `node_modules/ssh2` (hop 2b, 8 levels) —
  Junction/link installs previously failed every hop because the host does
  not inject `DSH_PROFILE_DIR` into plugin contexts. The failure message now
  lists every anchor tried with its failure reason, instead of blaming one
  env var.
- **Fixed (P0)**: remote paths are quoted according to the REMOTE shell.
  Windows OpenSSH's default cmd.exe does not strip single quotes, so every
  transfer failed with a misleading ENOENT; drive-letter/UNC paths are now
  double-quoted (or passed bare) with `"` escaped as `""`, and POSIX paths
  keep the proven single-quote form. A `remote_shell` argument
  (`posix`/`win`) pins ambiguous cases; detection defaults to the path shape.
- **Fixed**: `literal: true` downloads of names containing glob characters
  now escape the metacharacters in transit on POSIX remotes — the remote
  scp's own internal glob() could never match them before.
- **Fixed**: glob batch downloads accept Windows drive-letter prefixes
  (`C:/logs/*.txt`) — the whitelist previously rejected `:`, making glob
  unusable against Windows remotes.
- **Changed**: a successful upload summary now shows the remote destination
  (`remote path: ...`) instead of the local source path; download summaries
  keep `saved to ...`.
- **Docs**: new "When the remote is Windows" section (quoting, drive paths,
  literal escaping, non-ASCII names, negotiation overhead, parent-directory
  and hidden-file caveats); compatibility table records the Windows
  regression.

## 0.2.3 — 2026-11-20

Full hardening sweep: every remaining audit finding addressed (P2 batch),
adversarially reviewed and verified on an in-process ssh2 server harness.

- **Fixed**: a glob batch closing cleanly with zero files now fails with a
  "pattern matched nothing (or the remote aborted)" message instead of a raw
  transport error.
- **Fixed**: a download that transfers nothing now says `NOTHING transferred`
  in the result message (previously indistinguishable from a plain success).
- **Fixed**: remote-supplied text sanitization now also strips zero-width,
  bidirectional-override (RTLO) and word-joiner characters, and folds
  repeated spaces — invisible instruction carriers can no longer ride along
  in error messages.
- **Fixed**: downloaded entry names neutralize CR and invisible/bidirectional
  characters (replaced with `_` during name sanitization).
- **Fixed**: `max_concurrent_per_host` validation rejects NaN (previously it
  silently disabled the concurrency limit).
- **Fixed**: the second tool registration failure now rolls back the first
  registration instead of leaking it.
- **Changed**: downloads are additionally serialized per local destination
  path (a per-key mutex inside the per-host gate), so parallel calls from
  different hosts writing the same `local_path` can no longer interleave
  writes; uploads remain unlocked (their local side is read-only).
- **Changed**: idle per-host queue entries are removed after the last
  transfer; the wire buffer is released immediately on protocol failure.

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
