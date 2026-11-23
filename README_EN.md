<div align="center">

# dsh-scp-ops

**An SCP upload/download plugin for DeepSeek Harness that implements the SCP wire protocol on exec channels, with no SFTP subsystem required.**

scp_upload and scp_download cover single files, recursive directories and glob batches; named profiles target legacy devices without an SFTP subsystem.

<p align="center">
  <a href="LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/ciskonc/dsh-scp-ops"></a>
  <a href="https://github.com/ciskonc/dsh-scp-ops"><img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/ciskonc/dsh-scp-ops"></a>
  <a href="https://github.com/ciskonc/dsh-scp-ops/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/ciskonc/dsh-scp-ops"></a>
  <a href="https://github.com/ciskonc/dsh-scp-ops/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/ciskonc/dsh-scp-ops"></a>
</p>

English | [中文](README.md)

</div>

---

## Introduction

dsh-scp-ops is a DeepSeek Harness plugin for SCP upload and download, the companion plugin of dsh-ssh-ops. It implements the SCP wire protocol (scp -t / scp -f) over the ssh2 exec channel, so any remote host with an scp executable works, with no SFTP subsystem required.

Out of the box, file transfer between the DSH host and remote machines has no tool surface: scp runs as a hand-typed command in a terminal session, and authentication, path handling and post-transfer checks are left to the person at the terminal. Hosts that ship no SFTP subsystem — common in embedded firmware — leave the ssh2 library without a ready-made channel for this.

Installing this plugin gives the session two tools: scp_upload and scp_download. Single files, recursive directories and glob batches transfer directly, and preserve keeps mtime/atime on both sides. Legacy devices connect through profile-level algorithms with automatic keyboard-interactive responses.

## Installation

<details>
<summary>Install from npm</summary>

```sh
dsh plugin --profile web add dsh-scp-ops
```

ssh2 is resolved lazily and is not listed in dependencies: if dsh-ssh-ops is already installed in the same profile, the dependency is satisfied; otherwise add it manually:

```sh
dsh plugin --profile <name> add ssh2
```

A manual `pnpm add ssh2` can fail with `ERR_PNPM_IGNORED_BUILDS` and exit code 1 while the package is in fact installed and usable; the signal is misleading.

</details>

<details>
<summary>Build from source</summary>

```sh
git clone https://github.com/ciskonc/dsh-scp-ops.git
```

The ssh2 dependency applies as above.

</details>

## Usage

<details>
<summary>scp_upload</summary>

Uploads files from the local machine to the remote host. Single files and recursive directories (`recursive`). Transfers to the same host queue up by default (`max_concurrent_per_host`, default 1); raise that value to run several directories of one host in parallel. Two uploads aimed at the same remote destination are a caller-side conflict with an undefined result.

Landing semantics match OpenSSH scp: for a single file, a remote destination that is an existing directory receives the file inside itself, otherwise the exact path is written. With `recursive`, an existing remote destination nests the local basename inside it, while a destination that does not exist yet is created as-is at the requested path with the files directly inside (no extra basename level). Results carry `local_path_resolved` and `remote_path_resolved` (an echo of the request path sent to the remote).

Transfers stream at constant memory in both directions and are verified by byte count.

</details>

<details>
<summary>scp_download</summary>

Downloads files from the remote host to the local machine. Single files, recursive directories and glob batches (for example `/logs/*.log`); with `literal: true`, glob characters are treated literally.

With `recursive`, the remote top-level basename always nests inside local_path (whether or not that path existed before — deliberately asymmetric with uploads: it avoids clobbering an existing local directory). For single-file downloads, a `local_path` that is an existing directory receives the file inside it; an exact file path is written as-is (missing parent directories are created). Results carry `local_path_resolved`.

Download writes pass a containment check and refuse `./` and `..` entries; a symlink inside the target directory that points outside it is refused rather than followed, and a same-named link is never overwritten. On a Windows plugin host, file names are sanitized with Windows semantics (ADS colons, reserved names and trailing dots stripped). The size the remote declares is checked against a 4 GiB limit, and a directory tree is capped at 20000 entries.

</details>

<details>
<summary>Named profiles</summary>

Named profiles live in the `config.profiles` list of the patch layer:

```yaml
- id: scp-ops
  name: 'dsh-scp-ops'
  config:
    profiles:
      - name: legacy-nas
        host: 192.168.1.10
        username: admin
        password: 'app-password'
        algorithms:
          kex: [diffie-hellman-group14-sha1]
          cipher: [aes128-cbc]
        try_keyboard: true
```

A matched profile locks the endpoint: inline `host`/`port`/`username` values that conflict with the profile are rejected, and only authentication material (`password`/`private_key`/`passphrase`) may be supplied inline.

Legacy devices connect through profile-level `algorithms` (SHA1 KEX, CBC ciphers and the like) and `try_keyboard`, which answers keyboard-interactive prompts automatically.

</details>

<details>
<summary>Common parameters</summary>

| Parameter | Notes |
|---|---|
| `profile` or inline `host`/`port`/`username`/`password`/`private_key`/`passphrase` | Connection source; a matched profile locks the endpoint, see above |
| `recursive` | Recursive directory transfer (scp -r) |
| `preserve` | Keeps mtime/atime in both directions (scp -p; T frames round-trip in the four-field OpenSSH format) |
| `literal` | Download only: glob characters are treated literally (on POSIX remotes the glob metacharacters are escaped in transit, bypassing the remote scp's own glob) |
| `remote_shell` | `posix` / `win`: how remote paths are quoted; auto-detected from the path shape by default (drive-letter/UNC paths are treated as Windows). Set explicitly for Windows remotes with relative paths |
| `timeout_ms` | Range [5000, 3600000], default 10 minutes; values below 5000 are raised to 5000, values above 3600000 are clamped |
| `algorithms` | Inline SSH algorithm overrides (kex, cipher) for legacy devices; usually set in the profile instead |
| `try_keyboard` | Answer keyboard-interactive authentication prompts automatically; usually set in the profile instead |

</details>

## Compatibility

| Plugin version | DSH version tested | Notes |
|---|---|---|
| 0.3.1 (2026-11-23) | ≥ 0.2.0-rc.1 (tested on 0.2.2-rc.5) | Current release. Windows glob matching is case-insensitive and allows spaces (patterns are matched locally against a remote listing, never executed); enumerated names are filtered for cmd metacharacters; error listings and attempted commands are sanitized; the credential-reuse cache clears on plugin dispose |
| 0.3.0 (2026-11-23) | ≥ 0.2.0-rc.1 | Real-world audit suggestions S1-S17: actionable error hints (echoed-quote detection, ENOENT translation, remote directory listings, attempted command), plugin_version/remote_shell_mode/credentials_reused/remote_landing/file_names fields, Windows glob enumeration via PowerShell UTF-8 listing, per-target credential reuse, GBK fallback decoding |
| 0.2.5 (2026-11-23) | ≥ 0.2.0-rc.1 | Windows remote paths are always double-quoted (cmd metacharacter injection surface); README landing-semantics corrections |
| 0.2.4 (2026-11-23) | ≥ 0.2.0-rc.1 | Remote-shell quoting adaptation (Windows cmd remotes work out of the box), literal glob escaping, drive-letter glob prefix, upload summary shows the remote destination, and a fourth ssh2 resolution hop |
| 0.2.3 (2026-11-20) | ≥ 0.2.0-rc.1 | Downloads from different hosts into the same `local_path` are serialized per target path |
| 0.2.0 – 0.2.2 | ≥ 0.2.0-rc.1 | Earlier line. The per-target-path serialization above arrived in 0.2.3 |

Remote compatibility:

| Remote host | Status |
|---|---|
| OpenSSH 9.2p1 (fnOS NAS) | Verified on real-hardware regression |
| **Windows OpenSSH 9.5 (cmd.exe)** | **Verified on real-machine regression (since 0.2.4)**: drive-letter paths / spaced paths / non-ASCII names / recursive / glob — see "When the remote is Windows" below |
| dropbear / BusyBox / vendor firmware | Not verified |

### When the remote is Windows

Behaviour and caveats when the remote is Windows OpenSSH (default shell cmd.exe) — all since 0.2.4:

- **Path quoting adapts automatically**: drive-letter/UNC paths are quoted with Windows semantics — double-quoted when they contain a space or an embedded double quote (`"` escaped as `""`), passed bare otherwise; POSIX paths keep single quotes. Use `remote_shell: "win"` to disambiguate a Windows remote with relative paths.
- **Drive-letter paths work**: `C:/Users/...` works out of the box; glob batches accept a drive prefix (e.g. `C:/logs/*.txt`).
- **literal downloads of names with `[]`**: on POSIX remotes the glob metacharacters are escaped in transit (bypassing the remote scp's own glob parsing); on Windows remotes the path is sent as-is (its scp argv has no glob layer).
- **Non-ASCII file names**: the SCP wire protocol carries names as raw bytes; a remote that decodes them in its legacy ANSI code page may display mojibake in its console. The actual byte-level names can be read directly on the remote with PowerShell (`[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-ChildItem -Name`) — the plugin's failure listings use exactly this since 0.3.1, so SFTP is no longer needed for verification. Content itself is unaffected.
- **Negotiation overhead**: every transfer carries a fixed ~2-15 s SSH+scp negotiation cost regardless of file size; plan batches of small files accordingly.
- **Uploads do not create missing parent directories**: uploading into a deep remote directory that does not exist fails — create it first.
- **Manual protocol debugging**: when hand-testing the SCP protocol against a Windows remote, redirect commands from a file (`scp -t path < cmds.txt`); a pipe (`echo … | scp -t`) never terminates under cmd.
- **Recursive downloads do not skip hidden files**: `.git` and friends are pulled in full — mind the tree size.

The plugin is a host-only bundle: it registers host tools and patch config, with no client-side components.

## Known limitations

- No resume of interrupted transfers.
- Transfers to the same host run serially (max_concurrent_per_host defaults to 1).
- On a mid-transfer failure, files already transferred are kept; nothing is rolled back.
- No SSH host key verification (trust on first use).
- The SCP protocol has no length prefix, so a malicious remote can declare a wrong size and leave a ±1 byte ambiguity; mitigated by reconciling trailing bytes locally and by timeouts that show where the transfer stalled.
- Glob downloads depend on the remote scp accepting the `--` separator.
- local_path must be an absolute path.
- A download may carry at most 4 GiB per file, and one directory tree at most 20000 entries; a remote that declares more is refused.
- Since 0.2.3, parallel downloads from different hosts into the same local_path are automatically serialized per target path.
- Since 0.2.4, a successful upload summary shows the remote destination (`remote path: ...`) while a download summary shows where files landed locally (`saved to ...`) — uploads no longer print the local source path.
- Uploading a tree of empty directories creates all of them on the remote (result: files=0, dirs=N) — `files=0` does not mean "nothing was transferred".
- Since 0.3.1, omitted credentials reuse the last successful connection's auth material for the same host|port|username in this process (`credentials_reused: true`); the cache clears on plugin dispose or host restart — after a remote password change, pass the password explicitly.
- **Connection pool (since 0.4.0)**: transfers to the same host|port|username reuse a pooled live connection (auto-closed after 60 s idle; a lightweight health check guards each pool take-over). Semantics note: authentication happened when the pooled connection was established — later calls with a WRONG password still succeed on the pooled connection. Verify credentials on a fresh target or after the pool idles out; failed/aborted transfers never return their connection to the pool.

## Credits

- dsh-ssh-ops (caoyiwei850), the companion plugin.
- ssh2 (mscdex), the library underneath the exec channel and the SCP wire protocol.

## License

Released under the [MIT](LICENSE) license.
