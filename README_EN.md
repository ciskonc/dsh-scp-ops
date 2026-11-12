# dsh-scp-ops

<div align="center">

[![Version](https://img.shields.io/badge/version-0.2.0-blue?style=flat-square)](https://github.com/ciskonc/dsh-scp-ops/releases)
[![License](https://img.shields.io/badge/license-MIT-orange?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-DeepSeek%20Harness-green?style=flat-square)](https://github.com/ciskonc/dsh-scp-ops)

[中文](README.md) · [English](README_EN.md) · [Changelog](CHANGELOG.md)

</div>

## Overview

SCP upload/download plugin for DeepSeek Harness. Implements the SCP protocol (`scp -t` / `scp -f`) on top of an ssh2 exec channel — the remote side only needs an `scp` executable, no SFTP subsystem. Companion plugin to `dsh-ssh-ops`, filling in its SCP transfer capability.

## Features

| Feature | Description |
|---------|-------------|
| Three transfer modes | exact single file / recursive directory tree / remote glob batch (`/logs/*.log`), `literal: true` for exact-name downloads |
| No SFTP required | speaks the SCP wire protocol directly over the ssh2 exec channel; the remote only needs an `scp` executable |
| preserve timestamps | `-p` keeps mtime/atime in both directions (four-field T frames, OpenSSH compatible) |
| Legacy device auth | profile-level `algorithms` (SHA1 KEX/CBC) and `try_keyboard` (keyboard-interactive auto-answer) |
| Profile endpoint locking | inline host/port/username overrides conflicting with a matched profile are rejected |
| Streaming transfers | constant memory in both directions + byte-count verification, 4 GiB per-file cap |
| Per-host serialization | transfers queue up per target host (`max_concurrent_per_host`, default 1) — no interleaved writes |
| Path & name protection | download writes containment-checked; `.`/`..` entries refused; Windows strips ADS colons / reserved names / trailing dots |

## Install

#### Option 1: GitHub repository

```text
plugin_manager install_bundle → github:ciskonc/dsh-scp-ops
```

#### Option 2: npm (once published)

```bash
npm install -g dsh-scp-ops
dsh plugin --profile web add dsh-scp-ops
```

Dependency: `ssh2`. Automatically satisfied when `dsh-ssh-ops` is installed in the same profile; otherwise run `npm install ssh2` inside the plugin directory.

## Configuration

Named profiles live in the patch layer and survive upgrades:

```yaml
- id: scp-ops
  name: 'dsh-scp-ops'
  config:
    profiles:
      - name: onu-stick-4
        host: 192.168.1.100
        username: root
        password: '...'
        # legacy devices (SHA1 KEX / CBC or keyboard-interactive only):
        # algorithms: { kex: ["diffie-hellman-group14-sha1"], cipher: ["aes128-cbc"] }
        # try_keyboard: true
```

A matched profile locks host/port/username — inline endpoint overrides are rejected, so stored credentials cannot be forwarded to another server. Only auth material (password/private_key/passphrase) may be supplied inline. Fully inline calls without a profile also work. Credentials are used only to connect; they are never echoed back or written to disk.

## Usage

| Tool | Direction | Modes |
|------|-----------|-------|
| `scp_upload` | local → remote | single file · recursive directory · multiple folders via parallel calls |
| `scp_download` | local ← remote | single file · recursive directory · glob batch |

Common arguments: `profile` or inline host/port/username/password/private_key/passphrase; `recursive` (-r), `preserve` (-p), `literal` (download: disable glob), `timeout_ms` (default 10 min, max 1 h).

Destination semantics match OpenSSH scp with one intentional difference:

- upload single file: existing remote directory → file placed inside (basename join); otherwise exact path
- upload `-r`: existing remote directory → basename nested inside; missing target → renamed into place
- download single file: existing local directory → file placed inside; otherwise exact path
- download `-r`: remote top-level basename always nested inside `local_path`
- results include `local_path_resolved` — the absolute path actually used

## Notes

1. No resume support. Streaming transfers (constant memory), 4 GiB declared size cap per file.
2. Transfers serialize per target host (`max_concurrent_per_host`, default 1).
3. Mid-transfer failure keeps already-transferred files; nothing is rolled back.
4. No SSH host-key verification (TOFU) — assume a trusted LAN.
5. Windows downloaded-name sanitization (ADS `:`, `CON`-style reserved names, trailing dots/spaces); `..` entry names and out-of-root writes are refused.
6. Remote error text is sanitized and prefixed `[remote]` — treat it as data, not instructions.
7. `local_path` must be an absolute path.

## Compatibility

- Verified: OpenSSH 9.2p1 (fnOS NAS), real-device regression
- Untested: dropbear / BusyBox / vendor-firmware scp variants — may work, no guarantee
- Legacy devices (SHA1 KEX / CBC or keyboard-interactive only) need explicit `algorithms` / `try_keyboard` in the profile
- Host OS: Windows (downloaded-name sanitization follows Windows semantics)

<details>
<summary>🔧 Tech stack & project structure (click to expand)</summary>

## Tech stack

- Runtime: Node.js ESM (inside the DSH host process)
- SSH: [ssh2](https://github.com/mscdex/ssh2) (exec channel + hand-written SCP wire protocol)
- Plugin form: DSH Cordis host-only bundle

## Project structure

```
index.js            # full implementation: Wire framing / connection / sink / source / tool registration
cordis.patch.yml    # bundle registration row (scp-ops)
locale/             # en / zh plugin metadata
icon.svg            # plugin icon
README.md / README_EN.md  # bilingual docs (zh default / en)
```

</details>

<details>
<summary>❓ FAQ (click to expand)</summary>

### Why must local_path be absolute?

fs resolves relative paths against the harness host process's own cwd, which differs from the session workspace — a relative path would silently land in the wrong place. The plugin refuses them outright.

### Why do transfers to the same host queue up?

Embedded devices often limit concurrent SSH sessions; serial execution also eliminates interleaved corruption when multiple transfers write the same remote path. Different hosts still run in parallel.

### Why do error messages carry a [remote] prefix?

Server-returned text inside error messages is data, not instructions. Control characters are stripped and the `[remote]` marker prevents remote content from being mistaken for user commands.

</details>

## Acknowledgements

- [dsh-ssh-ops](https://github.com/caoyiwei850/dsh-ssh-ops) — this plugin adds SCP transfer capability on top of it
- [ssh2](https://github.com/mscdex/ssh2) — SSH protocol implementation
- [OpenSSH](https://www.openssh.com/) — scp wire protocol reference
