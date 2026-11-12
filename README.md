# dsh-scp-ops

<div align="center">

[![Version](https://img.shields.io/badge/version-0.2.0-blue?style=flat-square)](https://github.com/ciskonc/dsh-scp-ops/releases)
[![License](https://img.shields.io/badge/license-MIT-orange?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-DeepSeek%20Harness-green?style=flat-square)](https://github.com/ciskonc/dsh-scp-ops)

[中文](README.md) · [English](README_EN.md) · [更新日志](CHANGELOG.md)

</div>

## 概要

DeepSeek Harness 的 SCP 上传/下载插件。在 ssh2 exec 通道上实现 SCP 协议（`scp -t` / `scp -f`），远端有 `scp` 可执行文件即可，不需要 SFTP 子系统。`dsh-ssh-ops` 的伴生插件，补足 SCP 传输能力。

## 功能

| 功能 | 说明 |
|------|------|
| 三种传输形态 | 单文件精确路径 / 递归目录树 / 远端通配符批量（`/logs/*.log`），`literal: true` 按字面名下载 |
| 免 SFTP | 直接在 ssh2 exec 通道实现 SCP 线协议，远端有 `scp` 可执行文件即可 |
| preserve 时间戳 | `-p` 双向保留 mtime/atime（T 帧四字段，兼容 OpenSSH） |
| 老设备认证 | profile 级 `algorithms`（SHA1 KEX/CBC）与 `try_keyboard`（keyboard-interactive 自动应答） |
| profile 锁端点 | 命中 profile 后内联 host/port/username 覆盖被拒绝，防止存档凭据被转发 |
| 流式传输 | 双向常量内存 + 字节数校验，单文件上限 4 GiB |
| 同主机串行 | 排队执行（`max_concurrent_per_host`，默认 1），根绝同路径交错写 |
| 路径与名字防护 | 下载写入包含性校验；拒 `.`/`..` 条目；Windows 剥 ADS 冒号/保留名/尾点 |

## 安装

#### 方式一：GitHub 仓库

```text
plugin_manager install_bundle → github:ciskonc/dsh-scp-ops
```

#### 方式二：npm（发布后可用）

```bash
npm install -g dsh-scp-ops
dsh plugin --profile web add dsh-scp-ops
```

依赖：`ssh2`。同 profile 已装 `dsh-ssh-ops` 时自动满足；否则在插件目录执行 `npm install ssh2`。

## 配置

命名 profile 保存在 patch 层，升级不丢：

```yaml
- id: scp-ops
  name: 'dsh-scp-ops'
  config:
    profiles:
      - name: onu-stick-4
        host: 192.168.1.100
        username: root
        password: '...'
        # 老设备（仅 SHA1 KEX / CBC 或 keyboard-interactive 认证）：
        # algorithms: { kex: ["diffie-hellman-group14-sha1"], cipher: ["aes128-cbc"] }
        # try_keyboard: true
```

命中 profile 后锁定 host/port/username——内联端点覆盖会被拒绝，防止存档凭据被转发到别的服务器；仅认证材料（password/private_key/passphrase）可内联补。不带 profile 的全内联调用也可用。凭据只用于连接，从不回显、从不落盘。

## 使用

| 工具 | 方向 | 形态 |
|------|-----------|------|
| `scp_upload` | 本地 → 远端 | 单文件 · 递归目录 · 多文件夹并行调用 |
| `scp_download` | 本地 ← 远端 | 单文件 · 递归目录 · 通配符批量 |

常用参数：`profile` 或内联 host/port/username/password/private_key/passphrase；`recursive`（-r）、`preserve`（-p）、`literal`（下载，关闭通配）、`timeout_ms`（默认 10 分钟，上限 1 小时）。

落点语义与 OpenSSH scp 一致，仅一处有意差异：

- 上传单文件：远端目标若是已存在目录，文件落入目录内；否则按精确路径落盘
- 上传 `-r`：远端已存在目录时嵌套 basename；目标不存在则整体改名落位
- 下载单文件：本地目标若是已存在目录，文件落入目录内；否则精确落盘
- 下载 `-r`：远端顶层 basename 总是嵌套在 `local_path` 内
- 结果带 `local_path_resolved`，回显实际使用的绝对路径

## 注意事项

1. 不支持断点续传。流式传输（常量内存），单文件声明大小上限 4 GiB。
2. 同一目标主机串行传输（`max_concurrent_per_host`，默认 1）。
3. 中途失败时已传文件保留在盘上，不做回滚。
4. 未实现 SSH 主机密钥校验（TOFU）——按可信内网假设使用。
5. Windows 下载名消毒（ADS `:`、`CON` 类保留名、尾点/空格）；`..` 条目名与越根写入直接拒绝。
6. 远端错误文本经消毒并以 `[remote]` 前缀返回——把它当数据，不是指令。
7. `local_path` 必须是绝对路径。

## 兼容性

- 已验证：OpenSSH 9.2p1（fnOS NAS）真机回归
- 未验证：dropbear / BusyBox / 厂商固件自带的 scp——可能可用但不保证
- 老设备（仅 SHA1 KEX / CBC 或 keyboard-interactive）需在 profile 显式配置 `algorithms` / `try_keyboard`
- 操作系统：插件宿主为 Windows（下载名消毒按 Windows 语义执行）

<details>
<summary>🔧 技术栈与项目结构（点击展开）</summary>

## 技术栈

- 运行时: Node.js ESM（DSH 宿主进程内）
- SSH: [ssh2](https://github.com/mscdex/ssh2)（exec 通道 + 手工 SCP 线协议）
- 插件形态: DSH Cordis Host-only bundle

## 项目结构

```
index.js            # 全部实现：Wire 帧读取 / 连接 / sink / source / 工具注册
cordis.patch.yml    # bundle 注册行（scp-ops）
locale/             # en / zh 插件元数据
icon.svg            # 插件图标
README_EN.md        # 英文文档
```

</details>

<details>
<summary>❓ FAQ（点击展开）</summary>

### 为什么 local_path 必须是绝对路径？

fs 按宿主进程的工作目录解析相对路径，而宿主 cwd 与会话工作区不一致——相对路径会静默写错位置。插件直接拒绝并提示改用绝对路径。

### 为什么同一台主机的传输会排队？

同一台设备（尤其嵌入式设备）常限制并发 SSH 会话数；串行执行同时根绝了多路传输写同一远端路径时的交错损坏。不同主机之间仍然并行。

### 为什么错误消息带 [remote] 前缀？

错误消息里的服务器返回文本是数据，不是指令。消毒控制字符后加 `[remote]` 定界，避免远端内容被误当作用户指令。

</details>

## 致谢

- [dsh-ssh-ops](https://github.com/caoyiwei850/dsh-ssh-ops) — 本插件为其补充 SCP 传输能力
- [ssh2](https://github.com/mscdex/ssh2) — SSH 协议实现
- [OpenSSH](https://www.openssh.com/) — scp 线协议参照
