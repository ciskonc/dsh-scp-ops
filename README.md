<div align="center">

# dsh-scp-ops

**一个基于 exec 通道线协议的 SCP 上传/下载插件，远端无需 SFTP 子系统。**

scp_upload 与 scp_download 覆盖单文件、递归目录与通配符批量传输，命名 profile 面向不带 SFTP 子系统的老设备。

<p align="center">
  <a href="LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/ciskonc/dsh-scp-ops"></a>
  <a href="https://github.com/ciskonc/dsh-scp-ops"><img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/ciskonc/dsh-scp-ops"></a>
  <a href="https://github.com/ciskonc/dsh-scp-ops/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/ciskonc/dsh-scp-ops"></a>
  <a href="https://github.com/ciskonc/dsh-scp-ops/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/ciskonc/dsh-scp-ops"></a>
</p>

[English](README_EN.md) | 中文

</div>

---

## Introduction

dsh-scp-ops 是 DeepSeek Harness 的 SCP 上传/下载插件，dsh-ssh-ops 的伴生插件。它在 ssh2 的 exec 通道上实现 SCP 线协议（scp -t / scp -f），远端只要有 scp 可执行文件即可工作，不需要 SFTP 子系统。

原来在 DSH 里往远端传文件，只能在终端里手敲 scp：认证、路径处理与传完后的校验都得自己在终端里弄，插件层面没有入口；不带 SFTP 子系统的主机（嵌入式固件的常见形态）则让 ssh2 库没有现成通道可用。

装好这个插件后，会话里多出 scp_upload 与 scp_download 两个工具。单文件、递归目录与通配符批量传输直接下发，preserve 在双向保留 mtime/atime。老设备通过 profile 级 algorithms 与 keyboard-interactive 自动应答接入。

## Installation

<details>
<summary>从 npm 安装</summary>

```sh
dsh plugin --profile web add dsh-scp-ops
```

ssh2 为惰性解析的依赖，不进 dependencies：同一 profile 里已有 dsh-ssh-ops 时自动满足；否则手动添加：

```sh
dsh plugin --profile <name> add ssh2
```

用 pnpm 手动安装 ssh2 时，可能报 `ERR_PNPM_IGNORED_BUILDS` 且 exit code 为 1；此时包实际已装好可用，该信号有误导性。

</details>

<details>
<summary>从源码构建</summary>

```sh
git clone https://github.com/ciskonc/dsh-scp-ops.git
```

ssh2 依赖的处理同上。

</details>

## Usage

<details>
<summary>scp_upload</summary>

上传，本地到远端。支持单文件与递归目录（`recursive`）。同一台主机的传输默认排队（`max_concurrent_per_host`，默认 1）；调高该值后，同一主机的不同目录可以并行。两次上传指向同一个远端目标属调用方输入冲突，结果未定义。

落点语义与 OpenSSH scp 一致：上传单文件时，远端目标若为已存在目录，文件落入该目录内；否则按精确路径写入。`recursive` 上传时，远端目标已存在则本地 basename 嵌套其下；目标尚不存在则按请求路径原样建成该目录，文件直接落入其中（无额外 basename 层）。结果带 `local_path_resolved` 与 `remote_path_resolved`（后者为发送给远端的请求路径回显）。

传输流式进行，双向常量内存，并做字节数校验。

</details>

<details>
<summary>scp_download</summary>

下载，远端到本地。支持单文件、递归目录与通配符批量（如 `/logs/*.log`）；`literal: true` 时通配符字符按字面名处理。

`recursive` 下载时，远端顶层 basename 总是嵌套在 local_path 之内（无论该路径原先是否存在——与上传方向不对称，属刻意设计：避免覆盖既有目录）。下载单文件时，`local_path` 若为已存在目录，文件落入目录内；若为精确文件路径则按该路径写盘（缺失的父目录自动创建）。结果带 `local_path_resolved`。

下载写入做包含性校验，拒绝 `./` 与 `..` 条目；目标目录内的符号链接若指向该目录之外则拒绝进入，同名链接也不覆盖。插件宿主为 Windows 时，文件名按 Windows 语义消毒（剥离 ADS 冒号、保留名与尾点）。远端声明的文件大小按 4 GiB 上限校验，一棵目录树的条目数上限为 20000。

</details>

<details>
<summary>命名 profile</summary>

命名 profile 定义在 patch 层的 `config.profiles` 列表：

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

命中 profile 后端点被锁定：内联的 `host`/`port`/`username` 与 profile 冲突时会被拒绝，仅认证材料（`password`/`private_key`/`passphrase`）可内联补充。

老设备兼容走 profile 级 `algorithms`（SHA1 KEX、CBC 一类）与 `try_keyboard`（keyboard-interactive 自动应答）。

</details>

<details>
<summary>通用参数</summary>

| 参数 | 说明 |
|---|---|
| `profile` 或内联 `host`/`port`/`username`/`password`/`private_key`/`passphrase` | 连接来源；命中 profile 后端点锁定，见上节 |
| `recursive` | 递归目录传输（scp -r） |
| `preserve` | 双向保留 mtime/atime（scp -p；T 帧按 OpenSSH 四字段格式往返） |
| `literal` | 仅下载：通配符按字面名处理（POSIX 远端对 glob 元字符转义后下发，绕过远端 scp 自身的 glob） |
| `remote_shell` | `posix` / `win`：远端 shell 引用方式；默认按远端路径形态自动判断（盘符/UNC 路径按 Windows 处理），Windows 远端相对路径建议显式指定 |
| `timeout_ms` | 取值区间 [5000, 3600000]，默认 10 分钟；低于 5000 抬升到 5000，高于 3600000 钳到上限 |
| `algorithms` | 内联覆盖 SSH 算法（kex、cipher），供老设备使用；一般写在 profile 里 |
| `try_keyboard` | 自动应答 keyboard-interactive 认证提示；一般写在 profile 里 |

</details>

## Compatibility

| 插件版本 | 实测 DSH | 说明 |
|---|---|---|
| 0.3.1 (2026-11-23) | ≥ 0.2.0-rc.1（实测 0.2.2-rc.5） | 当前版本。win glob 大小写不敏感 + 允许空格（图案本地匹配，不进 shell）+ 枚举名安全过滤；错误清单/命令净化；凭据复用缓存随插件停用清空 |
| 0.3.0 (2026-11-23) | ≥ 0.2.0-rc.1 | 实战建议 S1-S17 落地：行动提示（错误附 hints/attempted 命令/远端清单）、plugin_version/remote_shell_mode/credentials_reused/remote_landing/file_names 字段、Windows glob 枚举实现、凭据按精确目标复用、GBK 解码 |
| 0.2.5 (2026-11-23) | ≥ 0.2.0-rc.1 | Windows 远端路径一律双引号（cmd 元字符注入面）；README 落点语义修正 |
| 0.2.4 (2026-11-23) | ≥ 0.2.0-rc.1 | 远端 shell 引用适配（Windows cmd 远端开箱即用）、literal glob 转义、盘符 glob 前缀、上传摘要回显远端落点、ssh2 解析第 4 级向上回溯 |
| 0.2.3 (2026-11-20) | ≥ 0.2.0-rc.1 | 不同主机写入同一 `local_path` 的下载按目标路径串行化 |
| 0.2.0 – 0.2.2 | ≥ 0.2.0-rc.1 | 早期线。按目标路径串行化是 0.2.3 才有的行为 |

远端兼容：

| 远端 | 状态 |
|---|---|
| OpenSSH 9.2p1（fnOS NAS） | 真机回归已验证 |
| **Windows OpenSSH 9.5（cmd.exe）** | **真机回归已验证（0.2.4 起）**：盘符路径/空格路径/中文文件名/递归/glob；见下方「远端为 Windows 时」 |
| dropbear / BusyBox / 厂商固件 | 未验证 |

### 远端为 Windows 时

远端是 Windows OpenSSH（默认 shell cmd.exe）时的行为与注意点（均自 0.2.4 起）：

- **路径引用自动适配**：盘符/UNC 路径按 Windows 语义引用——含空格或双引号时用双引号包裹（`"` 转义为 `""`），干净路径直传；POSIX 路径保持单引号。歧义场景（Windows 远端 + 相对路径）用 `remote_shell: "win"` 显式指定。
- **盘符路径可用**：`C:/Users/...` 形式开箱即用；glob 批量接受盘符前缀（如 `C:/logs/*.txt`）。
- **literal 下载含 `[]` 文件名**：POSIX 远端转义 glob 元字符后下发（绕过远端 scp 自身的 glob 解析）；Windows 远端直传（其 scp argv 无 glob 层）。
- **非 ASCII 文件名**：SCP 线协议按原始字节传输名称；远端按系统 ANSI 代码页解码时，控制台显示可能乱码。实际字节名可用远端 PowerShell（`[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-ChildItem -Name`）直接读出正确名称（0.3.1 起插件的失败清单也用此法），不必绕 SFTP；读写内容不受影响。
- **协商开销**：每次传输有约 2-15 秒的 SSH+scp 协商固定开销（与文件大小无关），批量小文件场景自行规划。
- **上传不自动创建父目录**：上传到远端不存在的深层目录会失败，先建目录再传。
- **手工排障提示**：在 Windows 远端手工调试 SCP 协议时用文件重定向（`scp -t path < cmds.txt`）；管道写法（`echo … | scp -t`）在 cmd 下永不退出。
- **递归下载不过滤隐藏文件**：`.git` 等会全量拉取，注意目录体量。

插件为 host-only bundle：注册 host 工具与 patch config，不含 client 侧组件。

## Known limitations

- 无断点续传。
- 同一主机串行传输（max_concurrent_per_host 默认 1）。
- 传输中途失败时，已传文件保留，不做回滚。
- 不做 SSH 主机密钥校验（TOFU，首次连接即信任）。
- SCP 协议没有长度前缀，恶意远端可声明错误大小导致 ±1 字节歧义；靠本地收尾字节对账和超时进度定位来缓解。
- 通配符下载依赖远端 scp 支持 `--` 分隔符。
- local_path 必须为绝对路径。
- 单次下载单文件上限 4 GiB，一棵目录树最多 20000 个条目；远端声明超出即拒绝。
- 0.2.3 起，不同主机并行下载写入同一 local_path 已按目标路径自动串行化。
- 上传结果摘要回显远端落点（`remote path: ...`），下载结果摘要回显本地落盘路径（`saved to ...`）——0.2.4 起，上传不再显示本地路径。
- 纯空目录树递归上传会在远端建成全部空目录（结果 files=0、dirs=N）——`files=0` 不等于"什么都没传"。
- 省略凭据时复用本进程内同一 host|port|username 的上次成功连接凭据（`credentials_reused: true`）；缓存随插件停用或宿主重启清空——远端改密后请显式传 password。
- **连接池**（0.4.0 起）：同一 host|port|username 的传输复用池内活连接（空闲 60 秒自动关闭，池取用时健康检查）。注意语义：池化连接在建立时已完成认证，之后即使传入错误密码也会成功——验证密码请使用新目标或等待池空闲关闭；传输失败/中止的连接不回池。

## Credits

- dsh-ssh-ops（caoyiwei850）：伴生插件。
- ssh2（mscdex）：exec 通道与 SCP 线协议的底层实现库。

## License

以 [MIT](LICENSE) 许可证发布。
