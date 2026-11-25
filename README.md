# Redmi WiFi SSH

一键为 **Redmi 路由器 AX6000（miwifi RB06）1.0.67** 开启 root SSH。  
SSH 密码 = Web 后台管理密码，重启后自动恢复。

One-click root SSH for **Redmi Router AX6000 (miwifi RB06) 1.0.67**.  
The SSH password equals the web admin password, and SSH is restored automatically after reboot.

[中文](#中文文档) | [English](#english)

---

## 中文文档

### 项目简介

`redmi_wifi_ssh.py` 是一个跨平台 Python 脚本：输入路由器 IP 和后台管理密码，即可为 Redmi AX6000（RB06）1.0.67 开启 root SSH。

- 立即生效：不需要重启路由器。
- 持久化：路由器重启后 SSH 自动恢复，密码仍为后台管理密码。
- 纯标准库：Windows / Linux / macOS 均可运行，不依赖 OpenSSL 或第三方 Python 包。
- 已验证：在 RB06 1.0.67 实机上完成 SSH 登录（`uid=0(root)`），并做过真实重启验证。

### 适用设备与固件

| 项目 | 内容 |
|---|---|
| 设备 | Redmi 路由器 AX6000（型号 RB06 / 小米固件 miwifi_rb06） |
| 固件 | 1.0.67 |
| 固件下载 | https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rb06/miwifi_rb06_firmware_de54d_1.0.67.bin |
| 固件 MD5 | `9adc67d8b5bd6dce8bff80cc0b5de54d` |

### 功能特性

- 自动登录路由器 Web API，获取 `stok`（兼容 `newEncryptMode=1` 的 SHA-256 流程和旧版 SHA-1 流程）。
- 通过 smartcontroller 场景 `name` 命令注入（CVE-2023-26319 类）执行 root 命令。
- 把系统 root 的登录密码设置为 Web 后台管理密码。
- 立即启动 dropbear，SSH 当场可用。
- 持久化：`/data/xq_ssh/boot.sh` + `/etc/config/firewall` 的 include 钩子。
- 保留 dropbear 主机密钥（备份在 `/data`），重启后客户端不会反复提示 host key 变化。
- 自动验证 SSH 密码登录（有 `sshpass` 时）并检查持久化配置。

### 工作原理

1. 脚本调用 `/api/xqsystem/login` 登录，取得 `stok`。
2. 通过 `/api/xqsmarthome/request_smartcontroller` 创建并启动场景，在场景 `name` 中注入 `$(command)`，以 root 执行命令。
3. 路由器从本机临时 HTTP 服务下载配置脚本并执行。
4. 配置脚本写入持久化开机脚本 `/data/xq_ssh/boot.sh`，并立即执行一次。
5. 在 `/etc/config/firewall` 注册 include 钩子，每次开机以 root 执行该脚本。
6. `boot.sh` 每次开机重设 root 密码哈希、恢复 host key、patch dropbear 的 release 渠道检查，并启动 dropbear。

> RB06 1.0.67 的 `/etc` 是 ramfs（重启即丢），所以密码哈希和 init 脚本修改必须由 `/data` 中的开机脚本在每次启动时重新应用。

### 环境要求

- Python 3.7+（Windows / Linux / macOS）。
- 本机需要能被路由器访问：脚本会临时在 `0.0.0.0` 上启动 HTTP 服务，供路由器下载配置脚本。
  - Windows 防火墙弹窗请允许“专用网络”。
- 可选：`sshpass`（Linux/macOS），用于自动验证密码登录。Windows 默认没有 `sshpass`，脚本会只检查 22 端口并给出手动连接命令。

### 使用方法

```bash
# 两个位置参数：IP + 后台密码
python3 redmi_wifi_ssh.py <路由器IP> '<后台管理密码>'

# 或用 --password
python3 redmi_wifi_ssh.py <路由器IP> --password '<后台管理密码>'

# 不传密码则交互输入
python3 redmi_wifi_ssh.py <路由器IP>
```

示例：

```bash
python3 redmi_wifi_ssh.py 192.168.31.1 'my-password'
python3 redmi_wifi_ssh.py 10.0.0.142 --password 'my-password'
python3 redmi_wifi_ssh.py 10.0.0.142 --no-verify
```

成功后的最后两行输出：

```text
ssh -o HostKeyAlgorithms=+ssh-rsa root@<路由器IP>
# 以上为 SSH 连接命令，SSH 密码 = Web 后台管理密码
```

### 参数说明

| 参数 | 说明 |
|---|---|
| `ip` | 路由器管理地址（必填，位置参数 1） |
| `password_pos` | 后台管理密码（位置参数 2，可省略） |
| `--password` | 后台管理密码（与位置参数 2 二选一） |
| `--user` | SSH 用户名，默认 `root` |
| `--port` | SSH 端口，默认 `22` |
| `--no-verify` | 只检查 22 端口，不自动验证密码登录 |
| `--listen-ip` | 本机用于让路由器下载脚本的 IP（默认自动探测） |

### SSH 登录

现代 OpenSSH 默认禁用 `ssh-rsa` 主机密钥，连接时需要显式允许：

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@<路由器IP>
```

密码 = Web 后台管理密码。

也可以写入 `~/.ssh/config`：

```sshconfig
Host <路由器IP>
    HostKeyAlgorithms +ssh-rsa
```

然后直接：

```bash
ssh root@<路由器IP>
```

### 重启持久化

- 开机脚本：`/data/xq_ssh/boot.sh`（UBI，重启不丢）。
- 开机钩子：`/etc/config/firewall` 中的 `firewall.xq_ssh` include（`/etc/config` 在 UBI 上）。
- 主机密钥：`/data/xq_ssh/dropbear_rsa_host_key`。
- 已做真实重启验证：重启后 SSH 自动恢复，`uid=0(root)`，host key 不变。

### 关闭 SSH

```bash
ssh root@<路由器IP> "/sbin/uci delete firewall.xq_ssh; /sbin/uci commit firewall; killall dropbear; rm -rf /data/xq_ssh"
```

### 注意事项

- 脚本会重启 dropbear 服务，**不要通过 SSH 会话运行本脚本**（会断开当前连接）；在本机直接运行即可。
- 后台密码连续错误会触发路由器登录锁定，脚本只尝试一次登录。
- 修改后台密码后，重新运行脚本即可同步 SSH 密码。
- 固件升级后如果 `/data` 或防火墙配置被重置，重新运行脚本即可。
- 仅用于你拥有或已获得明确授权的设备。

### 免责声明

本项目仅用于合法的安全研究、教学和已授权设备的测试。请勿用于未经授权的设备或网络。使用者需自行承担因使用本工具产生的一切后果，作者不承担任何责任。

---

## English

### Overview

`redmi_wifi_ssh.py` is a cross-platform Python script that enables root SSH on a Redmi AX6000 (RB06) running firmware 1.0.67. Pass the router IP and the web admin password; the script does the rest.

- Takes effect immediately — no router reboot required.
- Persistent — SSH comes back automatically after reboot, with the same password (the web admin password).
- Standard library only — runs on Windows, Linux, and macOS without OpenSSL or third-party Python packages.
- Tested — verified root login (`uid=0(root)`) on a real RB06 1.0.67 and validated across a real reboot.

### Supported Device and Firmware

| Item | Value |
|---|---|
| Device | Redmi Router AX6000 (model RB06 / Xiaomi firmware miwifi_rb06) |
| Firmware | 1.0.67 |
| Firmware download | https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rb06/miwifi_rb06_firmware_de54d_1.0.67.bin |
| Firmware MD5 | `9adc67d8b5bd6dce8bff80cc0b5de54d` |

### Features

- Logs in to the router web API and obtains a `stok` (supports both `newEncryptMode=1` SHA-256 and legacy SHA-1 flows).
- Executes root commands through a smartcontroller scene `name` command injection (CVE-2023-26319 class).
- Sets the system root password to the web admin password.
- Starts dropbear immediately; SSH is usable right away.
- Persistence via `/data/xq_ssh/boot.sh` plus a `/etc/config/firewall` include hook.
- Keeps the dropbear host key stable (backed up under `/data`).
- Verifies SSH password login (when `sshpass` is available) and checks the persistence configuration.

### How It Works

1. Logs in via `/api/xqsystem/login` to obtain a `stok`.
2. Creates and starts a scene via `/api/xqsmarthome/request_smartcontroller`, injecting `$(command)` into the scene `name`, which is executed as root.
3. The router downloads a setup script from a temporary local HTTP server and runs it.
4. The setup script writes the persistent boot script `/data/xq_ssh/boot.sh` and runs it immediately.
5. It registers a firewall include hook, which runs the boot script as root at every boot.
6. On each boot, `boot.sh` resets the root password hash, restores the host key, patches the dropbear release-channel check, and starts dropbear.

> On RB06 1.0.67, `/etc` is a ramfs and is lost on reboot. The password hash and init-script patch must therefore be re-applied on every boot by a script stored in `/data`.

### Requirements

- Python 3.7+ (Windows, Linux, macOS).
- The local machine must be reachable from the router: the script temporarily serves the setup script over HTTP on `0.0.0.0`.
  - On Windows, allow Python through the firewall for private networks when prompted.
- Optional: `sshpass` (Linux/macOS) for automated password verification. Windows does not have `sshpass` by default; the script will only check port 22 and print the manual SSH command.

### Usage

```bash
# Two positional arguments: IP + admin password
python3 redmi_wifi_ssh.py <router-ip> '<admin-password>'

# Or with --password
python3 redmi_wifi_ssh.py <router-ip> --password '<admin-password>'

# Omit the password to be prompted
python3 redmi_wifi_ssh.py <router-ip>
```

Examples:

```bash
python3 redmi_wifi_ssh.py 192.168.31.1 'my-password'
python3 redmi_wifi_ssh.py 10.0.0.142 --password 'my-password'
python3 redmi_wifi_ssh.py 10.0.0.142 --no-verify
```

The final two lines of a successful run are:

```text
ssh -o HostKeyAlgorithms=+ssh-rsa root@<router-ip>
# 以上为 SSH 连接命令，SSH 密码 = Web 后台管理密码
```

The second line is Chinese and means: “The line above is the SSH command; the SSH password is the web admin password.”

### Parameters

| Parameter | Description |
|---|---|
| `ip` | Router management IP (required, positional 1) |
| `password_pos` | Web admin password (positional 2, optional) |
| `--password` | Web admin password (alternative to positional 2) |
| `--user` | SSH username, default `root` |
| `--port` | SSH port, default `22` |
| `--no-verify` | Only check port 22; skip automated password verification |
| `--listen-ip` | Local IP the router should use to download the setup script (auto-detected by default) |

### SSH Login

Modern OpenSSH disables the `ssh-rsa` host key algorithm by default. Enable it explicitly:

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@<router-ip>
```

The password is the web admin password.

Alternatively, add this to `~/.ssh/config`:

```sshconfig
Host <router-ip>
    HostKeyAlgorithms +ssh-rsa
```

Then simply:

```bash
ssh root@<router-ip>
```

### Persistence Across Reboots

- Boot script: `/data/xq_ssh/boot.sh` (UBI, survives reboot).
- Boot hook: the `firewall.xq_ssh` include in `/etc/config/firewall` (`/etc/config` is on UBI).
- Host key: `/data/xq_ssh/dropbear_rsa_host_key`.
- Real reboot tested: SSH comes back automatically with `uid=0(root)` and the same host key.

### Disabling SSH

```bash
ssh root@<router-ip> "/sbin/uci delete firewall.xq_ssh; /sbin/uci commit firewall; killall dropbear; rm -rf /data/xq_ssh"
```

### Notes

- The script restarts dropbear. **Do not run it over an SSH session** — the current connection will be dropped. Run it locally instead.
- Repeated wrong admin passwords trigger the router's login lockout; the script only attempts one login.
- If you change the web admin password, re-run the script to update the SSH password.
- If a firmware upgrade resets `/data` or the firewall configuration, re-run the script.
- Use only on devices you own or have explicit permission to test.

### Disclaimer

This project is intended for legitimate security research, education, and testing on devices you are authorized to access. Do not use it against devices or networks you do not own or have permission to test. You are responsible for complying with applicable laws and for any consequences of using this tool. The author assumes no liability.
