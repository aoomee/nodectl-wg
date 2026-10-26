#!/usr/bin/env python3
"""Interactive A (Realm) -> WireGuard -> B (VLESS/REALITY) deployment."""
import argparse
import concurrent.futures
import base64
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import sys
import time
import warnings
from datetime import datetime
from urllib.parse import urlencode

import paramiko

BASE = Path(__file__).resolve().parent
ROOT = '/root/wg-ab-auto'
WG_SHA = '7616aa51a4425582f3b4650d1b085c34a0fefccbf8100306dbed8586c6cca80e'
os.umask(0o077)
warnings.simplefilter('error', getpass.GetPassWarning)


class RemoteOperationUncertain(RuntimeError):
    pass

PROBE = r'''
set -eu
test "$(id -u)" = 0 || { echo '需要 root 登录'; exit 1; }
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) echo '仅支持 Debian/Ubuntu'; exit 1;; esac
test "$(uname -m)" = x86_64 || { echo '此版本仅支持 x86_64 服务器'; exit 1; }
test -d /run/systemd/system || { echo '需要 systemd'; exit 1; }
command -v python3 >/dev/null || { echo '请先在服务器安装 python3'; exit 1; }
python3 - <<'PY'
import json,pathlib,subprocess
def out(args):
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);return p.stdout.strip()
ports=[]
for line in out(['ss','-H','-lnt']).splitlines():
 try:ports.append(int(line.split()[3].rsplit(':',1)[1]))
 except (ValueError,IndexError):pass
udp_ports=[]
for line in out(['ss','-H','-lun']).splitlines():
 try:udp_ports.append(int(line.split()[3].rsplit(':',1)[1]))
 except (ValueError,IndexError):pass
p=pathlib.Path('/root/wg-ab-auto/state.json')
state=json.loads(p.read_text()) if p.exists() else None
paths=['/etc/xray-wgab-auto/config.json','/etc/realm-wgab-auto/config.toml',
 '/etc/wireguard/wg-abauto.conf','/etc/systemd/system/xray-wgab-auto.service',
 '/etc/systemd/system/realm-wgab-auto.service','/usr/local/lib/xray-wgab-auto','/usr/local/lib/realm-wgab-auto',
 '/usr/local/sbin/wg-multi-relay-abauto']
print(json.dumps({'ports':ports,'udp_ports':udp_ports,'state':state,'virt':out(['systemd-detect-virt']),
 'kernel':out(['uname','-r']),'conflicts':[p for p in paths if pathlib.Path(p).exists()]}))
PY
'''


def log(message):
    print(message, flush=True)


def valid_ip(value):
    value = str(ipaddress.IPv4Address(value.strip()))
    if not ipaddress.ip_address(value).is_global:
        raise ValueError('请输入公网 IPv4 地址。')
    return value


def port_input(label):
    while True:
        raw = input(label + ' SSH 端口 [22]：').strip() or '22'
        if raw.isdecimal() and 1 <= int(raw) <= 65535:
            return int(raw)
        log('端口应为 1–65535。')


def ip_input(label):
    while True:
        try:
            return valid_ip(input(label + ' 公网 IPv4：'))
        except ValueError as exc:
            log(str(exc))


def choose_port(occupied):
    for port in [443, 24443, 34443, 44443] + list(range(20000, 21000)):
        if port not in occupied:
            return port
    raise RuntimeError('未找到可用业务端口。')


def instance_id(a, b, a_port, b_port, architecture='realm'):
    value = '%s:%s>%s:%s' % (a.ip, a_port, b.ip, b_port)
    if architecture != 'realm':
        value += ':' + architecture
    return 's' + hashlib.sha256(value.encode()).hexdigest()[:10]


def configure_pair(a, b, a_port, b_port, architecture='realm'):
    if architecture not in ('realm', 'vless_ss'):
        raise ValueError('未知的部署模式。')
    legacy = []
    for host in (a, b):
        raw = host.shell("if test -f /root/wg-ab-auto/state.json; then cat /root/wg-ab-auto/state.json; else echo null; fi", quiet=True)
        legacy.append(json.loads(raw))
    matches = lambda state: state and all(state.get(k) == v for k, v in
        dict(a_ip=a.ip, b_ip=b.ip, a_port=a_port, b_port=b_port).items())
    use_legacy = architecture == 'realm' and any(matches(state) for state in legacy) and all(not state or matches(state) for state in legacy)
    name = None if use_legacy else instance_id(a, b, a_port, b_port, architecture)
    for host in (a, b):
        host.instance = name
        host.root = ROOT if name is None else '/var/lib/songrong-wg/' + name
        host.iface = 'wg-abauto' if name is None else 'wg-' + name
        host.suffix = 'wgab-auto' if name is None else 'sr-' + name


def build_pair(a, b, pa, pb, sni, mtu, a_port=None, b_port=None, architecture='realm'):
    if a.ip == b.ip:
        raise RuntimeError('A 与 B 必须是不同的服务器。')
    for value in (a_port, b_port):
        if value is not None and (not isinstance(value, int) or not 1 <= value <= 65535):
            raise ValueError('业务端口必须为 1–65535。')
    if architecture not in ('realm', 'vless_ss'):
        raise ValueError('未知的部署模式。')
    expected = dict(a_ip=a.ip, b_ip=b.ip, sni=sni, mtu=mtu, schema=2)
    if architecture != 'realm':
        expected.update(architecture=architecture, schema=3)
    name = getattr(a, 'instance', None)
    if name:
        expected['instance'] = name
    else:
        expected.update(schema=1, a_ssh=a.port, b_ssh=b.port)
    states = [p['state'] for p in (pa, pb) if p['state']]
    ignored = {'role', 'a_ssh', 'b_ssh'}
    if states:
        old = {k: v for k, v in states[0].items() if k != 'role'}
        for key, value in expected.items():
            if key not in ignored and old.get(key) != value:
                raise RuntimeError('本次入口已有不同的 REALITY 或 MTU 配置；请使用空闲业务端口，避免覆盖运行中的服务。')
        for role, probe in [('A', pa), ('B', pb)]:
            state = probe['state']
            if state and (state.get('role') != role or {k:v for k,v in state.items() if k not in ignored} != {k:v for k,v in old.items() if k not in ignored}):
                raise RuntimeError('本次入口的两端配置不一致，请检查已有服务。')
        expected = old
        for key, value in [('a_port', a_port), ('b_port', b_port)]:
            if value is not None and old[key] != value:
                raise RuntimeError('指定业务端口与本次入口的运行配置不同。')
    else:
        expected.update(a_port=a_port or choose_port(pa['ports']), b_port=b_port or choose_port(pb['ports']))
    for role, probe in [('A', pa), ('B', pb)]:
        if not probe['state'] and probe['conflicts']:
            raise RuntimeError(role + ' 发现同名但无归属的运行配置，无法安全复用。')
        if not probe['state'] and expected[role.lower() + '_port'] in probe['ports']:
            raise RuntimeError(role + ' 的业务端口 ' + str(expected[role.lower() + '_port']) + ' 已被现有服务占用，请选择空闲端口。')
    if architecture == 'vless_ss' and not pb['state'] and expected['b_port'] in pb.get('udp_ports', []):
        raise RuntimeError('B 的 SS UDP 端口已被其他服务占用，请选择空闲端口。')
    return expected


def business_port_input(role, probe, requested):
    if requested is not None:
        return requested
    saved = probe['state']
    if saved:
        log(role + ' 沿用已有业务端口 ' + str(saved[role.lower() + '_port']))
        return saved[role.lower() + '_port']
    suggestion = choose_port(probe['ports'])
    while True:
        raw = input(role + ' 业务端口 [回车自动选择 ' + str(suggestion) + ']：').strip()
        if not raw:
            return suggestion
        if raw.isdecimal() and 1 <= int(raw) <= 65535:
            if int(raw) not in probe['ports']:
                return int(raw)
            log('该端口已经占用，请选其他端口；不会强制停止已有服务。')
        else:
            log('端口应为 1–65535。')


class TrustFirstUse(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        fp = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        log('首次连接 ' + hostname + '，记录 SSH 指纹 SHA256:' + fp)
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(str(BASE / '.known_hosts'))
        (BASE / '.known_hosts').chmod(0o600)


class Host:
    def __init__(self, role, ip, port, username='root'):
        self.role, self.ip, self.port = role, ip, port
        self.username = username
        self.sudo_password = None
        self.elevate = False
        self.instance = None
        self.root, self.iface, self.suffix = ROOT, 'wg-abauto', 'wgab-auto'
        self.client = paramiko.SSHClient()
        self.lock_channel = None

    def connect(self, via=None, password=None):
        known = BASE / '.known_hosts'
        if password is None:
            password = getpass.getpass(self.role + ' ' + self.username + ' 登录密码（隐藏输入）：')
        options = dict(port=self.port, username=self.username, password=password,
                       timeout=20, banner_timeout=20, auth_timeout=20,
                       look_for_keys=False, allow_agent=False)
        routes = [('direct', self.ip)]
        if via is not None:
            routes.append(('via A', self.ip))
        try:
            for index, (route, address) in enumerate(routes):
                self.client.close()
                self.client = paramiko.SSHClient()
                self.client.load_system_host_keys()
                if known.exists():
                    self.client.load_host_keys(str(known))
                self.client.set_missing_host_key_policy(TrustFirstUse())
                sock = None
                try:
                    if route != 'direct':
                        sock = via.client.get_transport().open_channel(
                            'direct-tcpip', (address, self.port), ('127.0.0.1', 0), timeout=20)
                    self.client.connect(self.ip, sock=sock, **options)
                    channel = self.client.get_transport().open_session(timeout=10)
                    try:
                        channel.exec_command('true')
                        deadline = time.monotonic() + 10
                        while not channel.exit_status_ready():
                            if time.monotonic() >= deadline:
                                raise socket.timeout('SSH health check timed out')
                            time.sleep(0.1)
                        if channel.recv_exit_status() != 0:
                            raise RuntimeError('SSH health check failed')
                    finally:
                        channel.close()
                    if index:
                        log(self.role + ' 经 ' + route + ' 建立稳定 SSH 连接。')
                    break
                except (OSError, EOFError, paramiko.SSHException, RuntimeError) as exc:
                    if sock is not None:
                        sock.close()
                    if isinstance(exc, (paramiko.AuthenticationException, paramiko.BadHostKeyException)):
                        raise
                    if index == len(routes) - 1:
                        raise
                    log(self.role + ' SSH 路径 ' + route + ' 不稳定，尝试其他路径。')
            uid = self.command('id -u', quiet=True).strip()
            if uid != '0':
                self.elevate = True
                self.sudo_password = password
                try:
                    if self.command('id -u', timeout=20, quiet=True).strip() != '0':
                        raise RuntimeError('sudo 未取得管理员权限。')
                except Exception:
                    self.sudo_password = None
                    raise RuntimeError(self.role + ' 登录成功，但该账号无法使用 sudo。需要免密 sudo，或 sudo 密码与登录密码相同。')
                log(self.role + ' 的 sudo 权限检查通过。')
        finally:
            del password
        self.client.get_transport().set_keepalive(20)
        log(self.role + ' SSH 已连接。')

    def open_command(self, command):
        channel = self.client.get_transport().open_session(timeout=20)
        channel.set_combine_stderr(True)
        marker = '__SR_SUDO_' + secrets.token_hex(12) + '__'
        if self.elevate:
            command = 'sudo -k -S -p ' + shlex.quote(marker) + ' -- bash -c ' + shlex.quote(command)
        channel.exec_command(command)
        return channel, marker.encode()

    def answer_sudo(self, channel, data, marker, answered):
        if marker in data:
            data[:] = data.replace(marker, b'')
            if answered or self.sudo_password is None:
                raise RuntimeError(self.role + ' sudo 验证失败。')
            channel.sendall((self.sudo_password + '\n').encode())
            return True
        return answered

    def command(self, command, timeout=300, quiet=False):
        channel, marker = self.open_command(command)
        answered = False
        data = bytearray()
        start = time.monotonic()
        last_notice = start
        try:
            while True:
                while channel.recv_ready():
                    data.extend(channel.recv(65536))
                    answered = self.answer_sudo(channel, data, marker, answered)
                if channel.exit_status_ready() and not channel.recv_ready():
                    break
                if time.monotonic() - start > timeout:
                    raise RuntimeError(self.role + ' 操作超时；请检查服务器上的服务和日志后重试。')
                if not quiet and time.monotonic() - last_notice >= 25:
                    log(self.role + ' 正在执行，请稍候……')
                    last_notice = time.monotonic()
                time.sleep(0.1)
            code = channel.recv_exit_status()
            text = data.decode('utf-8', errors='replace')
            if code:
                # Worker output contains progress/errors, not SSH passwords or private keys.
                raise RuntimeError(self.role + ' 执行失败：\n' + text[-5000:])
            return text
        finally:
            channel.close()

    def shell(self, script, **kwargs):
        return self.command('bash -c ' + shlex.quote(script), **kwargs)

    def read(self, path):
        if self.elevate:
            return self.command('cat -- ' + shlex.quote(path), quiet=True)
        with self.client.open_sftp() as sftp:
            with sftp.open(path, 'r') as f:
                return f.read().decode('utf-8')

    def put_text(self, path, content, mode=0o600):
        if self.elevate:
            with self.client.open_sftp() as sftp:
                tmp = sftp.normalize('.') + '/.sr-upload-' + secrets.token_hex(16)
                try:
                    with sftp.open(tmp, 'wx') as f:
                        f.chmod(0o600)
                        f.write(content)
                    target = path + '.upload-' + secrets.token_hex(8)
                    self.command('install -m ' + oct(mode)[2:] + ' -- ' + shlex.quote(tmp) + ' ' + shlex.quote(target) +
                                 ' && mv -f -- ' + shlex.quote(target) + ' ' + shlex.quote(path), quiet=True)
                finally:
                    sftp.remove(tmp)
            return
        with self.client.open_sftp() as sftp:
            tmp = path + '.upload'
            with sftp.open(tmp, 'w') as f:
                f.write(content)
            sftp.chmod(tmp, mode)
            sftp.posix_rename(tmp, path)

    def setup(self, pair):
        self.shell('install -d -m 700 ' + self.root)
        for name in ['remote_worker.py']:
            self.put_text(self.root + '/' + name, (BASE / name).read_text(), 0o700)
        self.put_text(self.root + '/request.json', json.dumps(dict(pair, role=self.role), indent=2))
        self.worker('init')

    def worker(self, action):
        token = secrets.token_hex(12)
        pid_file = self.root + '/operation-' + token + '.pid'
        script = 'echo $$ > ' + pid_file + '; trap ' + shlex.quote('rm -f ' + pid_file) + ' EXIT; ' \
                 + 'python3 ' \
                 + self.root + '/remote_worker.py ' + shlex.quote(action)
        try:
            result = self.command('setsid --wait bash -c ' + shlex.quote(script), timeout=1120)
        except BaseException:
            # Stop this exact operation's process group before rollback/credential cleanup.
            stop = """import os,signal,time,pathlib
p=pathlib.Path(PID_FILE)
if p.exists():
 try:
  pid=int(p.read_text().strip())
  marker=pathlib.Path('/proc/%s/cmdline'%pid)
  if os.getpgid(pid)==pid and TOKEN.encode() in marker.read_bytes():
   os.killpg(pid,signal.SIGTERM)
   time.sleep(2)
   try:
    if marker.exists() and TOKEN.encode() in marker.read_bytes():
     os.killpg(pid,signal.SIGKILL)
   except ProcessLookupError: pass
 except (FileNotFoundError,ProcessLookupError): pass
 p.unlink(missing_ok=True)
""".replace('PID_FILE', repr(pid_file)).replace('TOKEN', repr(token))
            try:
                self.command('python3 -c ' + shlex.quote(stop), timeout=15, quiet=True)
            except Exception:
                raise RemoteOperationUncertain(self.role + ' 无法确认远程操作已停止；请检查 ' + pid_file + '。')
            raise
        # Keep the UI compact; full WG/apt output remains available when a command fails.
        for line in result.splitlines():
            if any(token in line for token in ['通过', '已运行', '成功', '清理', '恢复', '失败', '重试', 'TCP_TEST_RESULT']):
                log(self.role + ': ' + line)
        return result

    def probe(self):
        probe = PROBE.replace(ROOT, self.root).replace('wg-abauto', self.iface).replace('wgab-auto', self.suffix).replace('wg-multi-relay-abauto', 'wg-multi-relay-' + (self.instance or 'abauto'))
        result = json.loads(self.shell(probe, quiet=True).strip().splitlines()[-1])
        if result['virt'] in ['lxc', 'openvz', 'docker', 'podman']:
            raise RuntimeError(self.role + ' 是容器环境；本脚本只支持具备内核 WireGuard 的 VPS。')
        log(self.role + ' 预检完成，内核 ' + result['kernel'])
        return result

    def close(self):
        self.sudo_password = None
        if self.lock_channel is not None:
            try:
                self.lock_channel.close()
            except (EOFError, OSError, paramiko.SSHException):
                pass
            self.lock_channel = None
        try:
            self.client.close()
        except (EOFError, OSError, paramiko.SSHException):
            pass

    def acquire_lock(self):
        channel, marker = self.open_command("flock -n /run/wg-ab-auto-session.lock sh -c 'echo LOCKED; cat >/dev/null'")
        channel.settimeout(15)
        data = bytearray()
        answered = False
        try:
            while b'\n' not in data:
                chunk = channel.recv(128)
                if not chunk:
                    raise RuntimeError(self.role + ' 已有自动部署在运行。')
                data += chunk
                answered = self.answer_sudo(channel, data, marker, answered)
            if data.strip() != b'LOCKED':
                raise RuntimeError(self.role + ' 无法获取部署锁。')
            self.lock_channel = channel
        except BaseException:
            channel.close()
            raise


def deploy_wg_pair(a, b):
    for host in (a, b):
        host.put_text(host.root + '/wg-multi-relay.sh', (BASE / 'vendor/wg-multi-relay.sh').read_text(), 0o700)
    plan = json.loads(a.worker('wg-subnets').strip().splitlines()[-1])
    b.put_text(b.root + '/excluded-subnets.json', json.dumps(plan))
    b.worker('wg-plan')
    code = b.read('/etc/wireguard/' + b.iface + '.pair')
    a.put_text(a.root + '/pair-code', base64.b64encode(code.encode()).decode())
    a.worker('wg-relay')
    peer = a.read('/etc/wireguard/' + a.iface + '.peer')
    b.put_text(b.root + '/peer-code', base64.b64encode(peer.encode()).decode())
    b.worker('wg-activate')
    a.worker('wg')


def interpret_wg_diagnostics(a, b, pair):
    lines = []
    established = bool(a.get('interface') or b.get('interface'))
    if not established:
        return dict(ok=False, established=False, lines=['尚未建立 WG；当前只能确认 SSH 和业务端口，部署时会继续验证 UDP 握手。'])
    for role, data in [('A', a), ('B', b)]:
        if not data.get('interface'):
            lines.append(role + ' 的 WG 接口未运行，请检查该端服务启动错误。')
        if data.get('capture'):
            lines.append(role + ' 本次采样：发出 %s 个、收到 %s 个 WG UDP 报文。' %
                         (data['outgoing'], data['incoming']))
        if data.get('listen_port'):
            lines.append(role + ' 的 WG UDP 本地端口：' + str(data['listen_port']) + '。')
        names = {1: '握手请求', 2: '握手响应', 3: 'Cookie 响应', 4: '加密数据'}
        for flow in data.get('flows', [])[:4]:
            lines.append(role + ' 观察到 ' + names.get(flow['kind'], 'WG 报文') + '：' + flow['source'] + ':' + str(flow['sport']) + ' → ' + flow['destination'] + ':' + str(flow['dport']) + '，' + str(flow['count']) + ' 个。')
        if data.get('note'):
            lines.append(role + '：' + data['note'])
    if not (a.get('interface') and b.get('interface')):
        return dict(ok=False, established=True, lines=lines)
    keys_match = a['public_key'] in b['peers'] and b['public_key'] in a['peers']
    if not keys_match:
        lines.append('两端的 WG 公钥配对不一致，需要重新配对；请勿仅放行端口。')
    else:
        lines.append('两端 WG 公钥配对一致。')
    port = b.get('wg_port') or b.get('listen_port') or 51820
    if a.get('wg_port') and str(a['wg_port']) != str(port):
        lines.append('A 配置的 UDP 目标端口与 B 的实际监听端口不同。')
    recent = all(0 < time.time() - d.get('handshake', 0) < 180 for d in [a, b])
    if recent and keys_match:
        lines.append('两端最近 3 分钟内有握手记录；若业务仍失败，继续检查隧道内业务端口、MTU 和 B 的外网访问。')
        return dict(ok=True, established=True, lines=lines)
    before, after = b.get('firewall_before', {}), b.get('firewall_after', {})
    dropped = max(0, after.get('drop', 0) - before.get('drop', 0))
    sources = b.get('incoming_sources', [])
    whitelist = after.get('sources', [])
    blocked_sources = []
    for source in sources:
        try:
            if whitelist and not any(ipaddress.ip_address(source) in ipaddress.ip_network(net, strict=False) for net in whitelist):
                blocked_sources.append(source)
        except ValueError: pass
    if dropped:
        lines.append('B 的 WG 白名单在采样期间丢弃了 %s 个 UDP 包；请核对中转的实际出口地址。' % dropped)
    if blocked_sources:
        lines.append('B 观察到白名单以外的 WG 报文来源：' + '、'.join(blocked_sources) + '。若这是 A 的实际出口，当前白名单地址配置不符。')
    can_compare = all(d.get('capture') and not d.get('capture_limited') for d in [a, b])
    if can_compare:
        if a['outgoing'] and not b['incoming']:
            lines.append('采样期间 A 发出了 WG 报文，但 B 未观察到：重点检查 B 云安全组 UDP %s、A 出站限制及两机之间的 UDP 线路。无法仅靠服务器区分具体拦截设备。' % port)
        elif b['outgoing'] and not a['incoming']:
            response = any(f.get('direction') == 'out' and f.get('kind') == 2 for f in b.get('flows', []))
            lines.append(('B 已发出握手响应' if response else 'B 已发出 WG 报文') + '，但 A 未观察到回包：检查 B → A 的 UDP 线路、云防火墙和 NAT；服务器采样尚不能确定具体拦截位置。')
        elif b['incoming'] and not b['outgoing'] and not dropped:
            lines.append('B 收到 WG 报文但未观察到回包：检查 B 的其他防火墙规则、Peer 配置和监听状态。')
        elif not a['outgoing']:
            lines.append('采样期间未观察到 A 向 B 发出 WG 报文：检查 A 的 Endpoint、路由与本机出站防火墙。')
        else:
            lines.append('采样期间两端有 WG 报文但没有近期握手，需要进一步核对两端时间、完整防火墙和 Peer 配置。')
    else:
        lines.append('收发采样不可用或受限，不能判断 UDP 在哪一段中断；请检查 B 云安全组 UDP %s 和两端防火墙。' % port)
    return dict(ok=False, established=True, lines=lines)


def diagnose_wg(a, b, pair):
    log('开始自动 WG 诊断：检查两端状态、配对和 UDP 收发，约需 15 秒。')
    source = Path(__file__).with_name('wg_diagnostics.py').read_text()
    def collect(host):
        payload = json.dumps(dict(role=host.role, a_ip=pair['a_ip'], b_ip=pair['b_ip'], iface=getattr(host, 'iface', 'wg-abauto')))
        output = host.shell('python3 -c ' + shlex.quote(source) + ' ' + shlex.quote(payload), timeout=35, quiet=True)
        return json.loads(output.strip().splitlines()[-1])
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fa, fb = pool.submit(collect, a), pool.submit(collect, b)
            report = interpret_wg_diagnostics(fa.result(), fb.result(), pair)
        for line in report['lines']:
            log('诊断：' + line)
        return report
    except Exception as exc:
        log('自动诊断未能完成（' + type(exc).__name__ + '）；原始部署错误保留，不将推测视为结论。')
        return dict(ok=False, established=None, lines=['诊断连接未完成。'])


def apply_deployment(a, b, pair):
    """Ordered stages; rollback if WG deployment or its business acceptance fails."""
    chain = pair.get('architecture') == 'vless_ss'
    prepared = []
    switching = False
    uncertain = False
    try:
        a.setup(pair)
        prepared.append(a)
        b.setup(pair)
        prepared.append(b)
        # Recover stale authorization from an earlier interrupted run before replacing its record.
        b.worker('cleanup')
        a.worker('cleanup')
        log('1/5 在 B 部署 Shadowsocks。' if chain else '1/5 在 B 部署 VLESS + REALITY。')
        b.worker('install-b')
        if chain:
            a.put_text(a.root + '/ss-credentials.json', b.read(b.root + '/ss-credentials.json'))
        log('2/5 在 A 部署 VLESS + REALITY → SS。' if chain else '2/5 在 A 部署 realm。')
        a.worker('install-a')
        if chain:
            a.worker('public-path')
            b.put_text(b.root + '/client-meta.json', a.read(a.root + '/client-meta.json'))
        log('3/5 从 B 经 A 的公网入口验证真实 VLESS 请求及出口 IP。')
        b.worker('test')
        # This is independent of the B-originated application test.
        with socket.create_connection((a.ip, pair['a_port']), timeout=15):
            pass
        log('本机到 A 入口端口可达。')
        log('4/5 在 A 执行 WG 配对并切换到 B 的隧道地址。')
        switching = True
        deploy_wg_pair(a, b)
        log('5/5 验证切换后的 HTTPS、出口 IP 和文件下载校验。')
        b.worker('test-final')
        a.command('systemctl is-active --quiet ' + ('xray-' if chain else 'realm-') + a.suffix + ' wg-quick@' + a.iface)
        b.command('systemctl is-active --quiet xray-' + b.suffix + ' wg-quick@' + b.iface)
        client_host = a if chain else b
        return json.loads(client_host.read(client_host.root + '/client-meta.json'))
    except BaseException as failure:
        uncertain = isinstance(failure, RemoteOperationUncertain)
        if switching and not uncertain:
            log('WG 阶段未通过；尝试恢复已经验证过的公网转发。')
            try:
                a.worker('rollback')
                b.worker('test')
                log('已恢复并验证公网转发；本次 WG 部署未标为成功。')
            except Exception as exc:
                log('自动回滚或回滚后验证未完成：' + str(exc))
            if isinstance(failure, Exception):
                diagnose_wg(a, b, pair)
        raise
    finally:
        cleanup_failed = []
        # Remove authorization first. If B cleanup fails, still remove A's private key.
        for host in reversed(prepared) if not uncertain else []:
            try:
                host.worker('cleanup')
            except Exception:
                cleanup_failed.append(host.role)
        if cleanup_failed:
            log('需处理：' + '、'.join(cleanup_failed) + ' 的临时凭据清理未完成；请按说明文档清理或重试。')
        if uncertain:
            log('连接中断后远程状态无法确认，未并发发起回滚或清理。请恢复 SSH 后按说明检查并清理临时密钥。')


def export_result(pair, meta):
    directory = BASE / 'results' / datetime.now().strftime('%Y%m%d-%H%M%S')
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    chain = pair.get('architecture') == 'vless_ss'
    query = urlencode({'encryption': 'none', 'security': 'reality', 'sni': meta['serverName'],
                       'fp': 'chrome', 'pbk': meta['publicKey'], 'sid': meta['shortId'],
                       'type': 'tcp', 'flow': meta['flow']})
    link = 'vless://' + meta['id'] + '@' + pair['a_ip'] + ':' + str(pair['a_port']) + '?' + query + ('#VLESS-WG-SS' if chain else '#A-WG-B')
    (directory / 'VLESS.txt').write_text(link + '\n')
    summary = dict(pair, status='verified', protocol='VLESS + REALITY → WG → SS' if chain else 'VLESS + REALITY + Vision',
                   interface='wg-' + pair.get('instance', 'abauto'), expected_exit=pair['b_ip'])
    (directory / 'result.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    command = 'wg-multi-relay-' + pair.get('instance', 'abauto')
    iface = 'wg-' + pair.get('instance', 'abauto')
    rollback_command = ('python3 /var/lib/songrong-wg/' + pair['instance'] + '/remote_worker.py rollback') if chain else command + ' realm-rollback ' + iface
    (directory / '结果说明.txt').write_text(
        '部署与业务验证已通过。\n入口：' + pair['a_ip'] + ':' + str(pair['a_port']) + '\n'
        '出口：' + pair['b_ip'] + '\n导入 VLESS.txt 中的链接。\n'
        '状态检查（在 A）：' + command + ' status ' + iface + '\n'
        + '切回公网（在 A，会重启本次入口服务）：' + rollback_command + '\n'
        + '测试从 B 发起，经 A 公网入口回到 B；另已检查运行本脚本的机器能连接 A 的入口端口。\n'
        '云安全组由你在云厂商控制台管理；本脚本不能修改。\n')
    for p in directory.iterdir():
        p.chmod(0o600)
    return directory


def main():
    parser = argparse.ArgumentParser(description='输入两台 VPS 的 IP/root 密码，部署 A realm → WG → B VLESS。')
    parser.add_argument('--check-only', action='store_true', help='仅检查连接、系统和端口，不修改服务器')
    parser.add_argument('--sni', default='addons.mozilla.org', help='REALITY 目标域名，默认 addons.mozilla.org')
    parser.add_argument('--a-port', type=int, help='指定 A 的入口端口；不填则运行时选择')
    parser.add_argument('--b-port', type=int, help='指定 B 的 VLESS 端口；不填则运行时选择')
    parser.add_argument('--mtu', type=int, default=1280, help='WG MTU，1280–1500，默认 1280')
    args = parser.parse_args()
    if not 1280 <= args.mtu <= 1500:
        parser.error('MTU 必须为 1280–1500。')
    if any(p is not None and not 1 <= p <= 65535 for p in [args.a_port, args.b_port]):
        parser.error('业务端口必须为 1–65535。')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', args.sni):
        parser.error('SNI 必须是合法域名。')
    if hashlib.sha256((BASE / 'vendor/wg-multi-relay.sh').read_bytes()).hexdigest() != WG_SHA:
        raise RuntimeError('随包 WG 脚本校验失败，请重新解压原始压缩包。')
    if not sys.stdin.isatty():
        raise RuntimeError('请在交互式终端中运行；不接受通过管道或文件输入 root 密码。')
    log('A = 中转/线路机（realm）；B = 落地/出口机（VLESS）。\n密码隐藏输入，不写入文件。')
    a = Host('A', ip_input('A 中转机'), port_input('A'))
    b = Host('B', ip_input('B 落地机'), port_input('B'))
    try:
        if a.ip == b.ip:
            raise RuntimeError('A 和 B 的公网 IP 不能相同。')
        a.connect()
        b.connect(via=a)
        if a.client.get_transport().get_remote_server_key().asbytes() == b.client.get_transport().get_remote_server_key().asbytes():
            raise RuntimeError('两端 SSH 主机指纹相同，请先确认没有把同一台机器填了两遍。')
        if not args.check_only:
            a.acquire_lock()
            b.acquire_lock()
        pa, pb = a.probe(), b.probe()
        a_port = business_port_input('A', pa, args.a_port)
        b_port = business_port_input('B', pb, args.b_port)
        pair = build_pair(a, b, pa, pb, args.sni, args.mtu, a_port, b_port)
        log('已确认：A ' + a.ip + ':' + str(pair['a_port']) + ' → B ' + b.ip + ':' + str(pair['b_port']))
        if args.check_only:
            log('检查完成；没有修改服务器。')
            return
        log('云安全组需允许 A 的 TCP 入口，以及 B 接收来自 A 的业务 TCP 和 WG UDP；受阻时脚本会停止并说明。')
        meta = apply_deployment(a, b, pair)
        directory = export_result(pair, meta)
        log('\n部署完成！客户端结果已保存：' + str(directory))
        log('入口：' + a.ip + ':' + str(pair['a_port']) + '；出口：' + b.ip)
    finally:
        b.close()
        a.close()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log('\n已中断。已尝试清理临时凭据；请查看上面的清理/回滚结果。')
        sys.exit(130)
    except paramiko.AuthenticationException:
        log('SSH 登录失败：请确认 root 密码、端口及服务器是否允许密码登录。')
        sys.exit(1)
    except paramiko.BadHostKeyException:
        log('SSH 指纹与已记录的指纹不同，已停止连接。核实是否重装过服务器后再更新主机记录。')
        sys.exit(1)
    except Exception as exc:
        log('未完成：' + type(exc).__name__ + ': ' + str(exc))
        sys.exit(1)
