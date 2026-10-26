#!/usr/bin/env python3
"""Remote operations. Receives deployment settings, never SSH passwords."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile

ROOT = Path('/root/wg-ab-auto')
STATE = ROOT / 'state.json'
XRAY_DIR = Path('/usr/local/lib/xray-wgab-auto')
XRAY_CONFIG = Path('/etc/xray-wgab-auto/config.json')
REALM_DIR = Path('/usr/local/lib/realm-wgab-auto')
REALM_CONFIG = Path('/etc/realm-wgab-auto/config.toml')
XRAY_SERVICE = 'xray-wgab-auto.service'
REALM_SERVICE = 'realm-wgab-auto.service'
IFACE = 'wg-abauto'
WG_SCRIPT = ROOT / 'wg-multi-relay.sh'
WG_SHA = '7616aa51a4425582f3b4650d1b085c34a0fefccbf8100306dbed8586c6cca80e'
XRAY_SHA = '23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'
REALM_SHA = 'b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65'
os.umask(0o077)


def configure_paths():
    global ROOT, STATE, XRAY_DIR, XRAY_CONFIG, REALM_DIR, REALM_CONFIG
    global XRAY_SERVICE, REALM_SERVICE, IFACE, WG_SCRIPT
    ROOT = Path(__file__).resolve().parent
    STATE = ROOT / 'state.json'
    c = json.loads((ROOT / 'request.json').read_text())
    instance = c.get('instance')
    if instance:
        if not re.fullmatch(r's[a-f0-9]{10}', instance):
            raise RuntimeError('隧道标识无效。')
        suffix = 'sr-' + instance
        XRAY_DIR = Path('/usr/local/lib/xray-' + suffix)
        XRAY_CONFIG = Path('/etc/xray-' + suffix + '/config.json')
        REALM_DIR = Path('/usr/local/lib/realm-' + suffix)
        REALM_CONFIG = Path('/etc/realm-' + suffix + '/config.toml')
        XRAY_SERVICE = 'xray-' + suffix + '.service'
        REALM_SERVICE = 'realm-' + suffix + '.service'
        IFACE = 'wg-' + instance
    WG_SCRIPT = ROOT / 'wg-multi-relay.sh'


def run(args, timeout=300, capture=False, check=True):
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout, env=env)
    if not capture and p.stdout:
        print(p.stdout, end='', flush=True)
    if check and p.returncode:
        raise RuntimeError('命令失败：' + args[0] + '（退出码 ' + str(p.returncode) + '）')
    return p


def save(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(4))
    try:
        with tmp.open('x') as f:
            f.write(content)
        tmp.chmod(mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def settings():
    c = json.loads((ROOT / 'request.json').read_text())
    if STATE.exists():
        old = json.loads(STATE.read_text())
        if old != c:
            raise RuntimeError('已有部署记录与输入不一致；停止，保留原配置。')
    else:
        for p in [XRAY_CONFIG, REALM_CONFIG, Path('/etc/wireguard/' + IFACE + '.conf'),
                  Path('/etc/systemd/system/' + XRAY_SERVICE),
                  Path('/etc/systemd/system/' + REALM_SERVICE), XRAY_DIR, REALM_DIR]:
            if p.exists():
                raise RuntimeError('发现没有本脚本记录的同名资源：' + str(p))
        save(STATE, json.dumps(c, indent=2) + '\n')
    return c


def dependencies():
    required = ['curl', 'tar', 'ss', 'ssh', 'ssh-keygen', 'systemctl']
    if any(not shutil.which(c) for c in required):
        run(['apt-get', 'update'], timeout=600)
        run(['apt-get', 'install', '-y', 'curl', 'ca-certificates', 'tar',
             'iproute2', 'openssh-client'], timeout=600)


def download(url, dest, expected):
    dest = Path(dest)
    if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == expected:
        return
    part = dest.with_suffix(dest.suffix + '.part')
    run(['curl', '-fLsS', '--retry', '2', '--connect-timeout', '15',
         '--max-time', '180', url, '-o', str(part)], timeout=600)
    if hashlib.sha256(part.read_bytes()).hexdigest() != expected:
        part.unlink(missing_ok=True)
        raise RuntimeError('下载文件校验失败，未执行：' + dest.name)
    os.replace(part, dest)


def binary_save(path, data):
    path = Path(path)
    if path.exists() and path.read_bytes() == data:
        return False
    tmp = path.with_name(path.name + '.new')
    tmp.write_bytes(data)
    tmp.chmod(0o755)
    os.replace(tmp, path)
    return True


def service(name, body, force_restart=False):
    path = Path('/etc/systemd/system/' + name)
    changed = not path.exists() or path.read_text() != body
    save(path, body, 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', name])
    active = run(['systemctl', 'is-active', '--quiet', name], capture=True, check=False).returncode == 0
    if changed or force_restart or not active:
        run(['systemctl', 'restart', name])
    time.sleep(2)
    run(['systemctl', 'is-active', '--quiet', name])


def firewall(c):
    if not shutil.which('ufw'):
        return
    status = run(['ufw', 'status'], capture=True).stdout
    if not re.search(r'^Status:\s+active\s*$', status, re.M):
        return
    if c['role'] == 'A':
        run(['ufw', 'allow', str(c['a_port']) + '/tcp', 'comment', 'wg-ab-auto entry'])
    else:
        run(['ufw', 'allow', 'from', c['a_ip'], 'to', 'any', 'port',
             str(c['b_port']), 'proto', 'tcp', 'comment', 'wg-ab-auto public relay'])
        run(['ufw', 'allow', 'from', c['a_ip'], 'to', 'any', 'port', '51820:51999',
             'proto', 'udp', 'comment', 'wg-ab-auto tunnel'])
        run(['ufw', 'allow', 'in', 'on', IFACE, 'to', 'any', 'port',
             str(c['b_port']), 'proto', 'tcp', 'comment', 'wg-ab-auto inner service'])
        if c.get('architecture') == 'vless_ss':
            run(['ufw', 'allow', 'from', c['a_ip'], 'to', 'any', 'port', str(c['b_port']), 'proto', 'udp', 'comment', 'songrong ss'])
            run(['ufw', 'allow', 'in', 'on', IFACE, 'to', 'any', 'port', str(c['b_port']), 'proto', 'udp', 'comment', 'songrong ss inner'])


def prepare_xray():
    dependencies()
    archive = ROOT / 'xray.zip'
    download('https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip', archive, XRAY_SHA)
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    XRAY_DIR.chmod(0o755)
    with zipfile.ZipFile(archive) as z:
        binary = z.read('xray')
    changed = binary_save(XRAY_DIR / 'xray', binary)
    if run(['id', 'xray-wgab-auto'], capture=True, check=False).returncode:
        run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'xray-wgab-auto'])
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    XRAY_CONFIG.parent.chmod(0o750)
    run(['chown', 'root:xray-wgab-auto', str(XRAY_CONFIG.parent)])
    return changed


def install_vless(c):
    chain = c.get('architecture') == 'vless_ss'
    if c['role'] != ('A' if chain else 'B'):
        raise RuntimeError('VLESS 角色与部署模式不一致。')
    changed = prepare_xray()
    meta_file = ROOT / 'client-meta.json'
    if not XRAY_CONFIG.exists() and not (ROOT / 'credentials.json').exists():
        result = run([str(XRAY_DIR / 'xray'), 'x25519'], capture=True).stdout
        keys = dict(line.split(':', 1) for line in result.splitlines() if ':' in line)
        keys = {k.strip(): v.strip() for k, v in keys.items()}
        private = keys.get('PrivateKey') or keys.get('Private key')
        public = keys.get('Password (PublicKey)') or keys.get('PublicKey') or keys.get('Password')
        if not private or not public:
            raise RuntimeError('无法识别 Xray 密钥输出；不打印密钥。')
        meta = dict(id=str(uuid.uuid4()), publicKey=public, shortId=secrets.token_hex(8),
                    serverName=c['sni'], address=c['a_ip'], port=c['a_port'], flow='xtls-rprx-vision')
        config = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '0.0.0.0', 'port': c['a_port'] if chain else c['b_port'], 'protocol': 'vless',
                          'settings': {'clients': [{'id': meta['id'], 'flow': meta['flow']}], 'decryption': 'none'},
                          'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                              'show': False, 'target': c['sni'] + ':443', 'xver': 0,
                              'serverNames': [c['sni']], 'privateKey': private, 'shortIds': [meta['shortId']]}}}],
            'outbounds': [{'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}}]}
        if chain:
            config['outbounds'] = [ss_outbound(c, json.loads((ROOT / 'ss-credentials.json').read_text()), c['b_ip'])]
        # A single credential bundle makes recovery safe if writing config/meta is interrupted.
        save(ROOT / 'credentials.json', json.dumps({'config': config, 'meta': meta}))
    elif not meta_file.exists() and not (ROOT / 'credentials.json').exists():
        raise RuntimeError('已有节点缺少客户端记录，停止，避免重新生成认证信息。')
    if (ROOT / 'credentials.json').exists():
        bundle = json.loads((ROOT / 'credentials.json').read_text())
        if not XRAY_CONFIG.exists():
            save(XRAY_CONFIG, json.dumps(bundle['config'], indent=2) + '\n', 0o640)
        if not meta_file.exists():
            save(meta_file, json.dumps(bundle['meta'], indent=2) + '\n')
    if chain:
        check_chain_credentials(json.loads(XRAY_CONFIG.read_text()), json.loads((ROOT / 'ss-credentials.json').read_text()))
    activate_xray(c, changed)
    print(c['role'] + '：VLESS + REALITY 已运行。', flush=True)


def activate_xray(c, changed=False):
    run(['chown', 'root:xray-wgab-auto', str(XRAY_CONFIG)])
    XRAY_CONFIG.chmod(0o640)
    run([str(XRAY_DIR / 'xray'), 'run', '-test', '-config', str(XRAY_CONFIG)], capture=True)
    firewall(c)
    service(XRAY_SERVICE, '''[Unit]
Description=Songrong tunnel Xray
After=network-online.target
Wants=network-online.target
[Service]
User=xray-wgab-auto
Group=xray-wgab-auto
ExecStart=/usr/local/lib/xray-wgab-auto/xray run -config /etc/xray-wgab-auto/config.json
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
'''.replace('/usr/local/lib/xray-wgab-auto', str(XRAY_DIR)).replace('/etc/xray-wgab-auto/config.json', str(XRAY_CONFIG)).replace('/usr/local/lib/realm-wgab-auto', str(REALM_DIR)).replace('/etc/realm-wgab-auto/config.toml', str(REALM_CONFIG)), force_restart=changed)


def install_a(c):
    if c.get('architecture') == 'vless_ss':
        return install_vless(c)
    if c['role'] != 'A':
        raise RuntimeError('角色错误：realm 只能部署在 A。')
    dependencies()
    archive = ROOT / 'realm.tar.gz'
    download('https://github.com/zhboner/realm/releases/download/v2.9.6/realm-x86_64-unknown-linux-musl.tar.gz', archive, REALM_SHA)
    REALM_DIR.mkdir(parents=True, exist_ok=True)
    REALM_DIR.chmod(0o755)
    with tarfile.open(archive, 'r:gz') as t:
        candidates = [m for m in t.getmembers() if m.isfile() and Path(m.name).name == 'realm']
        if len(candidates) != 1:
            raise RuntimeError('Realm 压缩包格式不符合预期。')
        changed = binary_save(REALM_DIR / 'realm', t.extractfile(candidates[0]).read())
    if not REALM_CONFIG.exists():
        save(REALM_CONFIG, '[network]\nno_tcp = false\nuse_udp = false\n\n[[endpoints]]\n'
             'listen = "0.0.0.0:%s"\nremote = "%s:%s"\n' % (c['a_port'], c['b_ip'], c['b_port']))
    firewall(c)
    service(REALM_SERVICE, '''[Unit]
Description=WG AB Auto Realm relay
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/local/lib/realm-wgab-auto/realm -c /etc/realm-wgab-auto/config.toml
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
'''.replace('/usr/local/lib/xray-wgab-auto', str(XRAY_DIR)).replace('/etc/xray-wgab-auto/config.json', str(XRAY_CONFIG)).replace('/usr/local/lib/realm-wgab-auto', str(REALM_DIR)).replace('/etc/realm-wgab-auto/config.toml', str(REALM_CONFIG)), force_restart=changed)
    print('A：realm 已运行；既有配置已保留。', flush=True)


def ss_outbound(c, credentials, address):
    return {'tag': 'landing-ss', 'protocol': 'shadowsocks', 'settings': {
        'address': address, 'port': c['b_port'], 'method': credentials['method'], 'password': credentials['password']}}


def check_chain_credentials(config, credentials):
    outbounds = config.get('outbounds', [])
    if len(outbounds) != 1 or outbounds[0].get('protocol') != 'shadowsocks' or outbounds[0].get('tag') != 'landing-ss':
        raise RuntimeError('本次 VLESS 入口的 SS 出站配置不符合预期。')
    if any(outbounds[0].get('settings', {}).get(k) != credentials[k] for k in ('method', 'password')):
        raise RuntimeError('两端 SS 认证信息不一致，已停止，保留原入口配置。')


def ss_server_config(c, credentials):
    return {'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '0.0.0.0', 'port': c['b_port'], 'protocol': 'shadowsocks',
                          'settings': dict(credentials, network='tcp,udp')}],
            'outbounds': [{'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}}]}


def install_b(c):
    if c.get('architecture') != 'vless_ss':
        return install_vless(c)
    if c['role'] != 'B':
        raise RuntimeError('SS 落地必须安装在 B。')
    changed = prepare_xray()
    secret_file = ROOT / 'ss-credentials.json'
    if not secret_file.exists():
        if XRAY_CONFIG.exists():
            raise RuntimeError('已有 SS 配置缺少认证记录，停止以免替换密码。')
        save(secret_file, json.dumps({'method': '2022-blake3-aes-128-gcm',
                                     'password': base64.b64encode(secrets.token_bytes(16)).decode()}))
    credentials = json.loads(secret_file.read_text())
    expected = ss_server_config(c, credentials)
    if XRAY_CONFIG.exists():
        if json.loads(XRAY_CONFIG.read_text()) != expected:
            raise RuntimeError('本次 SS 落地配置与运行记录不一致，保留原配置。')
    else:
        save(XRAY_CONFIG, json.dumps(expected, indent=2) + '\n', 0o640)
    activate_xray(c, changed)
    print('B：Shadowsocks 已运行。', flush=True)


def switch_ss_target(c, address):
    if c['role'] != 'A' or c.get('architecture') != 'vless_ss':
        raise RuntimeError('SS 出站切换仅适用于 VLESS → SS 的 A 端。')
    ipaddress.IPv4Address(address)
    old = XRAY_CONFIG.read_text()
    config = json.loads(old)
    check_chain_credentials(config, json.loads((ROOT / 'ss-credentials.json').read_text()))
    settings = config['outbounds'][0]['settings']
    if settings['port'] != c['b_port']:
        raise RuntimeError('SS 目标端口与本次配置不一致。')
    if settings['address'] == address:
        run(['systemctl', 'is-active', '--quiet', XRAY_SERVICE])
        return
    settings['address'] = address
    candidate = XRAY_CONFIG.with_suffix('.candidate.json')
    try:
        save(candidate, json.dumps(config, indent=2) + '\n', 0o640)
        run([str(XRAY_DIR / 'xray'), 'run', '-test', '-config', str(candidate)], capture=True)
        run(['chown', 'root:xray-wgab-auto', str(candidate)])
        os.replace(candidate, XRAY_CONFIG)
        try:
            run(['systemctl', 'restart', XRAY_SERVICE])
            run(['systemctl', 'is-active', '--quiet', XRAY_SERVICE])
        except Exception:
            save(XRAY_CONFIG, old, 0o640)
            run(['chown', 'root:xray-wgab-auto', str(XRAY_CONFIG)])
            run(['systemctl', 'restart', XRAY_SERVICE])
            raise
    finally:
        candidate.unlink(missing_ok=True)


def test_chain(c, large=False):
    if c['role'] != 'B':
        raise RuntimeError('业务验收在 B 发起，经 A 的公网入口。')
    m = json.loads((ROOT / 'client-meta.json').read_text())
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    config = {'log': {'loglevel': 'error'},
              'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
              'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': c['a_ip'], 'port': c['a_port'],
                  'users': [{'id': m['id'], 'encryption': 'none', 'flow': m['flow']}]}]},
                  'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                      'serverName': m['serverName'], 'fingerprint': 'chrome', 'publicKey': m['publicKey'], 'shortId': m['shortId']}}}]}
    test_file = ROOT / 'test-client.json'
    save(test_file, json.dumps(config))
    proc = subprocess.Popen([str(XRAY_DIR / 'xray'), 'run', '-config', str(test_file)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        if proc.poll() is not None:
            raise RuntimeError('测试客户端未能启动。')
        targets = [('出口 IP', 'https://api.ipify.org'), ('HTTPS', 'https://addons.mozilla.org/')]
        if large:
            targets.append(('文件下载', 'https://github.com/zhboner/realm/releases/download/v2.9.6/realm-x86_64-unknown-linux-musl.tar.gz'))
        for name, url in targets:
            good = False
            for attempt in range(1, 4):
                args = ['curl', '-fLsS', '--connect-timeout', '15', '--max-time', '30', '--proxy',
                        'socks5h://127.0.0.1:' + str(port), url]
                download_file = ROOT / 'test-download.bin'
                if name == '文件下载':
                    args += ['-o', str(download_file)]
                p = run(args, capture=True, check=False, timeout=40)
                good = p.returncode == 0
                if name == '出口 IP':
                    good = good and p.stdout.strip() == c['b_ip']
                elif name == 'HTTPS':
                    good = good and len(p.stdout) > 1000
                else:
                    good = good and download_file.exists() and hashlib.sha256(download_file.read_bytes()).hexdigest() == REALM_SHA
                    download_file.unlink(missing_ok=True)
                if good:
                    print(name + '：通过（第 ' + str(attempt) + ' 次，出口 B）', flush=True)
                    break
                print(name + '：第 ' + str(attempt) + ' 次未通过，检查/重试。', flush=True)
            if not good:
                raise RuntimeError(name + '验证失败；不将当前链路标为成功。')
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        test_file.unlink(missing_ok=True)
        (ROOT / 'test-download.bin').unlink(missing_ok=True)


def temporary_key(c):
    if c['role'] != 'A':
        raise RuntimeError('临时部署密钥只能在 A 生成。')
    key = ROOT / 'deploy-key'
    if key.exists():
        public = run(['ssh-keygen', '-y', '-f', str(key)], capture=True).stdout.strip()
        save(ROOT / 'deploy-key.pub', public + ' wg-ab-auto-temporary\n')
    else:
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'wg-ab-auto-temporary', '-f', str(key)])
    print('临时部署密钥已就绪。', flush=True)


def authorize(c):
    if c['role'] != 'B':
        raise RuntimeError('角色错误。')
    line = (ROOT / 'authorized-line').read_text().strip()
    if not line.startswith('from="' + c['a_ip'] + '",restrict ssh-ed25519 '):
        raise RuntimeError('临时公钥来源限制不正确。')
    ssh_dir = Path('/root/.ssh')
    if ssh_dir.is_symlink() or (ssh_dir / 'authorized_keys').is_symlink():
        raise RuntimeError('root SSH 目录/公钥文件是符号链接，停止以保留原有管理方式。')
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    p = ssh_dir / 'authorized_keys'
    old = p.read_text() if p.exists() else ''
    if line not in old.splitlines():
        save(p, old + ('\n' if old and not old.endswith('\n') else '') + line + '\n')
    print('B：已添加只允许 A 使用的临时 SSH 公钥。', flush=True)


def cleanup(c):
    if c['role'] == 'B':
        line_file = ROOT / 'authorized-line'
        p = Path('/root/.ssh/authorized_keys')
        if line_file.exists() and p.exists():
            line = line_file.read_text().strip()
            old = p.read_text()
            save(p, ''.join(s for s in old.splitlines(keepends=True) if s.strip() != line))
            line_file.unlink()
        (ROOT / 'test-client.json').unlink(missing_ok=True)
        if c.get('architecture') == 'vless_ss':
            (ROOT / 'client-meta.json').unlink(missing_ok=True)
    else:
        for name in ['deploy-key', 'deploy-key.pub', 'ssh-wrapper/ssh', 'b-known-hosts']:
            (ROOT / name).unlink(missing_ok=True)
    for name in ['pair-code', 'peer-code', 'excluded-subnets.json', 'test-download.bin']:
        (ROOT / name).unlink(missing_ok=True)
    print(c['role'] + '：临时部署凭据已清理。', flush=True)


def adapted_wg(c):
    if hashlib.sha256(WG_SCRIPT.read_bytes()).hexdigest() != WG_SHA:
        raise RuntimeError('WG 脚本校验失败。')
    source = WG_SCRIPT.read_text()
    if source.count('SELF_TARGET="/usr/local/sbin/wg-multi-relay"') != 1:
        raise RuntimeError('WG 管理命令路径不符合预期。')
    target = '/usr/local/sbin/wg-multi-relay-' + c.get('instance', 'abauto')
    source = source.replace('SELF_TARGET="/usr/local/sbin/wg-multi-relay"', 'SELF_TARGET="' + target + '"')
    adapted = ROOT / 'wg-adapted.sh'
    save(adapted, source, 0o700)
    save(target, source, 0o700)
    return str(adapted)


def wg_subnets(c):
    if c['role'] != 'A':
        raise RuntimeError('网段检查应在 A 执行。')
    script = adapted_wg(c)
    # Read the exact upstream planner to avoid collisions with other interfaces/routes.
    result = run(['bash', '-c', 'source ' + shlex.quote(script) + '; used_subnet_indexes ' + shlex.quote(IFACE)], capture=True)
    excluded = result.stdout.strip()
    if excluded and not re.fullmatch(r'[0-9, ]+', excluded):
        raise RuntimeError('无法读取已用网段。')
    print(json.dumps({'exclude': excluded}), flush=True)


def wg_plan(c):
    if c['role'] != 'B':
        raise RuntimeError('落地规划应在 B 执行。')
    excluded = json.loads((ROOT / 'excluded-subnets.json').read_text())['exclude']
    if excluded and not re.fullmatch(r'[0-9, ]+', excluded):
        raise RuntimeError('网段列表无效。')
    args = ['bash', adapted_wg(c), 'landing-plan', c.get('instance', 'abauto'), str(c['b_port']), c['b_ip'], '--mtu', str(c['mtu'])]
    if excluded:
        args += ['--exclude-subnets', excluded]
    run(args)


def wg_relay(c):
    if c['role'] != 'A':
        raise RuntimeError('中转安装应在 A 执行。')
    run(['bash', adapted_wg(c), 'relay-install', (ROOT / 'pair-code').read_text().strip(), c['a_ip']])


def wg_activate(c):
    if c['role'] != 'B':
        raise RuntimeError('落地激活应在 B 执行。')
    # This SSH connection originates at the panel, so never infer A from SSH_CONNECTION.
    run(['bash', adapted_wg(c), 'landing-activate', (ROOT / 'peer-code').read_text().strip(), '--auto', '--keep-relay-ip', '--no-wait'])


def deploy_wg(c):
    if c['role'] != 'A':
        raise RuntimeError('切换入口应在 A 执行。')
    adapted = adapted_wg(c)
    run(['bash', '-c', 'source ' + shlex.quote(adapted) + '; wait_for_handshake ' + shlex.quote(IFACE) + ' 60'], timeout=75)
    run(['bash', adapted, 'status', IFACE])
    pair_data = Path('/etc/wireguard/' + IFACE + '.pair').read_text()
    if c.get('architecture') == 'vless_ss':
        fields = dict(line.split('=', 1) for line in pair_data.splitlines() if '=' in line)
        if fields.get('LANDING_ENDPOINT') != c['b_ip'] or fields.get('SERVICE_PORT') != str(c['b_port']):
            raise RuntimeError('WG 对端与 SS 落地不一致。')
        target = str(ipaddress.IPv4Address(fields['LANDING_IP']))
        test = 'source ' + shlex.quote(adapted) + '; run_tcp_test ' + shlex.quote(target) + ' ' + str(c['b_port']) + ' 100'
        run(['bash', '-c', test], timeout=300)
        switch_ss_target(c, target)
        print('A：SS 出站已切换到 B 的 WG 隧道地址。', flush=True)
        return
    code = base64.b64encode(pair_data.encode()).decode('ascii')
    run(['bash', adapted, 'realm-cutover', code, str(REALM_CONFIG), REALM_SERVICE, str(c['a_port'])])


def rollback(c):
    if c.get('architecture') == 'vless_ss':
        switch_ss_target(c, c['b_ip'])
        print('已恢复 VLESS → SS 公网路径。', flush=True)
        return
    if c['role'] != 'A':
        raise RuntimeError('回滚只能在 A 执行。')
    command = '/usr/local/sbin/wg-multi-relay-' + c.get('instance', 'abauto')
    state = Path('/root/wg-multi-relay/' + IFACE + '/realm.state')
    if state.exists():
        run([command, 'realm-rollback', IFACE])
        print('已恢复 A → B 公网转发。', flush=True)
    else:
        # A failure during the cutover may predate upstream realm.state creation.
        # The service/config are exclusive to this controller: restore its one public rule.
        save(REALM_CONFIG, '[network]\nno_tcp = false\nuse_udp = false\n\n[[endpoints]]\n'
             'listen = "0.0.0.0:%s"\nremote = "%s:%s"\n' % (c['a_port'], c['b_ip'], c['b_port']))
        run(['systemctl', 'restart', REALM_SERVICE])
        run(['systemctl', 'is-active', '--quiet', REALM_SERVICE])
        print('已恢复本次部署的公网转发规则。', flush=True)


def main():
    action = sys.argv[1]
    configure_paths()
    c = settings()
    actions = {'init': lambda x: print('部署记录已确认。'), 'install-b': install_b,
               'install-a': install_a, 'test': test_chain, 'test-final': lambda x: test_chain(x, True),
               'key': temporary_key, 'authorize': authorize, 'cleanup': cleanup,
               'wg': deploy_wg, 'wg-subnets': wg_subnets, 'wg-plan': wg_plan,
               'wg-relay': wg_relay, 'wg-activate': wg_activate, 'rollback': rollback,
               'public-path': lambda x: switch_ss_target(x, x['b_ip'])}
    actions[action](c)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Never include complete subprocess arguments or key-generating command output.
        print('失败：' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
