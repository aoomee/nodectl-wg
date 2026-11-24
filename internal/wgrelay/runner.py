"""One isolated process per job. SSH passwords arrive through stdin only."""
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sys

import paramiko

sys.path.insert(0, str(Path(__file__).parent / 'engine'))
import deploy as engine

os.umask(0o077)


def interrupted(*_):
    raise KeyboardInterrupt()


def run():
    signal.signal(signal.SIGTERM, interrupted)
    request = json.load(sys.stdin)
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    source = Path(__file__).parent / 'engine'
    shutil.copyfile(source / 'remote_worker.py', folder / 'remote_worker.py')
    (folder / 'vendor').mkdir(exist_ok=True)
    shutil.copyfile(source / 'vendor/wg-multi-relay.sh', folder / 'vendor/wg-multi-relay.sh')
    known = folder.parent.parent / 'hosts' / 'known_hosts'
    known.parent.mkdir(exist_ok=True, mode=0o700)
    if known.exists():
        shutil.copyfile(known, folder / '.known_hosts')
    engine.BASE = folder
    a = engine.Host('A', request['a_ip'], request['a_ssh'], request.get('a_username', 'root'))
    b = engine.Host('B', request['b_ip'], request['b_ssh'], request.get('b_username', 'root'))
    try:
        print('正在连接 A 中转机…', flush=True)
        a.connect(password=request.pop('a_password'))
        print('正在连接 B 落地机…', flush=True)
        b.connect(via=a, password=request.pop('b_password'))
        if a.client.get_transport().get_remote_server_key().asbytes() == b.client.get_transport().get_remote_server_key().asbytes():
            raise RuntimeError('两台服务器的 SSH 指纹相同，请检查 IP。')
        if request['mode'] == 'deploy':
            a.acquire_lock()
            b.acquire_lock()
        engine.configure_pair(a, b, request['a_port'], request['b_port'], request.get('architecture', 'realm'))
        pa, pb = a.probe(), b.probe()
        pair = engine.build_pair(a, b, pa, pb, request['sni'], request['mtu'], request['a_port'], request['b_port'], request.get('architecture', 'realm'))
        if request['mode'] == 'check':
            report = engine.diagnose_wg(a, b, pair)
            result = {'kind': 'check', 'pair': pair, 'diagnostics': report}
            print('SSH、系统和业务端口检查通过；WG 诊断结果见上方。', flush=True)
        else:
            meta = engine.apply_deployment(a, b, pair)
            exported = engine.export_result(pair, meta)
            result = {'kind': 'deploy', 'pair': pair, 'link': (exported / 'VLESS.txt').read_text().strip()}
            print('部署和本次业务验证通过。请导入后在自己的网络中确认使用。', flush=True)
        (folder / 'result.json').write_text(json.dumps(result, ensure_ascii=False))
    finally:
        for host in (b, a):
            try:
                host.close()
            except Exception:
                pass
        if (folder / '.known_hosts').exists():
            tmp_known = known.with_name(known.name + '.tmp-' + secrets.token_hex(4))
            try:
                shutil.copyfile(folder / '.known_hosts', tmp_known)
                tmp_known.chmod(0o600)
                os.replace(tmp_known, known)
            finally:
                tmp_known.unlink(missing_ok=True)
        request.clear()


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        print('任务已中断，已尝试停止远程操作及清理临时凭据；重试前请确认服务器状态。', flush=True)
        sys.exit(130)
    except paramiko.AuthenticationException:
        print('SSH 登录失败：请确认用户名、密码、SSH 端口及服务器是否允许密码登录。', flush=True)
        sys.exit(1)
    except paramiko.BadHostKeyException:
        print('SSH 指纹与已记录的指纹不同，已停止连接。请核实服务器是否重装过系统后再更新主机记录。', flush=True)
        sys.exit(1)
    except paramiko.ssh_exception.NoValidConnectionsError:
        print('无法建立 SSH TCP 连接：请检查服务器公网 IP、SSH 端口及云安全组/防火墙放行规则。', flush=True)
        sys.exit(1)
    except (socket.timeout, TimeoutError):
        print('SSH 连接或操作超时：请检查服务器网络连通性、SSH 端口和防火墙状态后重试。', flush=True)
        sys.exit(1)
    except Exception as exc:
        print('未完成：' + type(exc).__name__ + '：' + str(exc), flush=True)
        sys.exit(1)
