"""No SSH/network calls. Verify the supplied engine's acceptance and rollback rules."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ENGINE = Path(__file__).resolve().parents[1] / 'internal/wgrelay/engine'
sys.path.insert(0, str(ENGINE))
import deploy
import remote_worker

class Host:
    def __init__(self, role):
        self.role = role
        self.ip = '8.8.8.8' if role == 'A' else '1.1.1.1'
        self.port = 22
        self.root = '/example/' + role
        self.iface = 'wg-stest'
        self.suffix = 'sr-stest'
        self.instance = 's0123456789'
        self.events = []
        self.fail = None
    def setup(self, pair): self.events.append('setup')
    def worker(self, action):
        self.events.append(action)
        if action == self.fail: raise RuntimeError('injected failure')
        return '{}'
    def put_text(self, path, content): self.events.append('put')
    def read(self, path): return '{"id":"test-client"}'
    def command(self, command): self.events.append('verify-service')

class EngineTests(unittest.TestCase):
    def test_conflict_and_udp_port_rejected(self):
        a, b = Host('A'), Host('B')
        pa = dict(ports=[], udp_ports=[], state=None, conflicts=[])
        pb = dict(pa, ports=[443])
        with self.assertRaisesRegex(RuntimeError, '占用'):
            deploy.build_pair(a,b,pa,pb,'addons.mozilla.org',1280,443,443)
        pb = dict(pa, udp_ports=[443])
        with self.assertRaisesRegex(RuntimeError, 'UDP'):
            deploy.build_pair(a,b,pa,pb,'addons.mozilla.org',1280,443,443,'vless_ss')
        pb = dict(pa, conflicts=['unowned-service'])
        with self.assertRaisesRegex(RuntimeError, '无归属'):
            deploy.build_pair(a,b,pa,pb,'addons.mozilla.org',1280,443,443)

    def test_different_ports_and_modes_use_different_instances(self):
        a,b=Host('A'),Host('B')
        ids={deploy.instance_id(a,b,443,443),deploy.instance_id(a,b,444,443),deploy.instance_id(a,b,443,443,'vless_ss')}
        self.assertEqual(3,len(ids))

    def test_success_requires_final_business_validation_for_both_modes(self):
        for architecture in ('realm','vless_ss'):
            a,b=Host('A'),Host('B')
            pair=dict(architecture=architecture,a_port=443)
            with patch.object(deploy,'deploy_wg_pair') as wg, patch.object(deploy.socket,'create_connection',return_value=contextlib.nullcontext()), contextlib.redirect_stdout(io.StringIO()):
                result=deploy.apply_deployment(a,b,pair)
            self.assertEqual('test-client',result['id'])
            self.assertIn('test-final',b.events)
            self.assertIn('verify-service',a.events)
            self.assertIn('verify-service',b.events)
            self.assertEqual('cleanup',a.events[-1])
            self.assertEqual('cleanup',b.events[-1])
            wg.assert_called_once()

    def test_final_failure_rolls_back_and_never_returns_success(self):
        a,b=Host('A'),Host('B');b.fail='test-final'
        with patch.object(deploy,'deploy_wg_pair'), patch.object(deploy,'diagnose_wg'), patch.object(deploy.socket,'create_connection',return_value=contextlib.nullcontext()), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'injected failure'):
                deploy.apply_deployment(a,b,dict(a_port=443))
        self.assertIn('rollback',a.events)
        self.assertEqual(2,b.events.count('test'))
        self.assertEqual('cleanup',a.events[-1])

    def test_precheck_does_not_claim_tunnel_exists(self):
        r=deploy.interpret_wg_diagnostics({}, {}, {})
        self.assertFalse(r['ok']);self.assertFalse(r['established'])

    def test_export_both_modes_as_vless(self):
        meta=dict(id='test-id',serverName='addons.mozilla.org',publicKey='public',shortId='1234',flow='xtls-rprx-vision')
        for architecture in ('realm','vless_ss'):
            with tempfile.TemporaryDirectory() as tmp, patch.object(deploy,'BASE',Path(tmp)):
                p=deploy.export_result(dict(architecture=architecture,a_ip='8.8.8.8',b_ip='1.1.1.1',a_port=443,instance='s0123456789'),meta)
                self.assertTrue((p/'VLESS.txt').read_text().startswith('vless://test-id@8.8.8.8:443?'))
                self.assertEqual('verified',json.loads((p/'result.json').read_text())['status'])

    def test_embedded_shell_hash_matches_both_callers(self):
        digest=hashlib.sha256((ENGINE/'vendor/wg-multi-relay.sh').read_bytes()).hexdigest()
        self.assertEqual(deploy.WG_SHA,digest)
        self.assertEqual(remote_worker.WG_SHA,digest)

if __name__=='__main__': unittest.main()
