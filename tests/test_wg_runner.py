"""Exercise the stdin -> engine -> result adapter without opening SSH sockets."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / 'internal/wgrelay'
spec = importlib.util.spec_from_file_location('wg_runner', ROOT/'runner.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class FakeHost:
    def __init__(self, role, ip, port, username):
        self.role,self.ip,self.port,self.username=role,ip,port,username
        self.client=types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(get_remote_server_key=lambda: types.SimpleNamespace(asbytes=lambda: role.encode())))
    def connect(self, **kwargs):
        assert kwargs['password'].startswith('private-')
    def acquire_lock(self): pass
    def probe(self): return {}
    def close(self): pass

class RunnerTests(unittest.TestCase):
    def test_check_and_deploy_result_contract_without_credentials(self):
        for mode in ('check','deploy'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);folder=root/'jobs'/'example';folder.parent.mkdir()
                payload=dict(mode=mode,architecture='realm',a_ip='8.8.8.8',b_ip='1.1.1.1',a_ssh=22,b_ssh=22,a_port=443,b_port=443,a_password='private-a',b_password='private-b',sni='addons.mozilla.org',mtu=1280)
                export=root/'export';export.mkdir();(export/'VLESS.txt').write_text('vless://verified')
                with patch.object(sys,'stdin',io.StringIO(json.dumps(payload))),patch.object(sys,'argv',['runner.py',str(folder)]),patch.object(runner.signal,'signal'),patch.object(runner.engine,'Host',FakeHost),patch.object(runner.engine,'BASE',root),patch.object(runner.engine,'configure_pair'),patch.object(runner.engine,'build_pair',return_value={'instance':'stest'}),patch.object(runner.engine,'diagnose_wg',return_value={'ok':False,'established':False}),patch.object(runner.engine,'apply_deployment',return_value={}),patch.object(runner.engine,'export_result',return_value=export),contextlib.redirect_stdout(io.StringIO()):
                    runner.run()
                result=json.loads((folder/'result.json').read_text())
                self.assertEqual(mode,result['kind'])
                self.assertEqual(mode=='deploy','link' in result)
                for p in folder.rglob('*'):
                    if p.is_file(): self.assertNotIn('private-',p.read_text())
                self.assertTrue((root/'hosts').is_dir())

if __name__=='__main__': unittest.main()
