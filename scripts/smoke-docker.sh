#!/usr/bin/env bash
set -euo pipefail
image=${1:?Usage: smoke-docker.sh IMAGE}
container=nodectl-wg-smoke
port=17878
cleanup() { docker rm -fv "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run --rm --entrypoint python3 "$image" -c 'import sys,paramiko; assert sys.version_info >= (3,10); print("WG runtime:", paramiko.__version__)'
docker run -d --init --name "$container" -p "127.0.0.1:${port}:8080" "$image" >/dev/null
python3 - "$port" "$container" <<'PY'
import base64,hashlib,http.cookiejar,json,re,subprocess,sys,time,urllib.parse,urllib.request,urllib.error
base='http://127.0.0.1:'+sys.argv[1]
for _ in range(90):
    try:
        with urllib.request.urlopen(base+'/login',timeout=2) as response:
            assert response.status==200
            break
    except (OSError,AssertionError): time.sleep(1)
else: raise SystemExit('Panel did not become ready')
cookies=http.cookiejar.CookieJar()
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
password=subprocess.check_output(['docker','exec',sys.argv[2],'cat','/app/data/initial-admin-password'],text=True).rstrip('\n')
assert len(password)>=12 and password!='admin', 'Missing random initial password'
login=urllib.parse.urlencode({'username':'admin','password':password}).encode()
with client.open(base+'/login',login,timeout=10) as response:
    page=response.read().decode()
assert any(c.name=='nodectl_token' for c in cookies), 'No authenticated session'
assert 'wgRelayModal' in page and 'WG 中转' in page, 'WG UI absent'
scripts=re.findall(r'<script\b[^>]*\bsrc="([^"]+)"[^>]*\bintegrity="([^"]+)"',page)
assert len(scripts)==2, 'Bundled browser libraries absent'
for src,integrity in scripts:
    assert src.startswith('/assets/vendor/'), 'External executable dependency'
    with client.open(base+src,timeout=10) as response:
        assert response.headers.get_content_type()=='text/javascript'
        assert response.headers['X-Content-Type-Options']=='nosniff'
        actual='sha384-'+base64.b64encode(hashlib.sha384(response.read()).digest()).decode()
        assert actual==integrity, 'Bundled script integrity mismatch'
with client.open(base+'/api/wg-relay/jobs',timeout=10) as response:
    assert json.load(response)=={'jobs':[]}
# No remote operation is started. Reject a malformed deployment request.
req=urllib.request.Request(base+'/api/wg-relay/start',b'{}',headers={'Content-Type':'application/json','X-NodeCtl-WG':'1'})
try: client.open(req,timeout=10)
except urllib.error.HTTPError as error: assert error.code==400
else: raise AssertionError('Invalid deployment request accepted')
print('Container login, embedded scripts/SRI, WG page, authenticated API, validation and Python runtime passed.')
PY
docker stop --time 65 "$container" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" = 0
