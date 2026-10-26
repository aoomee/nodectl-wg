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
python3 - "$port" <<'PY'
import http.cookiejar,json,sys,time,urllib.request,urllib.error
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
with client.open(base+'/login',b'username=admin&password=admin',timeout=10) as response:
    page=response.read().decode()
assert any(c.name=='nodectl_token' for c in cookies), 'No authenticated session'
assert 'wgRelayModal' in page and 'WG 中转' in page, 'WG UI absent'
with client.open(base+'/api/wg-relay/jobs',timeout=10) as response:
    assert json.load(response)=={'jobs':[]}
# No remote operation is started. Reject a malformed deployment request.
req=urllib.request.Request(base+'/api/wg-relay/start',b'{}',headers={'Content-Type':'application/json','X-NodeCtl-WG':'1'})
try: client.open(req,timeout=10)
except urllib.error.HTTPError as error: assert error.code==400
else: raise AssertionError('Invalid deployment request accepted')
print('Container login, WG page, authenticated API, validation and Python runtime passed.')
PY
docker stop --time 65 "$container" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" = 0
