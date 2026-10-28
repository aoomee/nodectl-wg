"""Exercise the shipped Compose service against disposable, isolated data."""

import base64
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def run(*args, env=None, timeout=120, include_stderr=False):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=timeout)
    # Logs, inspect results and password files can contain credentials.
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(args[:2])}")
    return result.stdout + (result.stderr if include_stderr else "")


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar)), jar


def request(opener, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data, headers=headers or {"Content-Type": "application/json"})
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(), response.geturl()


def api(opener, base, path, payload=None, expected=200):
    status, _, body, url = request(opener, base + path, payload)
    assert status == expected and urllib.parse.urlparse(url).path == path, f"API failed: {path} ({status})"
    return json.loads(body)


def login(base, password, accepted=True):
    opener, jar = client()
    form = urllib.parse.urlencode({"username": "admin", "password": password}).encode()
    with opener.open(base + "/login", form, timeout=15) as response:
        page = response.read().decode()
    assert bool(any(c.name == "nodectl_token" for c in jar)) == accepted, "Unexpected login result"
    return opener, jar, page


def check_logs(container, secret_values):
    logs = run("docker", "logs", container, include_stderr=True)
    logs += run("docker", "exec", container, "python3", "-c",
                "from pathlib import Path; print('\\n'.join(p.read_text() for p in Path('/app/data/logs').glob('*.log')))")
    assert all(value not in logs for value in secret_values), "Credentials appeared in container/application logs"


def main(image):
    repo = Path(__file__).resolve().parent.parent
    project = "nodectl-smoke-" + uuid.uuid4().hex[:12]
    work = Path(tempfile.mkdtemp(prefix=project + "-"))
    data = work / "data"
    data.mkdir()
    env = dict(os.environ, NODECTL_IMAGE=image, NODECTL_BIND="127.0.0.1", NODECTL_PORT="0",
               NODECTL_INITIAL_ADMIN_PASSWORD="", NODECTL_TRUSTED_PROXIES="")
    override = work / "test.json"
    override.write_text(json.dumps({"services": {"nodectl": {"volumes": [
        {"type": "bind", "source": str(data), "target": "/app/data"}
    ]}}}))
    compose_args = ("docker", "compose", "--project-name", project, "--env-file", os.devnull,
                    "-f", str(repo / "compose.wg.yaml"), "-f", str(override))

    def compose(*args):
        return run(*compose_args, *args, env=env)

    def inspect(container):
        return json.loads(run("docker", "inspect", container))[0]

    def start():
        compose("up", "-d", "--pull", "never", "--no-build")
        container = compose("ps", "-q", "nodectl").strip()
        info = inspect(container)
        bindings = info["NetworkSettings"]["Ports"]["8080/tcp"]
        assert len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "Backend exposed beyond loopback"
        mounts = [m for m in info["Mounts"] if m["Destination"] == "/app/data"]
        assert len(mounts) == 1 and mounts[0]["Type"] == "bind" and mounts[0]["Source"] == str(data), "Wrong data mount"
        assert info["HostConfig"]["Init"] is True, "Compose init process missing"
        base = "http://127.0.0.1:" + bindings[0]["HostPort"]
        opener, _ = client()
        for _ in range(90):
            if not inspect(container)["State"]["Running"]:
                raise RuntimeError("Panel container exited before readiness")
            try:
                if request(opener, base + "/login")[0] == 200:
                    return container, base
            except OSError:
                pass
            time.sleep(1)
        raise RuntimeError("Panel did not become ready")

    def stop(container):
        compose("stop")
        state = inspect(container)["State"]
        assert state["ExitCode"] == 0 and not state["OOMKilled"], "Container did not shut down cleanly"

    try:
        config = json.loads(compose("config", "--format", "json"))["services"]["nodectl"]
        assert config["image"] == image and config["restart"] == "unless-stopped"
        assert config["logging"]["options"]["max-size"] == "10m"
        assert config["logging"]["options"]["max-file"] == "3"
        run("docker", "run", "--rm", "--pull", "never", "--entrypoint", "python3", image, "-c",
            "import sys,paramiko; assert sys.version_info >= (3,10); assert paramiko.__version__ == '5.1.0'")
        print("PASS: Compose configuration and Python/Paramiko runtime", flush=True)

        container, base = start()
        initial = run("docker", "exec", container, "cat", "/app/data/initial-admin-password").rstrip("\n")
        assert len(initial) >= 12 and initial != "admin", "Missing random initial password"
        run("docker", "exec", container, "python3", "-c",
            "import os,stat; assert stat.S_IMODE(os.stat('/app/data/initial-admin-password').st_mode) == 0o600")
        anonymous, _ = client()
        assert urllib.parse.urlparse(request(anonymous, base + "/api/get-settings")[3]).path == "/login"
        login(base, "admin", accepted=False)
        session, _, page = login(base, initial)
        assert "wgRelayModal" in page and "WG 中转" in page, "WG UI absent"
        assert all(marker not in page for marker in ("hobin66/nodectl", "openUpdateModal", "checkForAppUpdate", "updateArrowIcon")), "Removed upstream updater returned"
        scripts = re.findall(r'<script\b[^>]*\bsrc="([^"]+)"[^>]*\bintegrity="([^"]+)"', page)
        assert len(scripts) == 2, "Bundled browser libraries absent"
        for src, integrity in scripts:
            assert src.startswith("/assets/vendor/"), "External executable dependency"
            status, headers, body, _ = request(session, base + src)
            assert status == 200 and headers.get_content_type() == "text/javascript"
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert "sha384-" + base64.b64encode(hashlib.sha384(body).digest()).decode() == integrity
        assert api(session, base, "/api/wg-relay/jobs") == {"jobs": []}
        status, _, _, _ = request(session, base + "/api/wg-relay/start", {},
                                  {"Content-Type": "application/json", "X-NodeCtl-WG": "1"})
        assert status == 400, "Invalid remote deployment request accepted"
        print("PASS: private initial password, authentication, embedded assets and WG API", flush=True)

        saved = {"sub_custom_name": "Docker persistence " + uuid.uuid4().hex,
                 "sub_token": secrets.token_hex(24), "proxy_socks5_pass": secrets.token_hex(24)}
        assert api(session, base, "/api/update-settings", saved)["status"] == "success"
        invalid = api(session, base, "/api/update-settings",
                      {"sub_custom_name": "must-not-persist", "login_ip_max_retries": "0"}, expected=400)
        assert invalid["status"] == "error"
        stored = api(session, base, "/api/get-settings")["data"]
        assert all(stored[k] == v for k, v in saved.items())
        password = secrets.token_urlsafe(24)
        assert api(session, base, "/api/change-password", {
            "old_username": "admin", "new_username": "admin", "old_password": initial,
            "new_password": password, "confirm_password": password})["status"] == "success"
        assert urllib.parse.urlparse(request(session, base + "/api/get-settings")[3]).path == "/login", "Old session survived rotation"
        login(base, initial, accepted=False)
        login(base, password)
        run("docker", "exec", container, "test", "!", "-e", "/app/data/initial-admin-password")
        secret_values = [initial, password, saved["sub_token"], saved["proxy_socks5_pass"]]
        check_logs(container, secret_values)
        stop(container)
        compose("rm", "-f", "nodectl")
        print("PASS: settings rollback, password rotation, credential-free logs and graceful stop", flush=True)

        # Existing data must survive replacement and take precedence over a new
        # bootstrap password supplied in the deployment environment.
        env["NODECTL_INITIAL_ADMIN_PASSWORD"] = secrets.token_urlsafe(24)
        second, base = start()
        assert second != container, "Container was not recreated"
        login(base, env["NODECTL_INITIAL_ADMIN_PASSWORD"], accepted=False)
        session, _, _ = login(base, password)
        stored = api(session, base, "/api/get-settings")["data"]
        assert all(stored[k] == v for k, v in saved.items()), "Recreation lost saved settings"
        run("docker", "exec", second, "test", "!", "-e", "/app/data/initial-admin-password")
        run("docker", "exec", second, "python3", "-c",
            "import sqlite3; c=sqlite3.connect('file:/app/data/nodectl.db?mode=ro',uri=True); "
            "assert c.execute('PRAGMA integrity_check').fetchall() == [('ok',)]")
        check_logs(second, secret_values + [env["NODECTL_INITIAL_ADMIN_PASSWORD"]])
        stop(second)
        print("PASS: recreated container retains password/settings, ignores bootstrap override and has intact SQLite data", flush=True)
    finally:
        try:
            compose("down", "--volumes", "--remove-orphans")
        finally:
            # Delete only this run's disposable bind data; container-created
            # files are root-owned on Linux and cannot be removed by the runner.
            run("docker", "run", "--rm", "--pull", "never", "--entrypoint", "python3",
                "--mount", f"type=bind,src={data},dst=/smoke-data", image, "-c",
                "from pathlib import Path; import shutil; "
                "[(shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()) for p in Path('/smoke-data').iterdir()]")
            shutil.rmtree(work)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: smoke-docker.py IMAGE")
    try:
        main(sys.argv[1])
    except Exception as error:
        raise SystemExit(f"Docker smoke failed: {error}") from None
