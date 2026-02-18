"""Shared fixtures for Playwright E2E tests."""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
            return True
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"Server on port {port} did not start within {timeout}s")


@pytest.fixture(scope="session")
def test_data_dir():
    """Create an isolated temporary data directory for the test session."""
    tmpdir = tempfile.mkdtemp(prefix="ssl_licence_e2e_")
    data_dir = Path(tmpdir) / "data"

    (data_dir / "products").mkdir(parents=True)
    (data_dir / "domains").mkdir(parents=True)
    (data_dir / "daily_reports").mkdir(parents=True)
    (data_dir / "letsencrypt").mkdir(parents=True)

    (data_dir / "products" / "registry.json").write_text("[]")
    (data_dir / "domains" / "registry.json").write_text("[]")
    (data_dir / "licences.json").write_text("{}")
    (data_dir / "cert_checks.json").write_text("[]")
    (data_dir / "alerts_history.json").write_text("[]")
    (data_dir / "settings.json").write_text("{}")

    yield str(data_dir)
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="session")
def server_port():
    return _find_free_port()


@pytest.fixture(scope="session")
def live_server(test_data_dir, server_port):
    """Start the Flask dev server for E2E tests."""
    env = os.environ.copy()
    env["FLASK_SECRET_KEY"] = "test-e2e-secret"
    env["SSL_LICENCE_DATA_DIR"] = test_data_dir
    env["PYTHONPATH"] = str(PROJECT_ROOT)

    server_script = f"""
import sys, os
sys.path.insert(0, '{PROJECT_ROOT}')
os.environ['SSL_LICENCE_DATA_DIR'] = '{test_data_dir}'
from web import create_app
app = create_app()
app.config['TESTING'] = True
app.run(host='127.0.0.1', port={server_port}, debug=False, use_reloader=False)
"""

    proc = subprocess.Popen(
        [sys.executable, "-c", server_script],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_server(server_port)
    yield f"http://127.0.0.1:{server_port}"

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def base_url(live_server):
    return live_server


@pytest.fixture()
def seeded_product(base_url):
    """Seed a test product via the API."""
    data = json.dumps({
        "name": "Test Product",
        "vendor": "TestVendor",
        "version": "1.0",
        "category": "operating_system",
        "licence_type": "subscription",
        "annual_cost": 1200.0,
        "environment": "production",
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/api/v1/products",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())


@pytest.fixture()
def seeded_domain(base_url):
    """Seed a test domain via the API."""
    data = json.dumps({
        "hostname": f"test-{int(time.time() * 1000)}.example.com",
        "notes": "E2E test domain",
        "warning_days": 30,
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/api/v1/domains",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())


@pytest.fixture()
def seeded_licence(base_url):
    """Seed a test licence via the API."""
    data = json.dumps({
        "licence_type": "standard",
        "issued_to": "E2E Test User",
        "valid_days": 365,
        "max_users": 5,
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/api/v1/licences",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())
