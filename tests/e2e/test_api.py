"""Test REST API endpoints via Playwright's request context."""

import json
import time


def test_api_health(page, base_url):
    """Health endpoint returns JSON."""
    resp = page.request.get(f"{base_url}/health")
    assert resp.status == 200
    data = resp.json()
    assert data["status"] == "healthy"


def test_api_list_products(page, base_url):
    """API: list products returns JSON array."""
    resp = page.request.get(f"{base_url}/api/v1/products")
    assert resp.status == 200
    assert isinstance(resp.json(), list)


def test_api_add_product(page, base_url):
    """API: add product returns 201."""
    resp = page.request.post(
        f"{base_url}/api/v1/products",
        data=json.dumps({
            "name": "API Test Product",
            "vendor": "APIVendor",
            "version": "3.0",
            "category": "operating_system",
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 201
    data = resp.json()
    assert data["name"] == "API Test Product"


def test_api_get_product_not_found(page, base_url):
    """API: get nonexistent product returns 404."""
    resp = page.request.get(f"{base_url}/api/v1/products/nonexistent-id")
    assert resp.status == 404


def test_api_list_domains(page, base_url):
    """API: list domains returns JSON array."""
    resp = page.request.get(f"{base_url}/api/v1/domains")
    assert resp.status == 200
    assert isinstance(resp.json(), list)


def test_api_add_domain(page, base_url):
    """API: add domain returns 201."""
    resp = page.request.post(
        f"{base_url}/api/v1/domains",
        data=json.dumps({"hostname": f"api-{int(time.time() * 1000)}.example.com"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 201


def test_api_list_alerts(page, base_url):
    """API: list alerts returns JSON array."""
    resp = page.request.get(f"{base_url}/api/v1/alerts")
    assert resp.status == 200
    assert isinstance(resp.json(), list)


def test_api_alert_summary(page, base_url):
    """API: alert summary returns JSON with total_alerts."""
    resp = page.request.get(f"{base_url}/api/v1/alerts/summary")
    assert resp.status == 200
    assert "total_alerts" in resp.json()


def test_api_issue_licence(page, base_url):
    """API: issue licence returns 201."""
    resp = page.request.post(
        f"{base_url}/api/v1/licences",
        data=json.dumps({
            "licence_type": "trial",
            "issued_to": "API E2E Test",
            "valid_days": 30,
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 201
    assert "key" in resp.json()


def test_api_validate_licence_invalid(page, base_url):
    """API: validate invalid licence key."""
    resp = page.request.post(
        f"{base_url}/api/v1/licences/validate",
        data=json.dumps({"key": "bogus-key"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 200
    assert resp.json()["is_valid"] is False


def test_api_certificates_history(page, base_url):
    """API: certificate history returns JSON array."""
    resp = page.request.get(f"{base_url}/api/v1/certificates/history")
    assert resp.status == 200
    assert isinstance(resp.json(), list)


def test_api_missing_required_fields(page, base_url):
    """API: missing required fields return 400."""
    resp = page.request.post(
        f"{base_url}/api/v1/products",
        data=json.dumps({"name": "Incomplete"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 400
    assert "error" in resp.json()
