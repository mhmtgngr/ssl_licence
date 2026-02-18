"""Test Settings management."""

import re


def test_settings_page_loads(page, base_url):
    """Settings page loads with tabs."""
    response = page.goto(f"{base_url}/settings")
    assert response.status == 200
    assert "Settings" in page.title()


def test_settings_tabs_present(page, base_url):
    """All three settings tabs are present."""
    page.goto(f"{base_url}/settings")
    assert page.locator("button:has-text('Azure DNS')").is_visible()
    assert page.locator("button:has-text(\"Let's Encrypt\")").is_visible()
    assert page.locator("button:has-text('Alert Settings')").is_visible()


def test_settings_azure_dns_form(page, base_url):
    """Azure DNS form fields are present."""
    page.goto(f"{base_url}/settings")
    assert page.locator("input[name='tenant_id']").is_visible()
    assert page.locator("input[name='subscription_id']").is_visible()


def test_settings_save_azure_dns(page, base_url):
    """Save Azure DNS settings."""
    page.goto(f"{base_url}/settings")
    page.fill("input[name='tenant_id']", "test-tenant-id")
    page.fill("input[name='subscription_id']", "test-sub-id")
    page.fill("input[name='client_id']", "test-client-id")
    page.fill("input[name='client_secret']", "test-secret")
    page.fill("input[name='resource_group']", "test-rg")

    # Click the Save button in the azure-dns tab
    page.locator("#azure-dns button[type='submit']:has-text('Save')").click()
    page.wait_for_url(re.compile(r"/settings"), timeout=10000)


def test_settings_letsencrypt_tab(page, base_url):
    """Switch to Let's Encrypt tab and verify form."""
    page.goto(f"{base_url}/settings")
    page.click("button:has-text(\"Let's Encrypt\")")
    page.wait_for_selector("#letsencrypt.show", state="visible", timeout=3000)
    assert page.locator("input[name='email']").is_visible()


def test_settings_alerts_tab(page, base_url):
    """Switch to Alert Settings tab and verify form."""
    page.goto(f"{base_url}/settings")
    page.click("button:has-text('Alert Settings')")
    page.wait_for_selector("#alert-settings.show", state="visible", timeout=3000)
    assert page.locator("input[name='ssl_warning_days']").is_visible()


def test_settings_save_alert_settings(page, base_url):
    """Save alert settings."""
    page.goto(f"{base_url}/settings")
    page.click("button:has-text('Alert Settings')")
    page.wait_for_selector("#alert-settings.show", state="visible", timeout=3000)
    page.fill("input[name='ssl_warning_days']", "14")
    page.locator("#alert-settings button[type='submit']").click()
    page.wait_for_url(re.compile(r"/settings"), timeout=10000)
