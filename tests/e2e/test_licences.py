"""Test Licence CRUD operations."""

import re


def test_licences_list_page_loads(page, base_url):
    """Licences list page loads."""
    response = page.goto(f"{base_url}/licences")
    assert response.status == 200
    assert "Licences" in page.title()


def test_licences_issue_page_loads(page, base_url):
    """Issue licence form page loads."""
    page.goto(f"{base_url}/licences/issue")
    assert page.locator("input[name='issued_to']").is_visible()
    assert page.locator("select[name='licence_type']").is_visible()


def test_licences_issue_and_verify(page, base_url):
    """Issue a licence via the form and verify it appears in the list."""
    page.goto(f"{base_url}/licences/issue")
    page.fill("input[name='issued_to']", "Playwright Test Customer")
    page.select_option("select[name='licence_type']", "professional")
    page.fill("input[name='valid_days']", "90")
    page.fill("input[name='max_users']", "10")
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/licences"), timeout=10000)
    # Check in the table to avoid matching the toast notification
    assert page.locator("table td:has-text('Playwright Test Customer')").is_visible()


def test_licences_validate_page_loads(page, base_url):
    """Validate licence page loads."""
    page.goto(f"{base_url}/licences/validate")
    assert page.locator("input[name='licence_key']").is_visible()


def test_licences_validate_invalid_key(page, base_url):
    """Validating an invalid key shows INVALID result."""
    page.goto(f"{base_url}/licences/validate")
    page.fill("input[name='licence_key']", "invalid-key-12345")
    page.click("button[type='submit']")
    page.wait_for_load_state("networkidle")
    assert page.locator(".badge.bg-danger:has-text('INVALID')").is_visible()


def test_licences_validate_valid_key(page, base_url, seeded_licence):
    """Validating a seeded licence key shows VALID result."""
    page.goto(f"{base_url}/licences/validate")
    page.fill("input[name='licence_key']", seeded_licence["key"])
    page.click("button[type='submit']")
    page.wait_for_load_state("networkidle")
    assert page.locator(".badge.bg-success:has-text('VALID')").is_visible()


def test_licences_issue_button_visible(page, base_url):
    """Issue and Validate buttons are present on list page."""
    page.goto(f"{base_url}/licences")
    assert page.locator("a:has-text('Issue')").count() > 0
    assert page.locator("a:has-text('Validate')").count() > 0


def test_licences_active_count_badge(page, base_url):
    """Active count badge is shown."""
    page.goto(f"{base_url}/licences")
    badge = page.locator("h4 .badge")
    assert badge.count() >= 1


def test_licences_revoke(page, base_url, seeded_licence):
    """Revoke a licence from the list."""
    page.goto(f"{base_url}/licences")

    revoke_form = page.locator("form[data-confirm='Revoke this licence?']").first
    if revoke_form.count() > 0:
        revoke_form.locator("button[type='submit']").click()
        page.locator("#confirmModalOk").click()
        page.wait_for_url(re.compile(r"/licences"), timeout=10000)
