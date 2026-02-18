"""Test Alerts listing and filtering."""


def test_alerts_page_loads(page, base_url):
    """Alerts page loads successfully."""
    response = page.goto(f"{base_url}/alerts")
    assert response.status == 200
    assert "Alerts" in page.title()


def test_alerts_filter_controls(page, base_url):
    """Filter controls (level, type, vendor) are present."""
    page.goto(f"{base_url}/alerts")
    assert page.locator("select[name='level']").is_visible()
    assert page.locator("select[name='type']").is_visible()
    assert page.locator("input[name='vendor']").is_visible()


def test_alerts_empty_state_or_table(page, base_url):
    """Either an alerts table or empty state is shown."""
    page.goto(f"{base_url}/alerts")
    has_table = page.locator("table").count() > 0
    has_empty = page.locator("text=No alerts").is_visible()
    assert has_table or has_empty


def test_alerts_filter_by_level(page, base_url):
    """Filtering by level works without error."""
    page.goto(f"{base_url}/alerts")
    page.select_option("select[name='level']", index=1)
    page.click("button[type='submit']")
    # Page should reload without error
    assert page.locator("select[name='level']").is_visible()


def test_alerts_badge_count(page, base_url):
    """Alerts page header shows badge with alert count."""
    page.goto(f"{base_url}/alerts")
    badge = page.locator("h4 .badge")
    assert badge.count() > 0
