"""Test dashboard page content and statistics."""


def test_dashboard_loads(page, base_url):
    """Dashboard page loads with 200 status."""
    response = page.goto(base_url)
    assert response.status == 200


def test_dashboard_title(page, base_url):
    """Dashboard page has correct title."""
    page.goto(base_url)
    assert "Dashboard" in page.title()


def test_dashboard_has_stat_cards(page, base_url):
    """Dashboard displays stat cards."""
    page.goto(base_url)
    cards = page.locator(".card")
    assert cards.count() >= 4


def test_dashboard_total_products_card(page, base_url):
    """Total Products card is visible."""
    page.goto(base_url)
    assert page.locator("text=Total Products").is_visible()


def test_dashboard_active_alerts_card(page, base_url):
    """Active Alerts card is visible."""
    page.goto(base_url)
    assert page.locator("text=Active Alerts").is_visible()


def test_dashboard_domain_summary_cards(page, base_url):
    """Domain summary cards are present."""
    page.goto(base_url)
    assert page.locator("text=Tracked Domains").is_visible()


def test_dashboard_alert_distribution_section(page, base_url):
    """Alert distribution section is present."""
    page.goto(base_url)
    assert page.locator("text=Alert Distribution").is_visible()


def test_dashboard_skip_link(page, base_url):
    """Skip to content link exists."""
    page.goto(base_url)
    skip = page.locator("a[href='#main-content']")
    assert skip.count() > 0
