"""Test Reports page and report types."""


def test_reports_page_loads(page, base_url):
    """Reports page loads with default expiry report."""
    response = page.goto(f"{base_url}/reports")
    assert response.status == 200


def test_reports_expiry_tab(page, base_url):
    """Expiry report tab is accessible."""
    page.goto(f"{base_url}/reports?type=expiry")
    assert page.locator("a.nav-link.active").count() > 0


def test_reports_compliance_tab(page, base_url):
    """Compliance report loads without error."""
    response = page.goto(f"{base_url}/reports?type=compliance")
    assert response.status == 200


def test_reports_cost_tab(page, base_url):
    """Cost report loads without error."""
    response = page.goto(f"{base_url}/reports?type=cost")
    assert response.status == 200


def test_reports_dashboard_tab(page, base_url):
    """Dashboard report loads without error."""
    response = page.goto(f"{base_url}/reports?type=dashboard")
    assert response.status == 200


def test_reports_daily_page_loads(page, base_url):
    """Daily reports page loads."""
    response = page.goto(f"{base_url}/reports/daily")
    assert response.status == 200


def test_reports_tab_navigation(page, base_url):
    """Report tab navigation is present."""
    page.goto(f"{base_url}/reports")
    tabs = page.locator("a.nav-link")
    assert tabs.count() >= 4
