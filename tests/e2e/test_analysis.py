"""Test Analysis page sections."""


def test_analysis_page_loads(page, base_url):
    """Analysis page loads."""
    response = page.goto(f"{base_url}/analysis")
    assert response.status == 200
    assert "Analysis" in page.title()


def test_analysis_recommendations_section(page, base_url):
    """Recommendations section loads."""
    response = page.goto(f"{base_url}/analysis?section=recommendations")
    assert response.status == 200


def test_analysis_risk_section(page, base_url):
    """Risk assessment section loads."""
    response = page.goto(f"{base_url}/analysis?section=risk")
    assert response.status == 200


def test_analysis_cost_section(page, base_url):
    """Cost optimization section loads."""
    response = page.goto(f"{base_url}/analysis?section=cost")
    assert response.status == 200


def test_analysis_upgrade_section(page, base_url):
    """Upgrade plans section loads."""
    response = page.goto(f"{base_url}/analysis?section=upgrade")
    assert response.status == 200


def test_analysis_nav_pills(page, base_url):
    """Navigation pills for all sections are present."""
    page.goto(f"{base_url}/analysis")
    nav_links = page.locator("a.nav-link")
    assert nav_links.count() >= 4
