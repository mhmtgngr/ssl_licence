"""Test cross-page navigation and layout."""

import re


def test_navbar_has_all_links(page, base_url):
    """Verify navbar contains links to all 9 sections."""
    page.goto(base_url)
    nav = page.locator("nav")
    for label in ["Dashboard", "Products", "Alerts", "Reports", "Analysis",
                   "Licences", "Certificates", "Domains", "Settings"]:
        assert nav.locator(f"text={label}").count() > 0


def test_navbar_brand_links_to_dashboard(page, base_url):
    """Brand link navigates to dashboard."""
    page.goto(f"{base_url}/products")
    page.click("a.navbar-brand")
    assert page.url.rstrip("/") == base_url.rstrip("/") or page.url.endswith("/")


def test_active_nav_link_highlighted(page, base_url):
    """Current page's nav link has the 'active' class."""
    page.goto(f"{base_url}/products")
    link = page.locator("nav a.nav-link.active")
    assert "Products" in link.text_content()


def test_navigate_all_main_pages(page, base_url):
    """Navigate to each main page and verify it loads without error."""
    pages_to_test = [
        ("/", "Dashboard"),
        ("/products", "Products"),
        ("/alerts", "Alerts"),
        ("/reports", "Reports"),
        ("/analysis", "Analysis"),
        ("/licences", "Licences"),
        ("/certificates", "Certificates"),
        ("/domains", "Domains"),
        ("/settings", "Settings"),
    ]
    for path, expected_title_part in pages_to_test:
        response = page.goto(f"{base_url}{path}")
        assert response.status == 200, f"Failed for {path}"
        assert expected_title_part in page.title(), f"Title missing '{expected_title_part}' for {path}"


def test_footer_present(page, base_url):
    """Footer is present on all pages."""
    page.goto(base_url)
    footer = page.locator("footer")
    assert footer.is_visible()
    assert "SSL Licence Manager" in footer.text_content()


def test_404_page(page, base_url):
    """Navigating to a nonexistent page shows 404."""
    response = page.goto(f"{base_url}/nonexistent-page-xyz")
    assert response.status == 404
    assert "404" in page.content()
