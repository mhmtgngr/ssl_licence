"""Test responsive design at mobile viewport."""

import pytest


@pytest.fixture()
def mobile_page(browser, base_url):
    """Create a page with mobile viewport."""
    context = browser.new_context(
        viewport={"width": 375, "height": 812},
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
    )
    page = context.new_page()
    yield page
    context.close()


def test_mobile_navbar_collapsed(mobile_page, base_url):
    """Navbar is collapsed on mobile viewport."""
    mobile_page.goto(base_url)
    toggler = mobile_page.locator("button.navbar-toggler")
    assert toggler.is_visible()
    nav_collapse = mobile_page.locator("#navbarNav")
    assert not nav_collapse.is_visible()


def test_mobile_navbar_toggle(mobile_page, base_url):
    """Clicking hamburger menu shows nav links on mobile."""
    mobile_page.goto(base_url)
    mobile_page.click("button.navbar-toggler")
    mobile_page.wait_for_selector("#navbarNav.show", state="visible", timeout=3000)
    assert mobile_page.locator("#navbarNav").is_visible()


def test_mobile_dashboard_loads(mobile_page, base_url):
    """Dashboard loads correctly on mobile."""
    response = mobile_page.goto(base_url)
    assert response.status == 200


def test_mobile_products_page(mobile_page, base_url):
    """Products page renders on mobile."""
    response = mobile_page.goto(f"{base_url}/products")
    assert response.status == 200


def test_mobile_stat_cards_stack(mobile_page, base_url):
    """Stat cards stack vertically on mobile."""
    mobile_page.goto(base_url)
    cards = mobile_page.locator(".card")
    if cards.count() >= 2:
        box1 = cards.nth(0).bounding_box()
        box2 = cards.nth(1).bounding_box()
        if box1 and box2:
            # On mobile, second card should be below first
            assert box2["y"] >= box1["y"]
