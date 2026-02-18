"""Test Products CRUD operations."""

import re


def test_products_list_page_loads(page, base_url):
    """Products page loads successfully."""
    response = page.goto(f"{base_url}/products")
    assert response.status == 200
    assert "Products" in page.title()


def test_products_add_button_visible(page, base_url):
    """Add Product button is visible on list page."""
    page.goto(f"{base_url}/products")
    assert page.locator("text=Add Product").is_visible()


def test_products_add_page_loads(page, base_url):
    """Add Product form page loads correctly."""
    page.goto(f"{base_url}/products/add")
    assert "Add Product" in page.title()
    assert page.locator("form").count() > 0


def test_products_add_and_verify(page, base_url):
    """Add a product via the form and verify it appears in the list."""
    page.goto(f"{base_url}/products/add")

    page.fill("input[name='name']", "Playwright Test Product")
    page.fill("input[name='vendor']", "PlaywrightVendor")
    page.fill("input[name='version']", "2.0")
    page.select_option("select[name='category']", index=1)
    page.fill("input[name='annual_cost']", "5000")
    page.fill("input[name='tags']", "e2e, test")

    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/products"), timeout=10000)
    # Use table link to avoid matching the toast message too
    assert page.locator("table a:has-text('Playwright Test Product')").is_visible()


def test_products_detail_page(page, base_url, seeded_product):
    """Product detail page shows product information."""
    product_id = seeded_product["product_id"]
    page.goto(f"{base_url}/products/{product_id}")
    assert page.locator("text=TestVendor").is_visible()


def test_products_delete(page, base_url, seeded_product):
    """Delete a product via the list page."""
    product_id = seeded_product["product_id"]
    page.goto(f"{base_url}/products")

    # Handle the confirm modal
    delete_form = page.locator(f"form[action*='{product_id}/delete']")
    if delete_form.count() > 0:
        delete_form.first.locator("button[type='submit']").click()
        # Click confirm in the modal
        page.locator("#confirmModalOk").click()
        page.wait_for_url(re.compile(r"/products"), timeout=10000)


def test_products_filter_controls(page, base_url):
    """Filter controls are present on the products list page."""
    page.goto(f"{base_url}/products")
    assert page.locator("select[name='category']").is_visible()
    assert page.locator("select[name='vendor']").is_visible()
    assert page.locator("input[name='q']").is_visible()


def test_products_add_form_has_csrf_token(page, base_url):
    """Add product form includes CSRF token."""
    page.goto(f"{base_url}/products/add")
    csrf = page.locator("input[name='csrf_token']")
    assert csrf.count() > 0
    assert csrf.get_attribute("value") != ""
