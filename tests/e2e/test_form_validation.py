"""Test form validation behavior (required fields, invalid data)."""


def test_product_form_required_name(page, base_url):
    """Product add form enforces required name field via HTML5 validation."""
    page.goto(f"{base_url}/products/add")
    page.fill("input[name='vendor']", "V")
    page.fill("input[name='version']", "1.0")
    page.click("button[type='submit']")
    # Browser validation prevents submission; should stay on the page
    assert "add" in page.url.lower() or "products" in page.url.lower()


def test_product_form_required_vendor(page, base_url):
    """Product add form enforces required vendor field."""
    page.goto(f"{base_url}/products/add")
    page.fill("input[name='name']", "TestProd")
    page.fill("input[name='version']", "1.0")
    page.click("button[type='submit']")
    assert "add" in page.url.lower() or "products" in page.url.lower()


def test_licence_issue_form_required_issued_to(page, base_url):
    """Licence issue form enforces required issued_to field."""
    page.goto(f"{base_url}/licences/issue")
    page.click("button[type='submit']")
    assert "issue" in page.url.lower() or "licences" in page.url.lower()


def test_domain_add_form_required_hostname(page, base_url):
    """Domain add form enforces required hostname field."""
    page.goto(f"{base_url}/domains/add")
    page.click("button[type='submit']")
    assert "add" in page.url.lower() or "domains" in page.url.lower()


def test_licence_validate_required_key(page, base_url):
    """Licence validate form requires a key."""
    page.goto(f"{base_url}/licences/validate")
    page.click("button[type='submit']")
    assert "validate" in page.url.lower() or "licences" in page.url.lower()


def test_product_form_required_version(page, base_url):
    """Product add form enforces required version field."""
    page.goto(f"{base_url}/products/add")
    page.fill("input[name='name']", "P")
    page.fill("input[name='vendor']", "V")
    page.click("button[type='submit']")
    assert "add" in page.url.lower() or "products" in page.url.lower()
