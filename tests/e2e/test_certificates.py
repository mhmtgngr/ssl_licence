"""Test Certificates checking and history."""


def test_certificates_list_page_loads(page, base_url):
    """Certificates list page loads."""
    response = page.goto(f"{base_url}/certificates")
    assert response.status == 200


def test_certificates_check_page_loads(page, base_url):
    """Check Remote page loads with form."""
    page.goto(f"{base_url}/certificates/check")
    assert page.locator("textarea[name='domains']").is_visible()


def test_certificates_history_page_loads(page, base_url):
    """Certificate check history page loads."""
    response = page.goto(f"{base_url}/certificates/history")
    assert response.status == 200


def test_certificates_chain_check_page_loads(page, base_url):
    """Chain check page loads."""
    page.goto(f"{base_url}/certificates/chain-check")
    assert page.locator("input[name='domain']").is_visible()


def test_certificates_ocsp_check_page_loads(page, base_url):
    """OCSP check page loads."""
    page.goto(f"{base_url}/certificates/ocsp-check")
    assert page.locator("input[name='domain']").is_visible()


def test_certificates_check_and_history_links(page, base_url):
    """Check Remote and History links are accessible."""
    page.goto(f"{base_url}/certificates")
    assert page.locator("a[href*='check']").count() > 0
    assert page.locator("a[href*='history']").count() > 0


def test_certificates_chain_check_accessible(page, base_url):
    """Chain Check page is directly accessible."""
    response = page.goto(f"{base_url}/certificates/chain-check")
    assert response.status == 200
