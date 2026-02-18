"""Test Domains CRUD operations."""

import re


def test_domains_list_page_loads(page, base_url):
    """Domains list page loads with summary cards."""
    response = page.goto(f"{base_url}/domains")
    assert response.status == 200
    assert page.locator("text=Total Domains").is_visible()


def test_domains_add_page_loads(page, base_url):
    """Add Domain form page loads."""
    page.goto(f"{base_url}/domains/add")
    assert page.locator("input[name='hostname']").is_visible()


def test_domains_detail_page(page, base_url, seeded_domain):
    """Domain detail page shows domain information."""
    domain_id = seeded_domain["domain_id"]
    response = page.goto(f"{base_url}/domains/{domain_id}")
    assert response.status == 200
    # The detail page has "SSL Certificate Details" and "DNS Information" card headers
    assert page.locator("text=SSL Certificate Details").is_visible()
    assert page.locator("text=DNS Information").is_visible()


def test_domains_edit_page_loads(page, base_url, seeded_domain):
    """Domain edit page loads with pre-filled data."""
    domain_id = seeded_domain["domain_id"]
    page.goto(f"{base_url}/domains/{domain_id}/edit")
    assert page.locator("select[name='status']").is_visible()


def test_domains_edit_and_save(page, base_url, seeded_domain):
    """Edit domain notes and save."""
    domain_id = seeded_domain["domain_id"]
    page.goto(f"{base_url}/domains/{domain_id}/edit")
    page.fill("textarea[name='notes']", "Updated by Playwright")
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(rf"/domains/{domain_id}"), timeout=10000)


def test_domains_filter_controls(page, base_url):
    """Filter controls are present on the domains list page."""
    page.goto(f"{base_url}/domains")
    assert page.locator("select[name='status']").is_visible()
    assert page.locator("select[name='type']").is_visible()
    assert page.locator("input[name='q']").is_visible()


def test_domains_discover_page_loads(page, base_url):
    """Subdomain discovery page loads."""
    response = page.goto(f"{base_url}/domains/discover")
    assert response.status == 200


def test_domains_import_page_loads(page, base_url):
    """Domain import page loads."""
    response = page.goto(f"{base_url}/domains/import")
    assert response.status == 200


def test_domains_delete(page, base_url, seeded_domain):
    """Delete a domain from detail page."""
    domain_id = seeded_domain["domain_id"]
    page.goto(f"{base_url}/domains/{domain_id}")

    delete_form = page.locator(f"form[action*='{domain_id}/delete']")
    if delete_form.count() > 0:
        delete_form.locator("button[type='submit']").click()
        page.locator("#confirmModalOk").click()
        page.wait_for_url(re.compile(r"/domains"), timeout=10000)


def test_domains_summary_cards_visible(page, base_url):
    """Summary cards are visible."""
    page.goto(f"{base_url}/domains")
    for label in ["Total Domains", "SSL OK"]:
        assert page.locator(f"text={label}").is_visible()


def test_domains_add_button_visible(page, base_url):
    """Add Domain button is visible."""
    page.goto(f"{base_url}/domains")
    assert page.locator("text=Add Domain").is_visible()
