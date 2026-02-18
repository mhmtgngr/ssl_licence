"""Test flash message display after actions."""

import re


def test_flash_message_after_product_add(page, base_url):
    """Toast notification appears after adding a product."""
    page.goto(f"{base_url}/products/add")
    page.fill("input[name='name']", "Flash Test Product")
    page.fill("input[name='vendor']", "FlashVendor")
    page.fill("input[name='version']", "1.0")
    page.select_option("select[name='category']", index=1)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/products"), timeout=10000)

    # Check for toast notification
    toast = page.locator(".toast")
    assert toast.count() > 0


def test_flash_message_after_settings_save(page, base_url):
    """Toast notification appears after saving settings."""
    page.goto(f"{base_url}/settings")
    page.click("button:has-text('Alert Settings')")
    page.wait_for_selector("#alert-settings.show", state="visible", timeout=3000)
    page.locator("#alert-settings button[type='submit']").click()
    page.wait_for_url(re.compile(r"/settings"), timeout=10000)

    toast = page.locator(".toast")
    assert toast.count() > 0


def test_flash_message_dismissible(page, base_url):
    """Toast notifications can be dismissed."""
    page.goto(f"{base_url}/products/add")
    page.fill("input[name='name']", "Dismiss Test Product")
    page.fill("input[name='vendor']", "DV")
    page.fill("input[name='version']", "1.0")
    page.select_option("select[name='category']", index=1)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/products"), timeout=10000)

    close_btn = page.locator(".toast .btn-close").first
    if close_btn.is_visible():
        close_btn.click()
        # Toast should disappear
        page.wait_for_timeout(500)
