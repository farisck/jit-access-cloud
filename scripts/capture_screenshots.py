"""
Capture README screenshots of https://jit.barfs.shop

Passwords are typed at a hidden prompt and are never saved to disk.
Run from the repo root. Screenshots go to docs/screenshots/.
They capture only the web page, so no browser tabs or toolbar appear.
"""
import getpass
import pathlib

from playwright.sync_api import sync_playwright

URL = "https://jit.barfs.shop"
OUT = pathlib.Path("docs/screenshots")
OUT.mkdir(parents=True, exist_ok=True)

EMPLOYEE = input("Employee email [employee@example.com]: ").strip() or "employee@example.com"
EMPLOYEE_PW = getpass.getpass("Employee password (hidden): ")
MANAGER = input("Manager email [manager@example.com]: ").strip() or "manager@example.com"
MANAGER_PW = getpass.getpass("Manager password (hidden): ")

REASON = "Verify demo bucket contents before the quarterly audit"


def login(page, email, password):
    page.goto(URL)
    page.fill("#username", email)
    page.fill("#password", password)
    page.click("#loginBtn")
    page.wait_for_selector("#app:not(.hidden)", timeout=20000)
    page.wait_for_timeout(1500)


def go(page, label):
    page.locator("#nav").get_by_role("button", name=label).first.click()
    page.wait_for_timeout(1500)


def shot(page, name):
    path = OUT / name
    page.screenshot(path=str(path))
    print("saved", path)


with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    desktop = {"viewport": {"width": 1440, "height": 900}}

    # ---- Employee: request form, then My access (desktop) ----
    ctx = browser.new_context(**desktop)
    page = ctx.new_page()
    login(page, EMPLOYEE, EMPLOYEE_PW)
    go(page, "Request access")
    page.fill("#reason", REASON)
    page.click("label[for=d15]")  # 15 minutes
    shot(page, "employee-request-form.png")
    page.click("#requestBtn")
    page.wait_for_timeout(2500)
    go(page, "My access")
    shot(page, "employee-my-access.png")
    ctx.close()

    # ---- Manager: approvals, active grants, history (desktop) ----
    ctx = browser.new_context(**desktop)
    page = ctx.new_page()
    login(page, MANAGER, MANAGER_PW)
    go(page, "Approvals")
    shot(page, "manager-approvals.png")

    input("\nIn the browser window, click APPROVE on the pending request, "
          "then press Enter here... ")
    go(page, "Active grants")
    shot(page, "manager-active-grants.png")

    input("\nOptional: submit/deny/revoke other requests so the history has a mix "
          "of Revoked, Denied and Expired, then press Enter here... ")
    go(page, "Access history")
    shot(page, "manager-access-history.png")
    ctx.close()

    # ---- Employee: mobile view ----
    ctx = browser.new_context(viewport={"width": 390, "height": 844},
                              device_scale_factor=2, is_mobile=True)
    page = ctx.new_page()
    login(page, EMPLOYEE, EMPLOYEE_PW)
    shot(page, "employee-mobile.png")
    ctx.close()

    browser.close()

print("\nDone. Check docs/screenshots/ before committing.")
