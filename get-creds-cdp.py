"""
EPROC Login and Credential Extraction using SeleniumBase CDP Mode

This script:
1. Logs into EPROC using SeleniumBase CDP mode (with UC stealth)
2. Solves captcha automatically via sb.cdp.solve_captcha()
3. Handles 2FA authentication
4. Extracts session credentials and endpoint URLs
"""

from seleniumbase import SB
import os
from dotenv import load_dotenv
import base64
from urllib.parse import unquote, urlparse
import pyotp
import json
from datetime import datetime
import re
from bs4 import BeautifulSoup
import traceback

# Load environment variables
load_dotenv()

# Base URL
BASE_URL = "https://eproc.jfrs.jus.br/eprocV2/externo_controlador.php"

# User agent with pt-BR locale
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# 2FA helpers (Google Authenticator export decoder)
# ---------------------------------------------------------------------------

class GoogleAuthenticatorDecoder:
    @staticmethod
    def decode_migration_data(data: str):
        """Decodifica os dados exportados do Google Authenticator (migration payload)"""
        decoded = base64.b64decode(data)
        accounts = []
        i = 0

        while i < len(decoded):
            if decoded[i] == 0x0A:
                i += 1
                if i >= len(decoded):
                    break

                account_len = decoded[i]
                i += 1
                account_data = decoded[i : i + account_len]

                j = 0
                secret = None
                name = None
                issuer = None

                while j < len(account_data):
                    if account_data[j] == 0x0A:  # secret
                        j += 1
                        if j >= len(account_data):
                            break
                        secret_len = account_data[j]
                        j += 1
                        secret = account_data[j : j + secret_len]
                        j += secret_len

                    elif account_data[j] == 0x12:  # name/label
                        j += 1
                        if j >= len(account_data):
                            break
                        name_len = account_data[j]
                        j += 1
                        name = account_data[j : j + name_len].decode("utf-8", errors="ignore")
                        j += name_len

                    elif account_data[j] == 0x1A:  # issuer
                        j += 1
                        if j >= len(account_data):
                            break
                        issuer_len = account_data[j]
                        j += 1
                        issuer = account_data[j : j + issuer_len].decode("utf-8", errors="ignore")
                        j += issuer_len
                    else:
                        j += 1

                if secret:
                    secret_base32 = base64.b32encode(secret).decode("utf-8")
                    accounts.append({"secret": secret_base32, "name": name, "issuer": issuer})

                i += account_len
            else:
                i += 1

        return accounts


def extract_accounts_from_export(data_exportada_urlencoded: str):
    """Recebe a DATA_EXPORTADA (com %3D etc), decodifica e retorna lista de contas."""
    payload = unquote(data_exportada_urlencoded)
    return GoogleAuthenticatorDecoder.decode_migration_data(payload)


def generate_2fa_code(secret_base32: str) -> str:
    """Gera o código TOTP atual (6 dígitos)."""
    totp = pyotp.TOTP(secret_base32)
    return totp.now()


def get_2fa_code_for_eproc_trf4() -> str:
    """
    Get 2FA code for Eproc/TRF4.
    Reads EXPORT_2FA_DATA from environment or .env file.

    Account order (1-based):
      [1] Eproc/TJRS
      [2] Eproc/TRF4  <- target (index 1 in 0-based)
      [3] Eproc/TJSC
    """
    export_data = os.getenv("EXPORT_2FA_DATA")
    if not export_data:
        raise ValueError("EXPORT_2FA_DATA environment variable not set")

    accounts = extract_accounts_from_export(export_data)
    if not accounts:
        raise ValueError("No accounts found in exported data")

    # Try to find by name/issuer match first
    trf4_account = None
    for acc in accounts:
        name = acc.get("name", "").upper()
        issuer = acc.get("issuer", "").upper()
        if "TRF4" in name or "TRF4" in issuer:
            trf4_account = acc
            break

    # Fallback to index [1] (0-based) = [2] (1-based)
    if not trf4_account and len(accounts) >= 2:
        trf4_account = accounts[1]
    elif not trf4_account and len(accounts) == 1:
        trf4_account = accounts[0]

    if not trf4_account:
        raise ValueError(
            f"Could not find Eproc/TRF4 account. "
            f"Found {len(accounts)} account(s) but none matched TRF4."
        )

    return generate_2fa_code(trf4_account["secret"])


# ---------------------------------------------------------------------------
# Page-source link extraction
# ---------------------------------------------------------------------------

def extract_links_from_page_source(html_content):
    """Extract the three main endpoint URLs from the authenticated page source."""
    soup = BeautifulSoup(html_content, "html.parser")
    result = {}

    # 1) get_urls — AJAX URL from the #RS link's data attribute
    rs_link = soup.find("a", href="#RS")
    if rs_link:
        for attr, value in rs_link.attrs.items():
            if attr.lower() == "data-urlassinadacarregamento":
                result["get_urls"] = value.replace("&amp;", "&")
                break

    # 2) due_today — citacao_intimacao_prazo_aberto_listar with vence_hoje=S
    link2 = soup.find("a", href=re.compile(r"citacao_intimacao_prazo_aberto_listar.*vence_hoje=S"))
    if link2:
        result["get_due_today"] = link2.get("href", "").replace("&amp;", "&")

    # 3) reports — relatorio_processo_procurador_listar
    link3 = soup.find(
        "a",
        href=re.compile(r"relatorio_processo_procurador_listar"),
        attrs={"aria-label": "Relação de Processos"},
    )
    if link3:
        result["get_reports"] = link3.get("href", "").replace("&amp;", "&")

    return result


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def main():
    """Run the full EPROC credentials workflow using CDP mode."""
    USUARIO = os.getenv("TJRS_USUARIO")
    SENHA = os.getenv("TJRS_SENHA")

    if not USUARIO or not SENHA:
        print("Error: TJRS_USUARIO and TJRS_SENHA must be set in environment or .env file")
        return

    with SB(uc=True, headless=False, xvfb=True) as sb:
        try:
            print("Starting EPROC credentials workflow (CDP mode)...")

            # ---- 1. Navigate & activate CDP mode ----
            sb.activate_cdp_mode(BASE_URL)
            sb.cdp.sleep(2)

            # ---- 2. Extract PHPSESSID from cookies ----
            phpsessid = None
            cookies = sb.cdp.get_all_cookies()
            for cookie in cookies:
                if getattr(cookie, "name", None) == "PHPSESSID":
                    phpsessid = getattr(cookie, "value", None)
                    break

            if not phpsessid:
                raise RuntimeError("No PHPSESSID found in cookies")
            print(f"Got PHPSESSID: {phpsessid[:20]}...")

            # ---- 3. Fill login form ----
            print("Logging in...")
            sb.cdp.wait_for_element("#txtUsuario", timeout=15)
            sb.cdp.type("#txtUsuario", USUARIO)
            sb.cdp.sleep(0.5)
            sb.cdp.type("#pwdSenha", SENHA)
            sb.cdp.sleep(1)
            sb.cdp.click("#sbmEntrar")

            # ---- 4. Solve captcha and submit ----
            print("Handling captcha...")
            sb.cdp.sleep(3)

            # Intercept window.confirm so clicking "Enviar" before captcha
            # is solved doesn't block execution. The flag tells us if the
            # popup fired (meaning captcha wasn't ready yet).
            sb.cdp.evaluate("""
                window.__captchaNotReady = false;
                window.__origConfirm = window.confirm;
                window.confirm = function(msg) {
                    if (msg && msg.indexOf("captcha") !== -1) {
                        window.__captchaNotReady = true;
                        return false;
                    }
                    return true;
                };
            """)

            MAX_CAPTCHA_ATTEMPTS = 5
            for attempt in range(1, MAX_CAPTCHA_ATTEMPTS + 1):
                print(f"  Captcha solve attempt {attempt}/{MAX_CAPTCHA_ATTEMPTS}...")

                # Step A: try to solve the captcha
                sb.cdp.solve_captcha()
                sb.cdp.sleep(4)

                # Step B: reset flag, then click "Enviar"
                sb.cdp.evaluate("window.__captchaNotReady = false;")
                try:
                    sb.cdp.click("button[onclick*=\"Submit('login')\"]")
                except Exception:
                    try:
                        sb.cdp.click_if_visible("button[value='Enviar']")
                    except Exception:
                        pass

                sb.cdp.sleep(2)

                # Step C: check if the popup fired (captcha wasn't solved)
                popup_fired = sb.cdp.evaluate("window.__captchaNotReady")
                if popup_fired:
                    print("  Captcha not solved yet (JS popup intercepted), retrying...")
                    continue

                # Step D: if the 2FA field appeared, we're through
                if sb.cdp.is_element_present("#txtAcessoCodigo"):
                    print("  Captcha solved, 2FA field is visible.")
                    break

                # Neither popup nor 2FA — page might still be loading
                print("  No popup but 2FA not visible yet, retrying...")
                if attempt == MAX_CAPTCHA_ATTEMPTS:
                    raise RuntimeError("Captcha was not solved after max attempts")

            # Restore original confirm
            sb.cdp.evaluate("if(window.__origConfirm) window.confirm = window.__origConfirm;")

            # ---- 5. Enter 2FA code ----
            sb.cdp.wait_for_element("#txtAcessoCodigo", timeout=30)
            print("Entering 2FA...")
            codigo_2fa = get_2fa_code_for_eproc_trf4()
            print("Generated 2FA code for Eproc/TRF4")

            sb.cdp.type("#txtAcessoCodigo", codigo_2fa)
            sb.cdp.sleep(1)
            sb.cdp.click("#btnValidar")

            # ---- 6. Wait for authenticated main page ----
            try:
                sb.cdp.wait_for_element("#processoscomprazoemaberto", timeout=30)
                print("Successfully authenticated and reached main page")
            except Exception:
                print("Main page element not found, but continuing...")

            # ---- 7. Extract open_processes URL ----
            href = sb.cdp.get_attribute(
                'a[aria-describedby="processoscomprazoemaberto"]', "href"
            )
            parsed = urlparse(href)
            open_processes_path = parsed.path.lstrip("/")
            if open_processes_path.startswith("eprocV2/"):
                open_processes_path = open_processes_path.replace("eprocV2/", "", 1)
            if parsed.query:
                open_processes_path += f"?{parsed.query}"

            # ---- 8. Extract remaining endpoints from page source ----
            print("Extracting endpoints from authenticated page...")
            page_source = sb.cdp.get_page_source()
            extracted_links = extract_links_from_page_source(page_source)

            # ---- 9. Build and output credentials ----
            credentials = {
                "phpsessid": phpsessid,
                "endpoints": {
                    "open_processes": open_processes_path,
                    "get_urls": extracted_links.get("get_urls"),
                    "due_today": extracted_links.get("get_due_today"),
                    "reports": extracted_links.get("get_reports"),
                },
                "run_at": datetime.now().isoformat(),
            }

            print("\nOutput:")
            print(json.dumps(credentials, indent=2))

        except Exception as e:
            print(f"\nEPROC credentials workflow failed: {e}")
            traceback.print_exc()
            # Save a screenshot for debugging
            try:
                sb.cdp.save_screenshot("error_screenshot.png", folder="output")
                print("Error screenshot saved to output/error_screenshot.png")
            except Exception:
                pass


if __name__ == "__main__":
    main()
