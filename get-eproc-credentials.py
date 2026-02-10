"""
EPROC Login and Request Monitoring using Driver syntax

This script:
1. Logs into EPROC using SeleniumBase Driver (with stealth mode)
2. Handles 2FA authentication
3. Monitors and logs all CDP events (requests) triggered after login
"""

from seleniumbase import Driver
from time import sleep
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


# 2FA functions from EprocTJRS-CodigoAut.py
class GoogleAuthenticatorDecoder:
    @staticmethod
    def decode_migration_data(data: str):
        """Decodifica os dados exportados do Google Authenticator (migration payload)"""
        decoded = base64.b64decode(data)
        accounts = []
        i = 0

        while i < len(decoded):
            if decoded[i] == 0x0a:
                i += 1
                if i >= len(decoded):
                    break

                account_len = decoded[i]
                i += 1
                account_data = decoded[i:i + account_len]

                j = 0
                secret = None
                name = None
                issuer = None

                while j < len(account_data):
                    if account_data[j] == 0x0a:  # secret
                        j += 1
                        if j >= len(account_data):
                            break
                        secret_len = account_data[j]
                        j += 1
                        secret = account_data[j:j + secret_len]
                        j += secret_len

                    elif account_data[j] == 0x12:  # name/label
                        j += 1
                        if j >= len(account_data):
                            break
                        name_len = account_data[j]
                        j += 1
                        name = account_data[j:j + name_len].decode("utf-8", errors="ignore")
                        j += name_len

                    elif account_data[j] == 0x1a:  # issuer
                        j += 1
                        if j >= len(account_data):
                            break
                        issuer_len = account_data[j]
                        j += 1
                        issuer = account_data[j:j + issuer_len].decode("utf-8", errors="ignore")
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
    accounts = GoogleAuthenticatorDecoder.decode_migration_data(payload)
    return accounts


def generate_2fa_code(secret_base32: str) -> str:
    """Gera o código TOTP atual (6 dígitos)."""
    totp = pyotp.TOTP(secret_base32)
    return totp.now()


def get_2fa_code_for_eproc_trf4() -> str:
    """
    Get 2FA code for Eproc/TRF4 (issuer index [2] in 1-based indexing).
    Reads EXPORT_2FA_TJRS4 from environment or .env file.
    
    Based on EprocTJRS-CodigoAut.py structure:
    - [1] Eproc/TJRS
    - [2] Eproc/TRF4  <- This one (index 1 in 0-based)
    - [3] Eproc/TJSC
    """
    export_data = os.getenv("EXPORT_2FA_DATA")
    if not export_data:
        raise ValueError("EXPORT_2FA_DATA environment variable not set")
    
    accounts = extract_accounts_from_export(export_data)
    
    if not accounts:
        raise ValueError("No accounts found in exported data")
    
    # First try to find by name/issuer match
    trf4_account = None
    for acc in accounts:
        name = acc.get('name', '').upper()
        issuer = acc.get('issuer', '').upper()
        # Look for TRF4 in name or issuer
        if 'TRF4' in name or 'TRF4' in issuer:
            trf4_account = acc
            break
    
    # If not found by name, use index [2] (1-based) = index [1] (0-based)
    if not trf4_account and len(accounts) >= 2:
        trf4_account = accounts[1]  # Index [2] in 1-based, [1] in 0-based
    elif not trf4_account and len(accounts) == 1:
        # If only one account, use it
        trf4_account = accounts[0]
    
    if not trf4_account:
        raise ValueError(
            f"Could not find Eproc/TRF4 account in exported data. "
            f"Found {len(accounts)} account(s) but none matched TRF4."
        )
    
    secret = trf4_account["secret"]
    return generate_2fa_code(secret)


def extract_links_from_page_source(html_content):
    """Extract the three main URLs from the page source."""
    soup = BeautifulSoup(html_content, 'html.parser')
    result = {}
    
    # Link 1: get_urls endpoint (AJAX URL from #RS link)
    rs_link = soup.find('a', href='#RS')
    if rs_link:
        url_attr = None
        for attr, value in rs_link.attrs.items():
            if attr.lower() == 'data-urlassinadacarregamento':
                url_attr = value
                break
        
        if url_attr:
            result['get_urls'] = url_attr.replace('&amp;', '&')
    
    # Link 2: get_due_today endpoint (citacao_intimacao_prazo_aberto_listar with vence_hoje=S)
    link2 = soup.find('a', href=re.compile(r'citacao_intimacao_prazo_aberto_listar.*vence_hoje=S'))
    if link2:
        href = link2.get('href', '').replace('&amp;', '&')
        result['get_due_today'] = href
    
    # Link 3: get_reports endpoint (relatorio_processo_procurador_listar)
    link3 = soup.find('a', href=re.compile(r'relatorio_processo_procurador_listar'),
                     attrs={'aria-label': 'Relação de Processos'})
    if link3:
        href = link3.get('href', '').replace('&amp;', '&')
        result['get_reports'] = href
    
    return result


def get_session_with_phpsessid():
    """Start a browser session and extract the PHPSESSID cookie."""
    print("Starting browser session...")

    driver = Driver(
        headless=True, 
        uc_cdp_events=True,
    )

    driver.get(BASE_URL)
    sleep(2)

    # Extract PHPSESSID directly from browser cookies
    cookies = driver.get_cookies()
    for cookie in cookies:
        if cookie.get("name") == "PHPSESSID":
            phpsessid = cookie.get("value")
            if phpsessid:
                print(f"Successfully obtained PHPSESSID: {phpsessid[:20]}...")
                return driver, phpsessid

    driver.quit()
    raise RuntimeError("No PHPSESSID found in cookies")


def get_credentials_workflow(driver, first_phpsessid: str, usuario: str, senha: str):
    """Step 1: Perform login + 2FA and capture page data using an existing session."""
    sleep(2)

    print("Logging in...")
    try:
        driver.wait_for_element('#txtUsuario', timeout=15)
    except Exception as e:
        print(f"Failed to find login form: {e}")
        raise

    driver.click('#txtUsuario')
    sleep(0.2)
    driver.type('#txtUsuario', usuario)

    sleep(0.5)

    driver.click('#pwdSenha')
    sleep(0.2)
    driver.type('#pwdSenha', senha)

    sleep(1)

    driver.click('#sbmEntrar')

    print("Handling captcha...")
    try:
        driver.wait_for_element("button[onclick*=\"Submit('login')\"]", timeout=15)
    except Exception:
        try:
            driver.wait_for_element("button:contains('Enviar')", timeout=15)
        except Exception:
            pass

    sleep(7)

    try:
        driver.wait_for_element("button[onclick*=\"Submit('login')\"]", timeout=5)
        driver.click("button[onclick*=\"Submit('login')\"][value='Enviar']")
        try:
            driver.wait_for_element_not_visible("button[onclick*=\"Submit('login')\"][value='Enviar']", timeout=5)
        except Exception:
            try:
                driver.wait_for_element('#txtAcessoCodigo', timeout=10)
            except Exception:
                pass
    except Exception:
        try:
            driver.click("button:contains('Enviar')")
            try:
                driver.wait_for_element_not_visible("button:contains('Enviar')", timeout=5)
            except Exception:
                try:
                    driver.wait_for_element('#txtAcessoCodigo', timeout=10)
                except Exception:
                    pass
        except Exception:
            try:
                driver.click("button[onclick*='Submit']")
                try:
                    driver.wait_for_element_not_visible("button[onclick*='Submit']", timeout=5)
                except Exception:
                    try:
                        driver.wait_for_element('#txtAcessoCodigo', timeout=10)
                    except Exception:
                        pass
            except Exception:
                pass

    sleep(7)

    try:
        driver.click("button[onclick*=\"Submit('login')\"][value='Enviar']")
        try:
            driver.wait_for_element_not_visible("button[onclick*=\"Submit('login')\"][value='Enviar']", timeout=5)
        except Exception:
            pass
    except Exception:
        try:
            driver.click("button:contains('Enviar')")
            try:
                driver.wait_for_element_not_visible("button:contains('Enviar')", timeout=5)
            except Exception:
                pass
        except Exception:
            try:
                driver.click("button[onclick*='Submit']")
                try:
                    driver.wait_for_element_not_visible("button[onclick*='Submit']", timeout=5)
                except Exception:
                    pass
            except Exception:
                pass

    try:
        driver.wait_for_element('#txtAcessoCodigo', timeout=10)
    except Exception as e:
        raise RuntimeError(f"2FA field not found. Login may have failed: {e}")

    print("Entering 2FA...")
    codigo_2fa = get_2fa_code_for_eproc_trf4()
    print(f"Generated 2FA code for Eproc/TRF4")

    driver.click('#txtAcessoCodigo')
    sleep(0.2)
    driver.type('#txtAcessoCodigo', codigo_2fa)

    sleep(1)

    driver.click('#btnValidar')

    try:
        driver.wait_for_element('#processoscomprazoemaberto', timeout=30)
        print("Successfully authenticated and reached main page")
    except Exception:
        print("Main page element not found, but continuing...")

    try:
        processoscomprazoemaberto_href = driver.get_attribute(
            'a[aria-describedby="processoscomprazoemaberto"]', 'href'
        )
    except Exception as e:
        print(f"Failed to extract open_processes URL: {e}")
        raise

    # Normalize open_processes URL to extract only controlador.php path
    parsed = urlparse(processoscomprazoemaberto_href)
    open_processes_path = parsed.path.lstrip('/')
    if open_processes_path.startswith('eprocV2/'):
        open_processes_path = open_processes_path.replace('eprocV2/', '', 1)
    if parsed.query:
        open_processes_path += f"?{parsed.query}"

    page_source = driver.page_source

    print("Extracting endpoints from authenticated page...")
    extracted_links = extract_links_from_page_source(page_source)

    credentials = {
        "phpsessid": first_phpsessid,
        "endpoints": {
            "open_processes": open_processes_path,
            "get_urls": extracted_links.get("get_urls"),
            "due_today": extracted_links.get("get_due_today"),
            "reports": extracted_links.get("get_reports"),
        },
        "run_at": datetime.now().isoformat()
    }

    return credentials


def main():
    """Main function: obtain session with PHPSESSID, then login and extract credentials."""
    # Read credentials from env vars
    USUARIO = os.getenv("TJRS_USUARIO")
    SENHA = os.getenv("TJRS_SENHA")

    if not USUARIO or not SENHA:
        print("Error: TJRS_USUARIO and TJRS_SENHA must be set in environment or .env file")
        return

    driver = None
    try:
        print("Starting EPROC credentials workflow...")
        driver, first_phpsessid = get_session_with_phpsessid()
        credentials = get_credentials_workflow(driver, first_phpsessid, USUARIO, SENHA)

        print("\nOutput:")
        print(json.dumps(credentials, indent=2))

    except Exception as e:
        print(f"\nEPROC credentials workflow failed: {e}")
        traceback.print_exc()
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


if __name__ == "__main__":
    main()
