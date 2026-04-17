"""
AI Agent - JWT Authorization Grant Demo

This script demonstrates an AI agent that:
1. Authenticates on the corporate realm using PKCE (Authorization Code Flow)
2. Obtains a corporate access token
3. Exchanges that token for an ai-agents realm token using the JWT Authorization Grant
   (urn:ietf:params:oauth:grant-type:jwt-bearer)
"""

import hashlib
import base64
import os
import re
import json
import time
import logging
import urllib.parse

import requests

# ─── Configuration ───────────────────────────────────────────────────────────
KC_BASE        = os.getenv("KC_BASE_URL", "https://keycloak:8443/auth")
CORP_REALM     = "corporate"
AI_REALM       = "ai-agents"
CORP_CLIENT_ID = "account"
AI_CLIENT_ID   = "ai-agent"
AI_CLIENT_SEC  = "ujs9899AGpXf7HpuDL6QB8eSrgmLpHwD"
KC_HOSTNAME    = os.getenv("KC_HOSTNAME", "localhost.idyatech.fr")
USERNAME       = os.getenv("KC_USERNAME", "ayat")
PASSWORD       = os.getenv("KC_PASSWORD", "password")
REDIRECT_URI   = f"https://{KC_HOSTNAME}:8443/auth/realms/{CORP_REALM}/account/"

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ai-agent")


def banner(title: str):
    log.info("=" * 60)
    log.info(f"  {title}")
    log.info("=" * 60)


def pretty_token(label: str, token_response: dict):
    """Print raw token then decoded claims in a readable way."""
    for key in ("access_token", "refresh_token", "id_token"):
        tok = token_response.get(key)
        if tok:
            log.info(f"  {label} – {key} (raw):")
            log.info(f"    {tok}")
            log.info("")
            parts = tok.split(".")
            if len(parts) == 3:
                payload = parts[1] + "=="
                try:
                    decoded = json.loads(base64.urlsafe_b64decode(payload))
                    log.info(f"  {label} – {key} (decoded claims):")
                    log.info(f"    {json.dumps(decoded, indent=4, default=str)}")
                except Exception:
                    pass
            log.info("")
    log.info(f"  token_type : {token_response.get('token_type')}")
    log.info(f"  expires_in : {token_response.get('expires_in')}s")
    log.info("")


# ─── PKCE helpers ────────────────────────────────────────────────────────────
def generate_pkce():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


# ─── URL rewriting ───────────────────────────────────────────────────────────
KC_PUBLIC_BASE = f"https://{KC_HOSTNAME}:8443"
KC_INTERNAL_BASE = "https://keycloak:8443"

def rewrite_url(url: str) -> str:
    """Rewrite public Keycloak hostname to internal Docker hostname."""
    return url.replace(KC_PUBLIC_BASE, KC_INTERNAL_BASE)


# ─── Step 1 : Authenticate on corporate realm with PKCE ─────────────────────
def step1_corporate_token() -> str:
    banner("STEP 1 – Authenticate on corporate realm (PKCE)")

    code_verifier, code_challenge = generate_pkce()
    log.info(f"  Generated PKCE code_verifier  : {code_verifier[:20]}…")
    log.info(f"  Generated PKCE code_challenge  : {code_challenge[:20]}…")

    session = requests.Session()
    session.verify = False  # self-signed cert

    # 1a – Start authorization request
    auth_url = f"{KC_BASE}/realms/{CORP_REALM}/protocol/openid-connect/auth"
    params = {
        "client_id": CORP_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    log.info("  → Requesting authorization endpoint …")
    resp = session.get(auth_url, params=params, allow_redirects=True)
    resp.raise_for_status()

    # 1b – Extract login form action URL and rewrite to internal host
    action_match = re.search(r'action="([^"]+)"', resp.text)
    if not action_match:
        log.error("  ✗ Could not find login form action URL")
        raise RuntimeError("Login form not found")
    action_url = action_match.group(1).replace("&amp;", "&")
    # Rewrite public hostname → internal Docker hostname
    action_url = rewrite_url(action_url)
    log.info(f"  → Login form action : {action_url[:80]}…")

    # 1c – Submit credentials
    log.info(f"  → Submitting credentials for user '{USERNAME}' …")
    login_resp = session.post(
        action_url,
        data={"username": USERNAME, "password": PASSWORD},
        allow_redirects=False,
    )

    # Follow redirects manually to capture the code
    while login_resp.status_code in (301, 302, 303):
        location = login_resp.headers["Location"]
        if "code=" in location:
            break
        location = rewrite_url(location)
        login_resp = session.get(location, allow_redirects=False)

    location = login_resp.headers.get("Location", "")
    parsed = urllib.parse.urlparse(location)
    qs = urllib.parse.parse_qs(parsed.query)
    code = qs.get("code", [None])[0]

    if not code:
        log.error(f"  ✗ No authorization code received. Location: {location}")
        raise RuntimeError("Authorization code not found")

    log.info(f"  ✓ Authorization code received : {code[:30]}…")

    # 1d – Exchange code for token
    token_url = f"{KC_BASE}/realms/{CORP_REALM}/protocol/openid-connect/token"
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CORP_CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    log.info("  → Exchanging authorization code for token …")
    token_resp = session.post(token_url, data=token_data)
    token_resp.raise_for_status()
    tokens = token_resp.json()

    log.info("  ✓ Corporate token obtained successfully!")
    pretty_token("Corporate", tokens)

    return tokens["access_token"]


# ─── Step 2 : Exchange corporate token → ai-agents token (JWT Bearer) ───────
def step2_jwt_bearer_exchange(corporate_token: str) -> dict:
    banner("STEP 2 – JWT Authorization Grant (jwt-bearer)")

    token_url = f"{KC_BASE}/realms/{AI_REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": AI_CLIENT_ID,
        "client_secret": AI_CLIENT_SEC,
        "assertion": corporate_token,
        "scope": "openid",
    }

    log.info(f"  → Sending JWT Bearer grant to {AI_REALM} realm …")
    log.info(f"    client_id  : {AI_CLIENT_ID}")
    log.info(f"    grant_type : urn:ietf:params:oauth:grant-type:jwt-bearer")
    log.info(f"    assertion  : {corporate_token[:50]}…")

    resp = requests.post(token_url, data=data, verify=False)

    if resp.status_code != 200:
        log.error(f"  ✗ Token exchange failed ({resp.status_code})")
        log.error(f"    {resp.text}")
        raise RuntimeError("JWT Bearer exchange failed")

    tokens = resp.json()
    log.info("  ✓ AI-Agent token obtained successfully!")
    pretty_token("AI-Agent", tokens)

    return tokens


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    # Suppress InsecureRequestWarning for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    banner("AI Agent – JWT Authorization Grant Demo")
    log.info("  This demo shows how an AI agent exchanges a corporate")
    log.info("  identity token for an AI-agents realm token using the")
    log.info("  standard JWT Authorization Grant (RFC 7523).")
    log.info("")

    corporate_token = step1_corporate_token()
    ai_tokens = step2_jwt_bearer_exchange(corporate_token)

    banner("SUMMARY")
    log.info("  ✓ Step 1 : Authenticated on corporate realm (PKCE)")
    log.info("  ✓ Step 2 : Exchanged corporate token → ai-agents token (jwt-bearer)")
    log.info("")
    log.info("  The AI agent now holds a valid token for the ai-agents realm")
    log.info("  without ever exposing user credentials to the ai-agents realm.")
    log.info("")


if __name__ == "__main__":
    main()

