# mcp_oauth_sdk/oauth.py

import os
import time
import functools
import uuid
import requests
from urllib.parse import urlencode
from jose import jwt
from dotenv import load_dotenv
load_dotenv(override=True)

class MCPOAuthSDK:
    def __init__(self):
        self.google_client_id = str(os.getenv("CLIENT_ID"))
        self.google_client_secret = str(os.getenv("CLIENT_SECRET"))
        self.redirect_uri = str(os.getenv("CLIENT_URI"))
        # Discovery
        self.google_discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
        self.jwks = None
        self.session_store = {}  # {session_id: {"id_token":..., "expires_at":...}}

    def _get_google_config(self):
        return requests.get(self.google_discovery_url).json()

    def _get_google_jwks(self):
        if not self.jwks:
            jwks_uri = self._get_google_config()["jwks_uri"]
            self.jwks = requests.get(jwks_uri).json()
        return self.jwks

    def _verify_id_token(self, token):
        jwks = self._get_google_jwks()
        try:
            payload = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=self.google_client_id,
                issuer="https://accounts.google.com"
            )
            return payload
        except Exception as e:
            print(f"[OAuth] Token verification failed: {e}")
            return None

    def start_auth_flow(self):
        """
        Returns Google OAuth 2.0 authorization URL.
        """
        config = self._get_google_config()
        auth_endpoint = config["authorization_endpoint"]

        state = str(uuid.uuid4())
        params = {
            "client_id": self.google_client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": self.redirect_uri,
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        url = f"{auth_endpoint}?{urlencode(params)}"
        return url

    def complete_auth_flow(self, code):
        """
        Exchange code for tokens and create a session.
        """
        config = self._get_google_config()
        token_endpoint = config["token_endpoint"]

        data = {
            "code": code,
            "client_id": self.google_client_id,
            "client_secret": self.google_client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code"
        }

        resp = requests.post(token_endpoint, data=data)
        tokens = resp.json()

        id_token = tokens.get("id_token")
        if not id_token:
            return None

        payload = self._verify_id_token(id_token)
        if not payload:
            return None

        session_id = str(uuid.uuid4())
        self.session_store[session_id] = {
            "id_token": id_token,
            "expires_at": time.time() + 1800  # 30 min
        }
        return session_id

    def end_auth_flow(self, session_id):
        """
        Invalidate session.
        """
        self.session_store.pop(session_id, None)
        return True

    def _is_session_valid(self, session_id):
        """
        Check session expiry.
        """
        session = self.session_store.get(session_id)
        if not session:
            return False
        if time.time() > session["expires_at"]:
            self.session_store.pop(session_id)
            return False
        return True

    def protect_tool(self, tool_func):
        """
        Decorator to protect MCP tools.
        Requires header: X-Session-ID: <session_id>
        """
        @functools.wraps(tool_func)
        def wrapper(*args, **kwargs):
            from mcp.server.fastmcp import get_current_request
            req = get_current_request()
            session_id = req.headers.get("X-Session-ID")
            if not session_id or not self._is_session_valid(session_id):
                return {"error": "Unauthorized: start OAuth flow first."}
            return tool_func(*args, **kwargs)
        return wrapper
