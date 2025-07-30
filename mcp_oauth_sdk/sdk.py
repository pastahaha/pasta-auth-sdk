# mcp_oauth_sdk/oauth.py

import os
import time
import uuid
import functools
import requests
from urllib.parse import urlencode
from jose import jwt


class MCPOAuthSDK:
    def __init__(self):
        self.google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
        self.google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
        self.redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")  # e.g., https://yourdomain.com/oauth/callback

        self.google_discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
        self.jwks = None

        self.protected_tools = []  # list of tool functions
        self.session_store = {}    # session_id -> {expires_at: float}

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
        Returns Google OAuth 2.0 login URL.
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
        return f"{auth_endpoint}?{urlencode(params)}"

    def complete_auth_flow(self, code):
        """
        Exchange code for tokens, create session.
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
            print("[OAuth] No id_token received")
            return None

        payload = self._verify_id_token(id_token)
        if not payload:
            return None

        # Create session
        session_id = str(uuid.uuid4())
        self.session_store[session_id] = {
            "id_token": id_token,
            "expires_at": time.time() + 1800  # 30 min session
        }
        print(f"[OAuth] New session created: {session_id}")
        return session_id

    def end_auth_flow(self, session_id):
        """
        Invalidate session.
        """
        self.session_store.pop(session_id, None)
        print(f"[OAuth] Session ended: {session_id}")

    def is_session_valid(self, session_id):
        session = self.session_store.get(session_id)
        if not session:
            return False
        if time.time() > session["expires_at"]:
            self.session_store.pop(session_id)
            return False
        return True

    def protect_tool(self, tool_func):
        """
        Instead of registering now, keep it aside.
        """
        self.protected_tools.append(tool_func)
        return tool_func

    def activate_protected_tools(self, mcp, session_id):
        """
        Register protected tools to MCP when session is valid.
        """
        if self.is_session_valid(session_id):
            for tool in self.protected_tools:
                mcp.add_tool(tool)
            print("[OAuth] Protected tools activated")
        else:
            print("[OAuth] Invalid session; cannot activate tools")
