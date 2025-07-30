# mcp_oauth_sdk/sdk.py

import os
import functools
import requests
from jose import jwt

class MCPOAuthSDK:
    def __init__(self, provider='google'):
        """
        Initialize the SDK with default provider 'google'.
        """
        self.provider = provider
        self.google_client_id = "833970626725-n9aku2mjrgtvkr5vqvhhomvmu4pjbp1o.apps.googleusercontent.com"
        self.google_discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
        self.jwks = None  # Cache the Google public keys

    def _get_google_jwks(self):
        """
        Fetch Google's JSON Web Key Set (JWKS) for signature verification.
        """
        if not self.jwks:
            discovery_doc = requests.get(self.google_discovery_url).json()
            jwks_uri = discovery_doc["jwks_uri"]
            self.jwks = requests.get(jwks_uri).json()
        return self.jwks

    def _verify_google_token(self, token):
        """
        Verify the Google ID token.
        """
        jwks = self._get_google_jwks()
        try:
            # Validate & decode
            payload = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=self.google_client_id,
                issuer="https://accounts.google.com"
            )
            return payload  # If successful
        except Exception as e:
            print(f"[OAuth] Token verification failed: {e}")
            return None

    def protect_tool(self, tool_func):
        """
        Decorator to protect MCP tools.
        """
        @functools.wraps(tool_func)
        def wrapper(*args, **kwargs):
            from mcp.server.fastmcp import get_current_request

            req = get_current_request()
            auth_header = req.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return {"error": "Unauthorized: Missing or invalid Authorization header"}

            token = auth_header.split(" ")[1]
            if self.provider == 'google':
                payload = self._verify_google_token(token)
                if not payload:
                    return {"error": "Unauthorized: Invalid token"}

                # Optional: add user info from token into tool call
                req.context['user'] = payload.get("email")  # or sub, name, etc.

            return tool_func(*args, **kwargs)
        return wrapper