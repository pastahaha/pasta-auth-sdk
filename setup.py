from setuptools import setup, find_packages

setup(
    name="mcp-oauth-sdk",
    version="0.1.0",
    description="OAuth SDK for MCP Server (Google OIDC)",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-jose"
    ],
)