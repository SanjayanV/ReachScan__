"""
web_utils.py — HTTP utility helpers.

VULNERABILITY: Uses requests.get() / requests.Session through a proxy
without stripping Proxy-Authorization headers on redirect.
CVE-2023-32681 (requests): Credential leakage on cross-origin redirect.

Call chain: main() → fetch_data() → requests.get()
             main() → post_report() → requests.post()
"""

import requests
from jinja2 import Environment, select_autoescape


def fetch_data(url: str, proxy: str = None) -> dict:
    """
    Fetch JSON data from an external API.

    ⚠️  VULNERABLE: If a proxy is supplied and the server issues a
    redirect to a different host, the Proxy-Authorization header is
    forwarded to the destination, leaking proxy credentials.
    CVE-2023-32681.

    Fix: Use requests >= 2.31.0, or manually strip the header on redirect
    via a custom Session hook.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # SINK: requests.get — CVE-2023-32681
    response = requests.get(url, proxies=proxies, timeout=10)  # noqa
    response.raise_for_status()
    return response.json()


def post_report(endpoint: str, payload: dict) -> bool:
    """
    POST a JSON report payload to an internal endpoint.

    ⚠️  Same CVE — requests.post is also a flagged sink.
    """
    # SINK: requests.post — CVE-2023-32681
    resp = requests.post(endpoint, json=payload, timeout=10)  # noqa
    return resp.status_code == 200


def render_dashboard(user_attrs: dict, template_str: str) -> str:
    """
    Render an HTML dashboard fragment for a user.

    ⚠️  VULNERABLE: Uses Jinja2 Environment with xmlattr filter.
    If user-controlled keys in `user_attrs` contain spaces or quotes,
    they are reflected into HTML attributes without escaping.
    CVE-2024-34064 (Jinja2).

    Fix: Sanitize attribute keys before passing to the template,
    or upgrade to Jinja2 >= 3.1.4.
    """
    # SINK: Environment — CVE-2024-34064
    env = Environment(autoescape=select_autoescape())  # noqa
    template = env.from_string(template_str)
    return template.render(user=user_attrs)
