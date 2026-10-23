"""URL policy checks at the standard-library request boundary.

Checks observe the effective request (including redirects). They log violations
without blocking I/O. Raw sockets and clients bypassing these APIs have only
the kernel monitor's IP/protocol policies.
"""
import builtins
import ipaddress
import re
from urllib.parse import urlsplit


def normalize_scheme(value):
    value = value.lower()
    if not re.fullmatch(r"[a-z*][a-z0-9+.*-]*", value):
        raise ValueError("invalid URL scheme policy")
    return value


def normalize_host(value):
    value = value.lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value or any(c.isspace() or c in "/@?#\x00" for c in value):
        raise ValueError("HOST must be a hostname or IP address, without URL, port, or user information")
    if ":" in value:
        return str(ipaddress.IPv6Address(value))
    # Encode individual labels so wildcard labels remain patterns.
    return ".".join(label.encode("idna").decode("ascii") for label in value.split("."))


def check(scheme, host):
    if not builtins._ANOTA_URL_ACTIVE():
        return
    builtins._ANOTA_CHECK_URL(scheme.lower(), normalize_host(host) if host else "")


def check_request(request):
    # Request.type/host are the fields used by urllib's actual handler.
    host = urlsplit("//" + request.host).hostname if request.host else ""
    check(request.type, host)


def check_http(connection, url):
    # An absolute-form request targets the URL host through a proxy. A CONNECT
    # tunnel targets _tunnel_host; otherwise the connection host is effective.
    parsed = urlsplit(url)
    scheme = "https" if getattr(connection, "_context", None) is not None else "http"
    host = connection._tunnel_host or connection.host
    if parsed.scheme and parsed.hostname:
        scheme, host = parsed.scheme, parsed.hostname
    check(scheme, host)
