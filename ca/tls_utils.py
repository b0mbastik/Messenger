"""TLS configuration helpers for the messenger transport."""

from __future__ import annotations

import ssl


TLS_VERSION_MAP = {
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}


def parse_tls_version(version: str) -> ssl.TLSVersion:
    """Translate a CLI TLS version string into ``ssl.TLSVersion``."""

    try:
        return TLS_VERSION_MAP[version]
    except KeyError as exc:
        raise ValueError(f"Unsupported TLS version '{version}'.") from exc


def build_server_ssl_context(
    certfile: str, keyfile: str, *, minimum_version: ssl.TLSVersion
) -> ssl.SSLContext:
    """Create a hardened TLS server context for the messenger."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = minimum_version
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def build_client_ssl_context(
    ca_certfile: str, *, minimum_version: ssl.TLSVersion
) -> ssl.SSLContext:
    """Create a TLS client context that verifies the messenger server."""

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_certfile)
    context.minimum_version = minimum_version
    context.options |= ssl.OP_NO_COMPRESSION
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context
