"""Project path helpers for the messenger layout."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CA_CERTS_DIR = Path("ca") / "certs"
SERVER_DATA_DIR = Path("server") / "data"
DEFAULT_IDENTITIES_ROOT = Path("client") / "identities"

DEFAULT_CA_CERT_PATH = CA_CERTS_DIR / "ca-cert.pem"
DEFAULT_CA_KEY_PATH = CA_CERTS_DIR / "ca-key.pem"
DEFAULT_SERVER_CERT_PATH = CA_CERTS_DIR / "server-cert.pem"
DEFAULT_SERVER_KEY_PATH = CA_CERTS_DIR / "server-key.pem"
DEFAULT_ACCOUNTS_FILE = SERVER_DATA_DIR / "accounts.json"


def resolve_project_path(path: str | Path) -> Path:
    """Resolve relative paths from the repository root."""

    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return PROJECT_ROOT / candidate
