"""Client-side remembered login helpers."""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SESSION_FILE = "session.json"
SESSION_KEY_FILE = "session.key"
SESSION_VERSION = 1


def load_saved_password(identity_dir: str | Path, username: str) -> str | None:
    session_path = Path(identity_dir) / SESSION_FILE
    key_path = Path(identity_dir) / SESSION_KEY_FILE

    try:
        payload = json.loads(session_path.read_text(encoding="utf-8"))
        key = key_path.read_bytes()
    except (OSError, json.JSONDecodeError):
        return None

    if payload.get("version") != SESSION_VERSION or payload.get("username") != username:
        return None

    nonce = _decode_base64(payload.get("nonce"))
    ciphertext = _decode_base64(payload.get("ciphertext"))
    if nonce is None or ciphertext is None or len(key) != 32:
        return None

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, username.encode("utf-8"))
        return plaintext.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def save_password_session(identity_dir: str | Path, username: str, password: str) -> None:
    base_dir = Path(identity_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base_dir, 0o700)
    except OSError:
        pass

    key_path = base_dir / SESSION_KEY_FILE
    session_path = base_dir / SESSION_FILE
    key = _load_or_create_key(key_path)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, password.encode("utf-8"), username.encode("utf-8"))
    session_path.write_text(
        json.dumps(
            {
                "version": SESSION_VERSION,
                "username": username,
                "nonce": _encode_base64(nonce),
                "ciphertext": _encode_base64(ciphertext),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _chmod_if_possible(session_path, 0o600)


def clear_password_session(identity_dir: str | Path) -> None:
    for path in (Path(identity_dir) / SESSION_FILE, Path(identity_dir) / SESSION_KEY_FILE):
        try:
            path.unlink()
        except OSError:
            pass


def _load_or_create_key(path: Path) -> bytes:
    try:
        key = path.read_bytes()
    except OSError:
        key = secrets.token_bytes(32)
        path.write_bytes(key)
        _chmod_if_possible(path, 0o600)
        return key

    if len(key) != 32:
        key = secrets.token_bytes(32)
        path.write_bytes(key)
        _chmod_if_possible(path, 0o600)
    return key


def _encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_base64(value: object) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        return None


def _chmod_if_possible(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass
