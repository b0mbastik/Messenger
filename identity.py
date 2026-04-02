"""Long-term identity key handling for messenger clients."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

IDENTITY_FILE = "identity.json"
DEFAULT_IDENTITIES_DIR = "identities"


class IdentityError(Exception):
    """Raised when identity material is missing or malformed."""


@dataclass(slots=True)
class PublicIdentity:
    """Serializable public identity bundle."""

    signing_public_key: str
    key_agreement_public_key: str

    @property
    def signing_fingerprint(self) -> str:
        return fingerprint_key(self.signing_public_key)

    @property
    def key_agreement_fingerprint(self) -> str:
        return fingerprint_key(self.key_agreement_public_key)

    def as_message_fields(self) -> dict[str, str]:
        return {
            "signing_public_key": self.signing_public_key,
            "key_agreement_public_key": self.key_agreement_public_key,
        }


@dataclass(slots=True)
class ClientIdentity:
    """Persistent client identity with long-term Ed25519 and X25519 keys."""

    signing_private_key: Ed25519PrivateKey
    key_agreement_private_key: X25519PrivateKey
    path: Path

    @property
    def public_identity(self) -> PublicIdentity:
        return PublicIdentity(
            signing_public_key=encode_public_key_bytes(
                self.signing_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
            key_agreement_public_key=encode_public_key_bytes(
                self.key_agreement_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
        )

    def private_payload(self) -> dict[str, str | int]:
        return {
            "version": 1,
            "signing_private_key": encode_private_key_bytes(
                self.signing_private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
            "key_agreement_private_key": encode_private_key_bytes(
                self.key_agreement_private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
        }

    @property
    def signing_fingerprint(self) -> str:
        return self.public_identity.signing_fingerprint

    @property
    def key_agreement_fingerprint(self) -> str:
        return self.public_identity.key_agreement_fingerprint


def load_or_create_identity(identity_dir: str | Path) -> ClientIdentity:
    """Load an existing client identity or create a new one."""

    identity_path = Path(identity_dir) / IDENTITY_FILE
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(identity_path.parent, 0o700)
    except OSError:
        pass

    if identity_path.exists():
        return load_identity(identity_path)

    identity = ClientIdentity(
        signing_private_key=Ed25519PrivateKey.generate(),
        key_agreement_private_key=X25519PrivateKey.generate(),
        path=identity_path,
    )
    save_identity(identity)
    return identity


def default_identity_dir_for_username(username: str) -> Path:
    """Return the default per-username identity directory."""

    safe_username = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in username
    ).strip("._-")
    if not safe_username:
        safe_username = "user"
    return Path(DEFAULT_IDENTITIES_DIR) / safe_username


def load_identity(identity_path: str | Path) -> ClientIdentity:
    """Load a client identity from disk."""

    path = Path(identity_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IdentityError(f"Unable to read identity file '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IdentityError(f"Identity file '{path}' is not valid JSON.") from exc

    if payload.get("version") != 1:
        raise IdentityError(f"Identity file '{path}' has an unsupported version.")

    try:
        signing_private_key = Ed25519PrivateKey.from_private_bytes(
            decode_key_bytes(payload["signing_private_key"])
        )
        key_agreement_private_key = X25519PrivateKey.from_private_bytes(
            decode_key_bytes(payload["key_agreement_private_key"])
        )
    except KeyError as exc:
        raise IdentityError(f"Identity file '{path}' is missing '{exc.args[0]}'.") from exc
    except ValueError as exc:
        raise IdentityError(f"Identity file '{path}' contains invalid key material.") from exc

    return ClientIdentity(
        signing_private_key=signing_private_key,
        key_agreement_private_key=key_agreement_private_key,
        path=path,
    )


def save_identity(identity: ClientIdentity) -> None:
    """Persist a client identity to disk."""

    identity.path.write_text(
        json.dumps(identity.private_payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(identity.path, 0o600)
    except OSError:
        pass


def validate_public_identity(
    signing_public_key: str, key_agreement_public_key: str
) -> PublicIdentity:
    """Validate the public identity fields carried in protocol messages."""

    signing_bytes = decode_key_bytes(signing_public_key)
    agreement_bytes = decode_key_bytes(key_agreement_public_key)

    try:
        Ed25519PublicKey.from_public_bytes(signing_bytes)
        X25519PublicKey.from_public_bytes(agreement_bytes)
    except ValueError as exc:
        raise IdentityError("Identity public key material is invalid.") from exc

    return PublicIdentity(
        signing_public_key=encode_public_key_bytes(signing_bytes),
        key_agreement_public_key=encode_public_key_bytes(agreement_bytes),
    )


def encode_private_key_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encode_public_key_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_key_bytes(value: object) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise IdentityError("Identity key data must be a non-empty base64 string.")

    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise IdentityError("Identity key data is not valid base64.") from exc


def fingerprint_key(encoded_public_key: str) -> str:
    """Return a SHA-256 fingerprint for a base64-encoded raw public key."""

    digest = hashlib.sha256(decode_key_bytes(encoded_public_key)).hexdigest()
    return digest
