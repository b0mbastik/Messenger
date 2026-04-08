"""Long-term identity key handling for messenger clients."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from shared.paths import DEFAULT_IDENTITIES_ROOT

IDENTITY_FILE = "identity.json"
IDENTITY_CERT_FILE = "identity-cert.pem"
DEFAULT_IDENTITIES_DIR = str(DEFAULT_IDENTITIES_ROOT)
KEY_AGREEMENT_BINDING_CONTEXT = b"messenger-key-agreement:v1"
ENCRYPTED_IDENTITY_VERSION = 2


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

    def private_payload(self, passphrase: str | bytes) -> dict[str, str | int]:
        encoded_passphrase = normalize_identity_passphrase(passphrase)
        return {
            "version": ENCRYPTED_IDENTITY_VERSION,
            "signing_private_key_pem": self.signing_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(encoded_passphrase),
            ).decode("ascii"),
            "key_agreement_private_key_pem": self.key_agreement_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(encoded_passphrase),
            ).decode("ascii"),
        }

    @property
    def signing_fingerprint(self) -> str:
        return self.public_identity.signing_fingerprint

    @property
    def key_agreement_fingerprint(self) -> str:
        return self.public_identity.key_agreement_fingerprint

    def sign_key_agreement_binding(self, username: str) -> str:
        """Sign the user's X25519 public key with the long-term Ed25519 identity."""

        signature = self.signing_private_key.sign(
            build_key_agreement_binding_payload(
                username,
                self.public_identity.key_agreement_public_key,
            )
        )
        return encode_public_key_bytes(signature)


def normalize_identity_passphrase(passphrase: str | bytes) -> bytes:
    """Normalize and validate the identity passphrase."""

    if isinstance(passphrase, str):
        encoded = passphrase.encode("utf-8")
    elif isinstance(passphrase, bytes):
        encoded = passphrase
    else:
        raise IdentityError("Identity passphrase must be text or bytes.")

    if not encoded:
        raise IdentityError("Identity passphrase must not be empty.")
    return encoded


def load_or_create_identity(
    identity_dir: str | Path,
    *,
    passphrase: str | bytes,
) -> ClientIdentity:
    """Load an existing client identity or create a new one."""

    identity_path = Path(identity_dir) / IDENTITY_FILE
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(identity_path.parent, 0o700)
    except OSError:
        pass

    encoded_passphrase = normalize_identity_passphrase(passphrase)
    if identity_path.exists():
        return load_identity(identity_path, passphrase=encoded_passphrase)

    identity = ClientIdentity(
        signing_private_key=Ed25519PrivateKey.generate(),
        key_agreement_private_key=X25519PrivateKey.generate(),
        path=identity_path,
    )
    save_identity(identity, passphrase=encoded_passphrase)
    return identity


def default_identity_dir_for_username(username: str) -> Path:
    """Return the default per-username identity directory."""

    safe_username = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in username
    ).strip("._-")
    if not safe_username:
        safe_username = "user"
    return Path(DEFAULT_IDENTITIES_DIR) / safe_username


def default_certificate_path(identity_dir: str | Path) -> Path:
    """Return the default path for a client identity certificate."""

    return Path(identity_dir) / IDENTITY_CERT_FILE


def load_identity(
    identity_path: str | Path,
    *,
    passphrase: str | bytes,
) -> ClientIdentity:
    """Load a client identity from disk."""

    path = Path(identity_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IdentityError(f"Unable to read identity file '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IdentityError(f"Identity file '{path}' is not valid JSON.") from exc

    version = payload.get("version")
    if version == ENCRYPTED_IDENTITY_VERSION:
        return _load_encrypted_identity(path, payload, passphrase=passphrase)

    raise IdentityError(
        f"Identity file '{path}' has unsupported version '{version}'. "
        f"Only encrypted version {ENCRYPTED_IDENTITY_VERSION} identities are accepted."
    )


def save_identity(identity: ClientIdentity, *, passphrase: str | bytes) -> None:
    """Persist a client identity to disk."""

    identity.path.write_text(
        json.dumps(identity.private_payload(passphrase), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(identity.path, 0o600)
    except OSError:
        pass


def _load_encrypted_identity(
    path: Path,
    payload: dict[str, Any],
    *,
    passphrase: str | bytes,
) -> ClientIdentity:
    try:
        signing_private_key = _load_private_key_from_pem(
            payload["signing_private_key_pem"],
            passphrase,
            expected_type=Ed25519PrivateKey,
            field_name="signing_private_key_pem",
        )
        key_agreement_private_key = _load_private_key_from_pem(
            payload["key_agreement_private_key_pem"],
            passphrase,
            expected_type=X25519PrivateKey,
            field_name="key_agreement_private_key_pem",
        )
    except KeyError as exc:
        raise IdentityError(f"Identity file '{path}' is missing '{exc.args[0]}'.") from exc

    return ClientIdentity(
        signing_private_key=signing_private_key,
        key_agreement_private_key=key_agreement_private_key,
        path=path,
    )
def _load_private_key_from_pem(
    pem_text: str,
    passphrase: str | bytes,
    *,
    expected_type: type,
    field_name: str,
) -> Any:
    if not isinstance(pem_text, str) or not pem_text.strip():
        raise IdentityError(f"Identity field '{field_name}' must be non-empty PEM text.")

    try:
        private_key = serialization.load_pem_private_key(
            pem_text.encode("ascii"),
            password=normalize_identity_passphrase(passphrase),
        )
    except (TypeError, ValueError) as exc:
        raise IdentityError("Unable to decrypt identity private keys. Check the passphrase.") from exc

    if not isinstance(private_key, expected_type):
        raise IdentityError(f"Identity field '{field_name}' contains the wrong key type.")
    return private_key


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


def build_key_agreement_binding_payload(
    username: str, key_agreement_public_key: str
) -> bytes:
    """Return the canonical payload signed to bind a user to an X25519 key."""

    username_bytes = username.encode("utf-8")
    if not username_bytes.strip():
        raise IdentityError("Username must be present to bind the key-agreement key.")

    key_bytes = decode_key_bytes(key_agreement_public_key)
    return (
        KEY_AGREEMENT_BINDING_CONTEXT
        + b"\x00"
        + username_bytes
        + b"\x00"
        + key_bytes
    )


def verify_key_agreement_binding(
    signing_public_key: str, username: str, key_agreement_public_key: str, signature: str
) -> None:
    """Verify that an Ed25519 identity key signed the supplied X25519 key."""

    public_key = Ed25519PublicKey.from_public_bytes(decode_key_bytes(signing_public_key))
    try:
        public_key.verify(
            decode_key_bytes(signature),
            build_key_agreement_binding_payload(username, key_agreement_public_key),
        )
    except InvalidSignature as exc:
        raise IdentityError("Key-agreement public key signature is invalid.") from exc
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
