"""Persistent account registry for certificate-backed messenger usernames."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from shared.identity import PublicIdentity


ACCOUNTS_FILE = "accounts.json"
PASSWORD_SCRYPT_N = 2**14
PASSWORD_SCRYPT_R = 8
PASSWORD_SCRYPT_P = 1
PASSWORD_HASH_LENGTH = 32


class AccountRegistryError(Exception):
    """Raised when the on-disk account registry is missing or malformed."""


@dataclass(slots=True)
class Account:
    """Represents a permanently registered messenger account."""

    username: str
    signing_public_key: str
    key_agreement_public_key: str
    identity_certificate: str
    created_at: str
    updated_at: str
    password_salt: str | None = None
    password_hash: str | None = None

    @classmethod
    def from_json(cls, payload: object) -> "Account":
        if not isinstance(payload, dict):
            raise AccountRegistryError("Account entry must be a JSON object.")

        required_fields = {
            "username",
            "signing_public_key",
            "key_agreement_public_key",
            "identity_certificate",
            "created_at",
            "updated_at",
        }
        missing = [field for field in required_fields if not isinstance(payload.get(field), str)]
        if missing:
            raise AccountRegistryError(
                f"Account entry is missing string field(s): {', '.join(sorted(missing))}."
            )

        password_salt = payload.get("password_salt")
        password_hash = payload.get("password_hash")
        if password_salt is not None and not isinstance(password_salt, str):
            raise AccountRegistryError("Account entry field 'password_salt' must be a string.")
        if password_hash is not None and not isinstance(password_hash, str):
            raise AccountRegistryError("Account entry field 'password_hash' must be a string.")
        if (password_salt is None) != (password_hash is None):
            raise AccountRegistryError(
                "Account entry password fields must include both 'password_salt' and 'password_hash'."
            )

        return cls(
            username=payload["username"],
            signing_public_key=payload["signing_public_key"],
            key_agreement_public_key=payload["key_agreement_public_key"],
            identity_certificate=payload["identity_certificate"],
            created_at=payload["created_at"],
            updated_at=payload["updated_at"],
            password_salt=password_salt,
            password_hash=password_hash,
        )

    def to_json(self) -> dict[str, str]:
        payload = {
            "username": self.username,
            "signing_public_key": self.signing_public_key,
            "key_agreement_public_key": self.key_agreement_public_key,
            "identity_certificate": self.identity_certificate,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if self.password_salt is not None and self.password_hash is not None:
            payload["password_salt"] = self.password_salt
            payload["password_hash"] = self.password_hash
        return payload

    @property
    def has_password(self) -> bool:
        return self.password_salt is not None and self.password_hash is not None


class AccountRegistry:
    """Stores persistent username-to-identity bindings."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._accounts: dict[str, Account] = {}
        self._load()

    def get(self, username: str) -> Account | None:
        return self._accounts.get(username)

    def find_by_signing_key(self, signing_public_key: str) -> Account | None:
        for account in self._accounts.values():
            if account.signing_public_key == signing_public_key:
                return account
        return None

    def create_account(
        self,
        username: str,
        public_identity: PublicIdentity,
        identity_certificate: str,
        password: str,
    ) -> Account:
        if username in self._accounts:
            raise AccountRegistryError(f"Username '{username}' is already registered.")
        existing_account = self.find_by_signing_key(public_identity.signing_public_key)
        if existing_account is not None:
            raise AccountRegistryError(
                "This signing identity is already permanently bound to "
                f"username '{existing_account.username}'."
            )

        timestamp = self._timestamp()
        password_salt, password_hash = hash_password(password)
        account = Account(
            username=username,
            signing_public_key=public_identity.signing_public_key,
            key_agreement_public_key=public_identity.key_agreement_public_key,
            identity_certificate=identity_certificate,
            created_at=timestamp,
            updated_at=timestamp,
            password_salt=password_salt,
            password_hash=password_hash,
        )
        self._accounts[username] = account
        self._save()
        return account

    def update_key_agreement_key(self, username: str, key_agreement_public_key: str) -> Account:
        account = self._accounts[username]
        account.key_agreement_public_key = key_agreement_public_key
        account.updated_at = self._timestamp()
        self._save()
        return account

    def verify_or_set_password(self, username: str, password: str) -> tuple[bool, bool]:
        account = self._accounts[username]
        if account.has_password:
            assert account.password_salt is not None
            assert account.password_hash is not None
            return verify_password(password, account.password_salt, account.password_hash), False

        password_salt, password_hash = hash_password(password)
        account.password_salt = password_salt
        account.password_hash = password_hash
        account.updated_at = self._timestamp()
        self._save()
        return True, True

    def matches_identity(
        self, username: str, signing_public_key: str, identity_certificate: str
    ) -> bool:
        account = self._accounts.get(username)
        if account is None:
            return False

        return (
            account.signing_public_key == signing_public_key
            and account.identity_certificate.strip() == identity_certificate.strip()
        )

    def _load(self) -> None:
        if not self.path.exists():
            return

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise AccountRegistryError(
                f"Unable to read account registry '{self.path}': {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise AccountRegistryError(
                f"Account registry '{self.path}' is not valid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise AccountRegistryError("Account registry root must be a JSON object.")

        self._accounts = {
            username: Account.from_json(account_payload)
            for username, account_payload in payload.items()
        }

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        serialized = {
            username: account.to_json()
            for username, account in sorted(self._accounts.items())
        }
        self.path.write_text(
            json.dumps(serialized, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_password(password: str, *, salt: bytes | None = None) -> tuple[str, str]:
    password_bytes = _normalize_password(password)
    password_salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password_bytes,
        salt=password_salt,
        n=PASSWORD_SCRYPT_N,
        r=PASSWORD_SCRYPT_R,
        p=PASSWORD_SCRYPT_P,
        dklen=PASSWORD_HASH_LENGTH,
    )
    return _encode_base64(password_salt), _encode_base64(digest)


def verify_password(password: str, password_salt: str, password_hash: str) -> bool:
    password_bytes = _normalize_password(password)
    try:
        salt_bytes = _decode_base64(password_salt)
        expected_hash = _decode_base64(password_hash)
    except ValueError as exc:
        raise AccountRegistryError("Stored password verifier is not valid base64.") from exc

    actual_hash = hashlib.scrypt(
        password_bytes,
        salt=salt_bytes,
        n=PASSWORD_SCRYPT_N,
        r=PASSWORD_SCRYPT_R,
        p=PASSWORD_SCRYPT_P,
        dklen=len(expected_hash),
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def _normalize_password(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise AccountRegistryError("Password must be a non-empty string.")
    return password.encode("utf-8")


def _encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_base64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)
