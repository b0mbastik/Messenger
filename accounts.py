"""Persistent account registry for certificate-backed messenger usernames."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from identity import PublicIdentity


ACCOUNTS_FILE = "accounts.json"


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

        return cls(
            username=payload["username"],
            signing_public_key=payload["signing_public_key"],
            key_agreement_public_key=payload["key_agreement_public_key"],
            identity_certificate=payload["identity_certificate"],
            created_at=payload["created_at"],
            updated_at=payload["updated_at"],
        )

    def to_json(self) -> dict[str, str]:
        return {
            "username": self.username,
            "signing_public_key": self.signing_public_key,
            "key_agreement_public_key": self.key_agreement_public_key,
            "identity_certificate": self.identity_certificate,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


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
        account = Account(
            username=username,
            signing_public_key=public_identity.signing_public_key,
            key_agreement_public_key=public_identity.key_agreement_public_key,
            identity_certificate=identity_certificate,
            created_at=timestamp,
            updated_at=timestamp,
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
