"""In-memory session storage for connected messenger users."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shared.e2ee import EncryptedEnvelope, EnvelopeReplayCache
from shared.identity import PublicIdentity


@dataclass(slots=True)
class Session:
    """Represents one connected client session."""

    username: str
    writer: Any
    address: str
    public_identity: PublicIdentity
    key_agreement_signature: str
    identity_certificate: str


class SessionStore:
    """Tracks live user sessions for the plaintext messenger."""

    def __init__(self) -> None:
        self._by_username: dict[str, Session] = {}
        self._by_writer: dict[Any, Session] = {}
        self._by_signing_key: dict[str, Session] = {}
        self._recent_envelopes = EnvelopeReplayCache()

    def register(
        self,
        username: str,
        writer: Any,
        address: str,
        public_identity: PublicIdentity,
        key_agreement_signature: str,
        identity_certificate: str,
    ) -> tuple[bool, str | None]:
        if username in self._by_username:
            return False, "username is already connected"
        if public_identity.signing_public_key in self._by_signing_key:
            return False, "signing identity is already connected"

        session = Session(
            username=username,
            writer=writer,
            address=address,
            public_identity=public_identity,
            key_agreement_signature=key_agreement_signature,
            identity_certificate=identity_certificate,
        )
        self._by_username[username] = session
        self._by_writer[writer] = session
        self._by_signing_key[public_identity.signing_public_key] = session
        return True, None

    def unregister(self, writer: Any) -> Session | None:
        session = self._by_writer.pop(writer, None)
        if session is None:
            return None

        self._by_username.pop(session.username, None)
        self._by_signing_key.pop(session.public_identity.signing_public_key, None)
        return session

    def rename(self, writer: Any, new_username: str) -> tuple[bool, str | None]:
        if new_username in self._by_username:
            return False, "username is already in use"

        session = self._by_writer.get(writer)
        if session is None:
            return False, "session is not registered"

        self._by_username.pop(session.username, None)
        session.username = new_username
        self._by_username[new_username] = session
        return True, None

    def get_by_writer(self, writer: Any) -> Session | None:
        return self._by_writer.get(writer)

    def get_by_username(self, username: str) -> Session | None:
        return self._by_username.get(username)

    def get_by_signing_key(self, signing_public_key: str) -> Session | None:
        return self._by_signing_key.get(signing_public_key)

    def list_usernames(self) -> list[str]:
        return sorted(self._by_username)

    def active_sessions(self) -> list[Session]:
        return list(self._by_writer.values())

    def check_and_remember_envelope(self, envelope: EncryptedEnvelope) -> None:
        self._recent_envelopes.check_and_remember(envelope)
