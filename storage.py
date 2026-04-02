"""In-memory session storage for connected messenger users."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Session:
    """Represents one connected client session."""

    username: str
    writer: Any
    address: str


class SessionStore:
    """Tracks live user sessions for the plaintext messenger."""

    def __init__(self) -> None:
        self._by_username: dict[str, Session] = {}
        self._by_writer: dict[Any, Session] = {}

    def register(self, username: str, writer: Any, address: str) -> bool:
        if username in self._by_username:
            return False

        session = Session(username=username, writer=writer, address=address)
        self._by_username[username] = session
        self._by_writer[writer] = session
        return True

    def unregister(self, writer: Any) -> Session | None:
        session = self._by_writer.pop(writer, None)
        if session is None:
            return None

        self._by_username.pop(session.username, None)
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

    def list_usernames(self) -> list[str]:
        return sorted(self._by_username)

    def active_sessions(self) -> list[Session]:
        return list(self._by_writer.values())
