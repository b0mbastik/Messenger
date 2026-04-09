"""Helpers for newline-delimited JSON messages used by the messenger."""

from __future__ import annotations

import json
import re
from typing import Any

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888

Message = dict[str, Any]
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")


class ProtocolError(Exception):
    """Raised when a peer sends malformed or unexpected protocol data."""


_SCHEMAS: dict[str, dict[str, type | tuple[type, ...]]] = {
    "register": {
        "username": str,
        "password": str,
        "signing_public_key": str,
        "key_agreement_public_key": str,
        "key_agreement_signature": str,
    },
    "login": {
        "username": str,
        "password": str,
        "signing_public_key": str,
        "key_agreement_public_key": str,
        "key_agreement_signature": str,
        "identity_certificate": str,
    },
    "recover_certificate": {
        "username": str,
        "password": str,
        "signing_public_key": str,
        "key_agreement_public_key": str,
        "key_agreement_signature": str,
    },
    "register_ok": {"username": str, "identity_certificate": str},
    "register_error": {"text": str},
    "list_users": {},
    "users_list": {"users": list},
    "lookup_user": {"username": str},
    "user_bundle": {
        "username": str,
        "signing_public_key": str,
        "key_agreement_public_key": str,
        "key_agreement_signature": str,
        "identity_certificate": str,
    },
    "user_bundle_error": {"username": str, "text": str},
    "direct_message": {
        "to": str,
        "envelope": dict,
    },
    "incoming_message": {
        "signing_public_key": str,
        "identity_certificate": str,
        "envelope": dict,
    },
    "delivery_error": {"text": str},
    "system_message": {"text": str},
    "rename": {"new_username": str},
    "rename_ok": {"username": str},
    "rename_error": {"text": str},
    "disconnect": {},
}


def validate_message(message: object, *, allowed_types: set[str] | None = None) -> Message:
    """Validate a decoded JSON message and return it as a protocol message."""

    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")

    message_type = message.get("type")
    if not isinstance(message_type, str):
        raise ProtocolError("message is missing a string 'type' field")

    if allowed_types is not None and message_type not in allowed_types:
        raise ProtocolError(f"message type '{message_type}' is not allowed here")

    schema = _SCHEMAS.get(message_type)
    if schema is None:
        raise ProtocolError(f"unsupported message type '{message_type}'")

    for field, expected_type in schema.items():
        if field not in message:
            raise ProtocolError(f"message type '{message_type}' is missing '{field}'")
        value = message[field]
        if not isinstance(value, expected_type):
            expected_name = _type_name(expected_type)
            raise ProtocolError(
                f"field '{field}' in '{message_type}' must be {expected_name}"
            )
        if expected_type is str and not value.strip():
            raise ProtocolError(f"field '{field}' in '{message_type}' must not be empty")

    if message_type == "users_list":
        users = message["users"]
        if not all(isinstance(user, str) and user.strip() for user in users):
            raise ProtocolError("'users' must contain non-empty strings")

    if message_type in {"direct_message", "incoming_message"}:
        _validate_encrypted_envelope(message["envelope"])

    if message_type == "direct_message" and message["to"] != message["envelope"]["to"]:
        raise ProtocolError("direct_message routing target must match encrypted envelope recipient")

    return dict(message)


def encode_message(message: Message) -> bytes:
    """Serialize a message as newline-delimited JSON."""

    validate_message(message)
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


async def send_message(writer: Any, message: Message) -> None:
    """Send one validated message to a stream writer."""

    writer.write(encode_message(message))
    await writer.drain()


async def read_message(
    reader: Any, *, allowed_types: set[str] | None = None
) -> Message | None:
    """Read one message from a stream reader.

    Returns ``None`` on clean EOF.
    """

    raw_line = await reader.readline()
    if raw_line == b"":
        return None

    try:
        decoded = json.loads(raw_line.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProtocolError("message was not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError("message was not valid JSON") from exc

    return validate_message(decoded, allowed_types=allowed_types)


def _type_name(expected_type: type | tuple[type, ...]) -> str:
    if isinstance(expected_type, tuple):
        return " or ".join(item.__name__ for item in expected_type)
    return expected_type.__name__


def _validate_encrypted_envelope(envelope: object) -> None:
    if not isinstance(envelope, dict):
        raise ProtocolError("encrypted envelope must be a JSON object")

    required_fields = (
        "message_id",
        "protocol_version",
        "timestamp",
        "from",
        "to",
        "sender_ephemeral_public_key",
        "nonce",
        "ciphertext",
        "signature",
    )
    for field in required_fields:
        value = envelope.get(field)
        if not isinstance(value, str):
            raise ProtocolError(f"encrypted envelope field '{field}' must be str")
        if not value.strip():
            raise ProtocolError(f"encrypted envelope field '{field}' must not be empty")

    for field in ("from", "to"):
        if not is_valid_username(envelope[field]):
            raise ProtocolError(f"encrypted envelope field '{field}' must contain a valid username")


def is_valid_username(username: object) -> bool:
    return isinstance(username, str) and USERNAME_PATTERN.fullmatch(username) is not None
