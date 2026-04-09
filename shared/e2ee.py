"""Application-layer end-to-end encryption helpers for messenger messages."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from dataclasses import dataclass
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ca.cert_utils import validate_client_certificate
from shared.identity import (
    ClientIdentity,
    decode_key_bytes,
    encode_public_key_bytes,
    verify_key_agreement_binding,
)
from shared.protocol import is_valid_username

HKDF_INFO_CONTEXT = b"messenger-e2ee:key:v1"
AEAD_AAD_CONTEXT = b"messenger-e2ee:aad:v1"
SIGNATURE_CONTEXT = b"messenger-e2ee:signature:v1"
ENVELOPE_PROTOCOL_VERSION = "messenger-e2ee-envelope:v1"
ENVELOPE_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"
MAX_ENVELOPE_CLOCK_SKEW = timedelta(minutes=5)
NONCE_SIZE = 12
AES_KEY_SIZE = 32
X25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
AESGCM_TAG_SIZE = 16


class MessageCryptoError(Exception):
    """Raised when end-to-end encryption state is invalid."""


class EnvelopeReplayCache:
    """Tracks recently accepted envelopes and rejects duplicate message IDs."""

    def __init__(self, *, max_skew: timedelta = MAX_ENVELOPE_CLOCK_SKEW) -> None:
        self.max_skew = max_skew
        self._seen: dict[tuple[str, str, str], datetime] = {}

    def check_and_remember(
        self,
        envelope: EncryptedEnvelope,
        *,
        now: datetime | None = None,
    ) -> datetime:
        current_time = now or datetime.now(timezone.utc)
        parsed_timestamp = validate_envelope_timestamp_freshness(
            envelope,
            now=current_time,
            max_skew=self.max_skew,
        )
        self._purge_expired(current_time)

        cache_key = (
            envelope.sender_username,
            envelope.recipient_username,
            envelope.message_id,
        )
        if cache_key in self._seen:
            raise MessageCryptoError("Encrypted envelope replay detected.")

        self._seen[cache_key] = parsed_timestamp + self.max_skew
        return parsed_timestamp

    def _purge_expired(self, current_time: datetime) -> None:
        expired_keys = [
            key for key, expires_at in self._seen.items() if expires_at < current_time
        ]
        for key in expired_keys:
            self._seen.pop(key, None)


@dataclass(slots=True)
class RecipientBundle:
    """A connected recipient's certified encryption bundle."""

    username: str
    signing_public_key: str
    key_agreement_public_key: str
    key_agreement_signature: str
    identity_certificate: str


@dataclass(slots=True, frozen=True)
class EncryptedEnvelope:
    """Signed encrypted message envelope passed through the server."""

    message_id: str
    protocol_version: str
    timestamp: str
    sender_username: str
    recipient_username: str
    sender_ephemeral_public_key: str
    nonce: str
    ciphertext: str
    signature: str

    def as_message(self) -> dict[str, str]:
        return {
            "message_id": self.message_id,
            "protocol_version": self.protocol_version,
            "timestamp": self.timestamp,
            "from": self.sender_username,
            "to": self.recipient_username,
            "sender_ephemeral_public_key": self.sender_ephemeral_public_key,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "signature": self.signature,
        }

    def unsigned_message(self) -> dict[str, str]:
        payload = self.as_message()
        payload.pop("signature")
        return payload


def validate_recipient_bundle(
    bundle: RecipientBundle,
    ca_certificate: x509.Certificate,
) -> RecipientBundle:
    """Verify the CA-issued identity and current X25519 binding for a recipient."""

    try:
        validate_client_certificate(
            bundle.identity_certificate,
            bundle.username,
            bundle.signing_public_key,
            ca_certificate,
        )
        verify_key_agreement_binding(
            bundle.signing_public_key,
            bundle.username,
            bundle.key_agreement_public_key,
            bundle.key_agreement_signature,
        )
    except Exception as exc:
        raise MessageCryptoError(f"Recipient identity verification failed: {exc}") from exc

    return bundle


def encrypt_message_for_recipient(
    sender_identity: ClientIdentity,
    sender_username: str,
    recipient_bundle: RecipientBundle,
    plaintext: str,
) -> dict[str, str]:
    """Encrypt and sign a direct message for one recipient."""

    plaintext_bytes = plaintext.encode("utf-8")
    if not plaintext_bytes.strip():
        raise MessageCryptoError("Message text must not be empty.")

    ephemeral_private_key = X25519PrivateKey.generate()
    sender_ephemeral_public_key = encode_public_key_bytes(
        ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    derived_key = _derive_message_key(
        ephemeral_private_key,
        peer_public_key=recipient_bundle.key_agreement_public_key,
        sender_username=sender_username,
        recipient_username=recipient_bundle.username,
        sender_ephemeral_public_key=sender_ephemeral_public_key,
        recipient_key_agreement_public_key=recipient_bundle.key_agreement_public_key,
    )
    message_id = str(uuid.uuid4())
    timestamp = _format_envelope_timestamp(datetime.now(timezone.utc))
    nonce = os.urandom(NONCE_SIZE)
    unsigned_envelope = EncryptedEnvelope(
        message_id=message_id,
        protocol_version=ENVELOPE_PROTOCOL_VERSION,
        timestamp=timestamp,
        sender_username=sender_username,
        recipient_username=recipient_bundle.username,
        sender_ephemeral_public_key=sender_ephemeral_public_key,
        nonce=_encode_base64(nonce),
        ciphertext="",
        signature="",
    )
    aad = _build_aad(unsigned_envelope)
    ciphertext = AESGCM(derived_key).encrypt(nonce, plaintext_bytes, aad)
    envelope = EncryptedEnvelope(
        message_id=message_id,
        protocol_version=ENVELOPE_PROTOCOL_VERSION,
        timestamp=timestamp,
        sender_username=sender_username,
        recipient_username=recipient_bundle.username,
        sender_ephemeral_public_key=sender_ephemeral_public_key,
        nonce=_encode_base64(nonce),
        ciphertext=_encode_base64(ciphertext),
        signature="",
    )
    signature = sender_identity.signing_private_key.sign(_build_signature_payload(envelope))
    return EncryptedEnvelope(
        message_id=envelope.message_id,
        protocol_version=envelope.protocol_version,
        timestamp=envelope.timestamp,
        sender_username=envelope.sender_username,
        recipient_username=envelope.recipient_username,
        sender_ephemeral_public_key=envelope.sender_ephemeral_public_key,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        signature=_encode_base64(signature),
    ).as_message()


def decrypt_message_from_sender(
    recipient_identity: ClientIdentity,
    recipient_username: str,
    sender_signing_public_key: str,
    sender_identity_certificate: str,
    envelope: EncryptedEnvelope | object,
    ca_certificate: x509.Certificate,
    replay_cache: EnvelopeReplayCache | None = None,
) -> str:
    """Verify and decrypt an incoming direct message."""

    parsed_envelope = parse_encrypted_envelope(envelope)
    if parsed_envelope.recipient_username != recipient_username:
        raise MessageCryptoError("Encrypted envelope recipient does not match this client.")

    try:
        validate_client_certificate(
            sender_identity_certificate,
            parsed_envelope.sender_username,
            sender_signing_public_key,
            ca_certificate,
        )
    except Exception as exc:
        raise MessageCryptoError(f"Sender identity verification failed: {exc}") from exc

    try:
        sender_public_key = Ed25519PublicKey.from_public_bytes(
            decode_key_bytes(sender_signing_public_key)
        )
        sender_public_key.verify(
            decode_key_bytes(parsed_envelope.signature),
            _build_signature_payload(parsed_envelope),
        )
    except Exception as exc:
        raise MessageCryptoError(f"Message signature verification failed: {exc}") from exc

    try:
        derived_key = _derive_message_key(
            recipient_identity.key_agreement_private_key,
            peer_public_key=parsed_envelope.sender_ephemeral_public_key,
            sender_username=parsed_envelope.sender_username,
            recipient_username=recipient_username,
            sender_ephemeral_public_key=parsed_envelope.sender_ephemeral_public_key,
            recipient_key_agreement_public_key=recipient_identity.public_identity.key_agreement_public_key,
        )
        plaintext = AESGCM(derived_key).decrypt(
            _decode_base64(parsed_envelope.nonce),
            _decode_base64(parsed_envelope.ciphertext),
            _build_aad(parsed_envelope),
        )
    except Exception as exc:
        raise MessageCryptoError(f"Message decryption failed: {exc}") from exc

    try:
        plaintext_text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MessageCryptoError(f"Message decryption failed: {exc}") from exc
    if replay_cache is not None:
        replay_cache.check_and_remember(parsed_envelope)
    return plaintext_text


def parse_encrypted_envelope(envelope: EncryptedEnvelope | object) -> EncryptedEnvelope:
    """Validate and normalize an encrypted envelope."""

    if isinstance(envelope, EncryptedEnvelope):
        return envelope
    if not isinstance(envelope, dict):
        raise MessageCryptoError("Encrypted envelope must be a JSON object.")

    required_fields = {
        "message_id": "message_id",
        "protocol_version": "protocol_version",
        "timestamp": "timestamp",
        "from": "sender_username",
        "to": "recipient_username",
        "sender_ephemeral_public_key": "sender_ephemeral_public_key",
        "nonce": "nonce",
        "ciphertext": "ciphertext",
        "signature": "signature",
    }
    values: dict[str, str] = {}
    for field_name, normalized_name in required_fields.items():
        raw_value = envelope.get(field_name)
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise MessageCryptoError(
                f"Encrypted envelope field '{field_name}' must be a non-empty string."
            )
        values[normalized_name] = raw_value

    try:
        uuid.UUID(values["message_id"])
    except ValueError as exc:
        raise MessageCryptoError("Encrypted envelope message_id must be a valid UUID.") from exc

    if values["protocol_version"] != ENVELOPE_PROTOCOL_VERSION:
        raise MessageCryptoError(
            "Encrypted envelope protocol_version is not supported by this client."
        )

    _parse_envelope_timestamp(values["timestamp"])

    for field_name in ("sender_username", "recipient_username"):
        if not is_valid_username(values[field_name]):
            raise MessageCryptoError(
                f"Encrypted envelope {field_name.removesuffix('_username')} must be a valid username."
            )

    sender_ephemeral_public_key = _decode_base64(values["sender_ephemeral_public_key"])
    if len(sender_ephemeral_public_key) != X25519_PUBLIC_KEY_SIZE:
        raise MessageCryptoError(
            "Encrypted envelope sender_ephemeral_public_key must encode 32 bytes."
        )

    nonce = _decode_base64(values["nonce"])
    if len(nonce) != NONCE_SIZE:
        raise MessageCryptoError(f"Encrypted envelope nonce must encode {NONCE_SIZE} bytes.")

    ciphertext = _decode_base64(values["ciphertext"])
    if len(ciphertext) < AESGCM_TAG_SIZE:
        raise MessageCryptoError(
            "Encrypted envelope ciphertext is too short to contain an AES-GCM tag."
        )

    signature = _decode_base64(values["signature"])
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise MessageCryptoError(
            "Encrypted envelope signature must encode 64 bytes."
        )

    return EncryptedEnvelope(**values)


def validate_envelope_timestamp_freshness(
    envelope: EncryptedEnvelope,
    *,
    now: datetime | None = None,
    max_skew: timedelta = MAX_ENVELOPE_CLOCK_SKEW,
) -> datetime:
    """Reject envelopes that are too far from the server's current UTC clock."""

    parsed_timestamp = _parse_envelope_timestamp(envelope.timestamp)
    current_time = now or datetime.now(timezone.utc)
    skew = abs(current_time - parsed_timestamp)
    if skew > max_skew:
        raise MessageCryptoError(
            "Encrypted envelope timestamp is outside the allowed clock-skew window."
        )
    return parsed_timestamp


def _derive_message_key(
    private_key: X25519PrivateKey,
    *,
    peer_public_key: str,
    sender_username: str,
    recipient_username: str,
    sender_ephemeral_public_key: str,
    recipient_key_agreement_public_key: str,
) -> bytes:
    peer_x25519_public_key = X25519PublicKey.from_public_bytes(decode_key_bytes(peer_public_key))
    if sender_ephemeral_public_key == recipient_key_agreement_public_key:
        raise MessageCryptoError("Ephemeral and recipient X25519 keys must be different.")

    shared_secret = private_key.exchange(peer_x25519_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=_build_hkdf_info(
            sender_username,
            recipient_username,
            sender_ephemeral_public_key,
            recipient_key_agreement_public_key,
        ),
    )
    return hkdf.derive(shared_secret)


def _build_hkdf_info(
    sender_username: str,
    recipient_username: str,
    sender_ephemeral_public_key: str,
    recipient_key_agreement_public_key: str,
) -> bytes:
    return b"\x00".join(
        (
            HKDF_INFO_CONTEXT,
            sender_username.encode("utf-8"),
            recipient_username.encode("utf-8"),
            decode_key_bytes(sender_ephemeral_public_key),
            decode_key_bytes(recipient_key_agreement_public_key),
        )
    )


def _build_aad(
    envelope: EncryptedEnvelope,
) -> bytes:
    return AEAD_AAD_CONTEXT + _canonical_json_bytes(
        {
            "message_id": envelope.message_id,
            "protocol_version": envelope.protocol_version,
            "timestamp": envelope.timestamp,
            "from": envelope.sender_username,
            "to": envelope.recipient_username,
            "sender_ephemeral_public_key": envelope.sender_ephemeral_public_key,
        }
    )


def _build_signature_payload(envelope: EncryptedEnvelope) -> bytes:
    return SIGNATURE_CONTEXT + _canonical_json_bytes(envelope.unsigned_message())


def _canonical_json_bytes(payload: dict[str, str]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _format_envelope_timestamp(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).strftime(ENVELOPE_TIMESTAMP_FORMAT)


def _parse_envelope_timestamp(timestamp: str) -> datetime:
    try:
        return datetime.strptime(timestamp, ENVELOPE_TIMESTAMP_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise MessageCryptoError(
            "Encrypted envelope timestamp must be UTC RFC 3339 text with whole seconds."
        ) from exc


def _encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_base64(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise MessageCryptoError("Encrypted message fields must be valid base64.") from exc
