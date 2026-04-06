"""Application-layer end-to-end encryption helpers for messenger messages."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

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

HKDF_INFO_CONTEXT = b"messenger-e2ee:key:v1"
AEAD_AAD_CONTEXT = b"messenger-e2ee:aad:v1"
SIGNATURE_CONTEXT = b"messenger-e2ee:signature:v1"
NONCE_SIZE = 12
AES_KEY_SIZE = 32


class MessageCryptoError(Exception):
    """Raised when end-to-end encryption state is invalid."""


@dataclass(slots=True)
class RecipientBundle:
    """A connected recipient's certified encryption bundle."""

    username: str
    signing_public_key: str
    key_agreement_public_key: str
    key_agreement_signature: str
    identity_certificate: str


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
    nonce = os.urandom(NONCE_SIZE)
    aad = _build_aad(
        sender_username,
        recipient_bundle.username,
        sender_ephemeral_public_key,
    )
    ciphertext = AESGCM(derived_key).encrypt(nonce, plaintext_bytes, aad)
    signature = sender_identity.signing_private_key.sign(
        _build_signature_payload(
            sender_username,
            recipient_bundle.username,
            sender_ephemeral_public_key,
            nonce,
            ciphertext,
        )
    )
    return {
        "sender_ephemeral_public_key": sender_ephemeral_public_key,
        "nonce": _encode_base64(nonce),
        "ciphertext": _encode_base64(ciphertext),
        "signature": _encode_base64(signature),
    }


def decrypt_message_from_sender(
    recipient_identity: ClientIdentity,
    recipient_username: str,
    sender_username: str,
    sender_signing_public_key: str,
    sender_identity_certificate: str,
    sender_ephemeral_public_key: str,
    nonce: str,
    ciphertext: str,
    signature: str,
    ca_certificate: x509.Certificate,
) -> str:
    """Verify and decrypt an incoming direct message."""

    try:
        validate_client_certificate(
            sender_identity_certificate,
            sender_username,
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
            decode_key_bytes(signature),
            _build_signature_payload(
                sender_username,
                recipient_username,
                sender_ephemeral_public_key,
                _decode_base64(nonce),
                _decode_base64(ciphertext),
            ),
        )
    except Exception as exc:
        raise MessageCryptoError(f"Message signature verification failed: {exc}") from exc

    try:
        derived_key = _derive_message_key(
            recipient_identity.key_agreement_private_key,
            peer_public_key=sender_ephemeral_public_key,
            sender_username=sender_username,
            recipient_username=recipient_username,
            sender_ephemeral_public_key=sender_ephemeral_public_key,
            recipient_key_agreement_public_key=recipient_identity.public_identity.key_agreement_public_key,
        )
        plaintext = AESGCM(derived_key).decrypt(
            _decode_base64(nonce),
            _decode_base64(ciphertext),
            _build_aad(sender_username, recipient_username, sender_ephemeral_public_key),
        )
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise MessageCryptoError(f"Message decryption failed: {exc}") from exc


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
    sender_username: str,
    recipient_username: str,
    sender_ephemeral_public_key: str,
) -> bytes:
    return b"\x00".join(
        (
            AEAD_AAD_CONTEXT,
            sender_username.encode("utf-8"),
            recipient_username.encode("utf-8"),
            decode_key_bytes(sender_ephemeral_public_key),
        )
    )


def _build_signature_payload(
    sender_username: str,
    recipient_username: str,
    sender_ephemeral_public_key: str,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(ciphertext)
    return b"\x00".join(
        (
            SIGNATURE_CONTEXT,
            sender_username.encode("utf-8"),
            recipient_username.encode("utf-8"),
            decode_key_bytes(sender_ephemeral_public_key),
            nonce,
            digest.finalize(),
        )
    )


def _encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_base64(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise MessageCryptoError("Encrypted message fields must be valid base64.") from exc
