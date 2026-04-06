"""X.509 helpers for CA-backed messenger client identities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from shared.identity import decode_key_bytes


class CertificateError(Exception):
    """Raised when a user certificate is missing or cannot be trusted."""


def load_ca_certificate(ca_certfile: str | Path) -> x509.Certificate:
    """Load a CA certificate from PEM."""

    path = Path(ca_certfile)
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except OSError as exc:
        raise CertificateError(f"Unable to read CA certificate '{path}': {exc}") from exc
    except ValueError as exc:
        raise CertificateError(f"CA certificate '{path}' is not valid PEM.") from exc


def load_ca_private_key(ca_keyfile: str | Path) -> Any:
    """Load a CA private key from PEM."""

    path = Path(ca_keyfile)
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    except OSError as exc:
        raise CertificateError(f"Unable to read CA private key '{path}': {exc}") from exc
    except ValueError as exc:
        raise CertificateError(f"CA private key '{path}' is not valid PEM.") from exc


def issue_client_certificate(
    username: str,
    signing_public_key: str,
    ca_certfile: str | Path,
    ca_keyfile: str | Path,
    output_path: str | Path,
    *,
    valid_days: int = 365,
) -> Path:
    """Issue a client identity certificate for the user's Ed25519 key."""

    ca_certificate = load_ca_certificate(ca_certfile)
    ca_private_key = load_ca_private_key(ca_keyfile)
    certificate_pem = build_client_certificate_pem(
        username,
        signing_public_key,
        ca_certificate,
        ca_private_key,
        valid_days=valid_days,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(certificate_pem, encoding="utf-8")
    return output


def build_client_certificate_pem(
    username: str,
    signing_public_key: str,
    ca_certificate: x509.Certificate,
    ca_private_key: object,
    *,
    valid_days: int = 365,
) -> str:
    """Build and sign a client identity certificate as PEM text."""

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(decode_key_bytes(signing_public_key))
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_certificate.public_key()),
            critical=False,
        )
    )

    algorithm = (
        None
        if isinstance(ca_private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
        else hashes.SHA256()
    )
    certificate = builder.sign(private_key=ca_private_key, algorithm=algorithm)
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def validate_client_certificate(
    certificate_pem: str,
    expected_username: str,
    expected_signing_public_key: str,
    ca_certificate: x509.Certificate,
) -> x509.Certificate:
    """Validate a client certificate against the CA and claimed identity."""

    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    except ValueError as exc:
        raise CertificateError("Client certificate is not valid PEM.") from exc

    now = datetime.now(timezone.utc)
    if certificate.not_valid_before_utc > now:
        raise CertificateError("Client certificate is not valid yet.")
    if certificate.not_valid_after_utc < now:
        raise CertificateError("Client certificate has expired.")

    if certificate.issuer != ca_certificate.subject:
        raise CertificateError("Client certificate was not issued by the configured CA.")

    _verify_certificate_signature(certificate, ca_certificate)

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise CertificateError("Client certificate must contain exactly one common name.")
    if common_names[0].value != expected_username:
        raise CertificateError("Client certificate common name does not match the username.")

    public_key = certificate.public_key()
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise CertificateError("Client certificate must carry an Ed25519 public key.")

    expected_public_key = decode_key_bytes(expected_signing_public_key)
    actual_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if actual_public_key != expected_public_key:
        raise CertificateError("Client certificate does not match the supplied signing key.")

    try:
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CertificateError("Client certificate is missing basic constraints.") from exc
    if basic_constraints.ca:
        raise CertificateError("Client certificate must not be a CA certificate.")

    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateError("Client certificate is missing key usage.") from exc
    if not key_usage.digital_signature:
        raise CertificateError("Client certificate is not permitted for digital signatures.")

    try:
        extended_key_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise CertificateError("Client certificate is missing extended key usage.") from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in extended_key_usage:
        raise CertificateError("Client certificate is not permitted for client authentication.")

    return certificate


def _verify_certificate_signature(
    certificate: x509.Certificate, ca_certificate: x509.Certificate
) -> None:
    """Verify a directly-issued client certificate signature."""

    ca_public_key = ca_certificate.public_key()
    try:
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
            return

        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
            return

        if isinstance(ca_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
            return
    except Exception as exc:
        raise CertificateError("Client certificate signature verification failed.") from exc

    raise CertificateError("Configured CA public key type is not supported.")
