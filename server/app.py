"""Async TLS-protected messaging server for the terminal messenger."""

from __future__ import annotations

import argparse
import asyncio
import ssl

from ca.cert_utils import (
    CertificateError,
    build_client_certificate_pem,
    load_ca_certificate,
    load_ca_private_key,
    validate_client_certificate,
)
from ca.tls_utils import build_server_ssl_context, parse_tls_version
from cryptography import x509
from server.accounts import AccountRegistry, AccountRegistryError
from server.storage import SessionStore
from shared.e2ee import (
    MessageCryptoError,
    parse_encrypted_envelope,
    validate_envelope_timestamp_freshness,
)
from shared.identity import (
    IdentityError,
    validate_public_identity,
    verify_key_agreement_binding,
)
from shared.paths import (
    DEFAULT_ACCOUNTS_FILE,
    DEFAULT_CA_CERT_PATH,
    DEFAULT_CA_KEY_PATH,
    DEFAULT_SERVER_CERT_PATH,
    DEFAULT_SERVER_KEY_PATH,
    resolve_project_path,
)
from shared.protocol import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    ProtocolError,
    is_valid_username,
    read_message,
    send_message,
)

USERNAME_REQUIREMENTS = (
    "Username must be 1-32 characters, start with a letter or digit, "
    "and use only letters, digits, '.', '_' or '-'."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS-protected terminal messenger server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument(
        "--certfile",
        default=str(DEFAULT_SERVER_CERT_PATH),
        help="Path to the TLS server certificate PEM file",
    )
    parser.add_argument(
        "--keyfile",
        default=str(DEFAULT_SERVER_KEY_PATH),
        help="Path to the TLS server private key PEM file",
    )
    parser.add_argument(
        "--tls-min-version",
        choices=("1.2", "1.3"),
        default="1.3",
        help="Minimum TLS version to allow. Defaults to 1.3.",
    )
    parser.add_argument(
        "--ca-cert",
        default=str(DEFAULT_CA_CERT_PATH),
        help="Path to the CA certificate PEM file used to verify client identity certificates",
    )
    parser.add_argument(
        "--ca-key",
        default=str(DEFAULT_CA_KEY_PATH),
        help="Path to the CA private key PEM file used to issue client identity certificates",
    )
    parser.add_argument(
        "--accounts-file",
        default=str(DEFAULT_ACCOUNTS_FILE),
        help="Path to the persistent account registry JSON file",
    )
    return parser.parse_args()


def log(message: str) -> None:
    print(f"[server] {message}")


def format_address(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer or "unknown")


def format_tls_details(writer: asyncio.StreamWriter) -> str:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return "without TLS"

    protocol = ssl_object.version() or "unknown TLS version"
    cipher = ssl_object.cipher()
    cipher_name = cipher[0] if cipher else "unknown cipher"
    return f"using {protocol} ({cipher_name})"


async def safe_send(writer: asyncio.StreamWriter, message: dict[str, object]) -> bool:
    try:
        await send_message(writer, message)
        return True
    except (ConnectionError, OSError, asyncio.CancelledError):
        return False


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    store: SessionStore,
    accounts: AccountRegistry,
    ca_certificate: x509.Certificate,
    ca_private_key: object,
) -> None:
    address = format_address(writer)
    log(f"connect {address} {format_tls_details(writer)}")

    try:
        first_message = await read_message(
            reader, allowed_types={"register", "login", "recover_certificate"}
        )
        if first_message is None:
            log(f"disconnect {address} before registration")
            return

        auth_mode = first_message["type"]
        username = first_message["username"].strip()
        password = str(first_message["password"])
        try:
            public_identity = validate_public_identity(
                first_message["signing_public_key"],
                first_message["key_agreement_public_key"],
            )
        except IdentityError as exc:
            await safe_send(
                writer,
                {
                    "type": "register_error",
                    "text": f"Client identity error: {exc}",
                },
            )
            log(f"rejected registration from {address}: invalid identity ({exc})")
            return

        if not is_valid_username(username):
            await safe_send(
                writer,
                {
                    "type": "register_error",
                    "text": USERNAME_REQUIREMENTS,
                },
            )
            log(f"rejected registration from {address}: invalid username '{username}'")
            return

        try:
            verify_key_agreement_binding(
                public_identity.signing_public_key,
                username,
                public_identity.key_agreement_public_key,
                first_message["key_agreement_signature"],
            )
        except IdentityError as exc:
            await safe_send(
                writer,
                {
                    "type": "register_error",
                    "text": f"Client identity error: {exc}",
                },
            )
            log(f"rejected registration from {address}: invalid key binding ({exc})")
            return

        account = accounts.get(username)
        created_account = False
        migrated_password = False

        if auth_mode == "register":
            if account is not None:
                await safe_send(
                    writer,
                    {
                        "type": "register_error",
                        "text": f"Username '{username}' is already registered. Log in instead.",
                    },
                )
                log(f"rejected registration from {address}: username already registered ('{username}')")
                return

            existing_identity = accounts.find_by_signing_key(public_identity.signing_public_key)
            if existing_identity is not None and existing_identity.username != username:
                await safe_send(
                    writer,
                    {
                        "type": "register_error",
                        "text": "This signing identity is already permanently bound to "
                        f"username '{existing_identity.username}'.",
                    },
                )
                log(
                    "rejected registration from "
                    f"{address}: signing identity already bound ('{existing_identity.username}')"
                )
                return

            if account is None:
                identity_certificate = build_client_certificate_pem(
                    username,
                    public_identity.signing_public_key,
                    ca_certificate,
                    ca_private_key,
                )
                try:
                    account = accounts.create_account(
                        username,
                        public_identity,
                        identity_certificate,
                        password,
                    )
                except AccountRegistryError as exc:
                    await safe_send(
                        writer,
                        {
                            "type": "register_error",
                            "text": f"Account registry error: {exc}",
                        },
                    )
                    log(f"rejected registration from {address}: account registry error ({exc})")
                    return
                created_account = True
        else:
            if account is None:
                await safe_send(
                    writer,
                    {
                        "type": "register_error",
                        "text": f"Username '{username}' is not registered.",
                    },
                )
                log(f"rejected login from {address}: username not registered ('{username}')")
                return

            try:
                password_valid, migrated_password = accounts.verify_or_set_password(username, password)
            except AccountRegistryError as exc:
                await safe_send(
                    writer,
                    {
                        "type": "register_error",
                        "text": f"Account registry error: {exc}",
                    },
                )
                log(f"rejected login from {address}: password registry error ({exc})")
                return

            if not password_valid:
                await safe_send(
                    writer,
                    {
                        "type": "register_error",
                        "text": "Invalid password.",
                    },
                )
                log(f"rejected login from {address}: invalid password ('{username}')")
                return

            if auth_mode == "login":
                try:
                    validate_client_certificate(
                        first_message["identity_certificate"],
                        username,
                        public_identity.signing_public_key,
                        ca_certificate,
                    )
                except CertificateError as exc:
                    await safe_send(
                        writer,
                        {
                            "type": "register_error",
                            "text": f"Client certificate error: {exc}",
                        },
                    )
                    log(f"rejected login from {address}: certificate error ({exc})")
                    return

                if not accounts.matches_identity(
                    username,
                    public_identity.signing_public_key,
                    first_message["identity_certificate"],
                ):
                    await safe_send(
                        writer,
                        {
                            "type": "register_error",
                            "text": "Stored identity for this username does not match the presented certificate.",
                        },
                    )
                    log(f"rejected login from {address}: stored identity mismatch ('{username}')")
                    return
            else:
                if account.signing_public_key != public_identity.signing_public_key:
                    await safe_send(
                        writer,
                        {
                            "type": "register_error",
                            "text": "Stored identity for this username does not match the local identity.",
                        },
                    )
                    log(f"rejected certificate recovery from {address}: stored identity mismatch ('{username}')")
                    return

        assert account is not None
        if account.key_agreement_public_key != public_identity.key_agreement_public_key:
            account = accounts.update_key_agreement_key(
                username,
                public_identity.key_agreement_public_key,
            )
        registered, error = store.register(
            username,
            writer,
            address,
            public_identity,
            first_message["key_agreement_signature"],
            account.identity_certificate,
        )
        if not registered:
            if error == "signing identity is already connected":
                text = "This long-term signing identity is already connected as another user."
            else:
                text = f"Username '{username}' is already connected."
            await safe_send(
                writer,
                {
                    "type": "register_error",
                    "text": text,
                },
            )
            log(f"rejected registration from {address}: {error} ('{username}')")
            return
        await send_message(
            writer,
            {
                "type": "register_ok",
                "username": username,
                "identity_certificate": account.identity_certificate,
            },
        )
        await send_message(
            writer,
            {
                "type": "system_message",
                "text": f"Welcome, {username}. Type /help to see commands.",
            },
        )
        if created_account:
            status = "registered"
        elif auth_mode == "recover_certificate":
            status = "recovered certificate and authenticated"
        else:
            status = "authenticated"
        if migrated_password:
            status += " with password migration"
        log(
            f"{status} {username} from {address} "
            f"(sign={public_identity.signing_fingerprint[:16]}, "
            f"x25519={public_identity.key_agreement_fingerprint[:16]})"
        )

        while True:
            message = await read_message(reader)
            if message is None:
                break

            session = store.get_by_writer(writer)
            if session is None:
                break

            message_type = message["type"]
            if message_type == "list_users":
                await send_message(
                    writer,
                    {"type": "users_list", "users": store.list_usernames()},
                )
                continue

            if message_type == "lookup_user":
                recipient_name = message["username"]
                recipient = store.get_by_username(recipient_name)
                if recipient is None:
                    await send_message(
                        writer,
                        {
                            "type": "user_bundle_error",
                            "username": recipient_name,
                            "text": f"User '{recipient_name}' is not connected.",
                        },
                    )
                    continue

                await send_message(
                    writer,
                    {
                        "type": "user_bundle",
                        "username": recipient.username,
                        "signing_public_key": recipient.public_identity.signing_public_key,
                        "key_agreement_public_key": recipient.public_identity.key_agreement_public_key,
                        "key_agreement_signature": recipient.key_agreement_signature,
                        "identity_certificate": recipient.identity_certificate,
                    },
                )
                continue

            if message_type == "direct_message":
                recipient_name = message["to"]
                try:
                    envelope = parse_encrypted_envelope(message["envelope"])
                except MessageCryptoError as exc:
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": f"Invalid encrypted envelope: {exc}",
                        },
                    )
                    log(
                        "delivery error "
                        f"{session.username} -> {recipient_name}: invalid envelope ({exc})"
                    )
                    continue

                if envelope.sender_username != session.username:
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": "Encrypted envelope sender does not match the authenticated session.",
                        },
                    )
                    log(
                        "delivery error "
                        f"{session.username} -> {recipient_name}: sender mismatch in envelope"
                    )
                    continue

                if envelope.recipient_username != recipient_name:
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": "Encrypted envelope recipient does not match the routing target.",
                        },
                    )
                    log(
                        "delivery error "
                        f"{session.username} -> {recipient_name}: recipient mismatch in envelope"
                    )
                    continue

                try:
                    validate_envelope_timestamp_freshness(envelope)
                except MessageCryptoError as exc:
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": f"Invalid encrypted envelope: {exc}",
                        },
                    )
                    log(
                        "delivery error "
                        f"{session.username} -> {recipient_name}: stale envelope timestamp ({exc})"
                    )
                    continue

                recipient = store.get_by_username(recipient_name)

                if recipient is None:
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": f"User '{recipient_name}' is not connected.",
                        },
                    )
                    log(f"delivery error {session.username} -> {recipient_name}: user missing")
                    continue

                try:
                    store.check_and_remember_envelope(envelope)
                except MessageCryptoError as exc:
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": f"Invalid encrypted envelope: {exc}",
                        },
                    )
                    log(
                        "delivery error "
                        f"{session.username} -> {recipient_name}: rejected envelope ({exc})"
                    )
                    continue

                delivered = await safe_send(
                    recipient.writer,
                    {
                        "type": "incoming_message",
                        "signing_public_key": session.public_identity.signing_public_key,
                        "identity_certificate": session.identity_certificate,
                        "envelope": envelope.as_message(),
                    },
                )
                if not delivered:
                    stale_session = store.unregister(recipient.writer)
                    if stale_session is not None:
                        recipient.writer.close()
                        await recipient.writer.wait_closed()
                        log(
                            f"disconnect {stale_session.username} ({stale_session.address}) after send failure"
                        )
                    await send_message(
                        writer,
                        {
                            "type": "delivery_error",
                            "text": f"User '{recipient_name}' disconnected before delivery.",
                        },
                    )
                    continue

                log(
                    "message "
                    f"{session.username} -> {recipient_name}: "
                    f"id={envelope.message_id} "
                    f"{len(envelope.ciphertext)} base64 bytes"
                )
                continue

            if message_type == "rename":
                await send_message(
                    writer,
                    {
                        "type": "rename_error",
                        "text": "Usernames are bound to CA-signed certificates and cannot be changed.",
                    },
                )
                continue

            if message_type == "disconnect":
                log(f"disconnect requested by {session.username}")
                break

            await send_message(
                writer,
                {
                    "type": "system_message",
                    "text": f"Unsupported message type '{message_type}'.",
                },
            )

    except ProtocolError as exc:
        log(f"protocol error from {address}: {exc}")
        await safe_send(writer, {"type": "system_message", "text": f"Protocol error: {exc}"})
    except (ConnectionError, OSError) as exc:
        log(f"connection error from {address}: {exc}")
    except Exception as exc:
        log(f"unexpected error from {address}: {exc}")
    finally:
        session = store.unregister(writer)
        if session is not None:
            log(f"disconnect {session.username} ({session.address})")
        else:
            log(f"disconnect {address}")

        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def shutdown_clients(store: SessionStore) -> None:
    for session in store.active_sessions():
        if not session.writer.is_closing():
            await safe_send(
                session.writer,
                {"type": "system_message", "text": "Server is shutting down."},
            )
            session.writer.close()

    for session in store.active_sessions():
        try:
            await session.writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def run_server(
    host: str,
    port: int,
    ssl_context: ssl.SSLContext,
    accounts: AccountRegistry,
    ca_certificate: x509.Certificate,
    ca_private_key: object,
) -> None:
    store = SessionStore()
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(
            reader,
            writer,
            store,
            accounts,
            ca_certificate,
            ca_private_key,
        ),
        host,
        port,
        ssl=ssl_context,
    )

    sockets = server.sockets or []
    if sockets:
        addresses = ", ".join(str(sock.getsockname()) for sock in sockets)
        log(f"listening on {addresses}")

    try:
        async with server:
            await server.serve_forever()
    finally:
        log("shutting down")
        server.close()
        await server.wait_closed()
        await shutdown_clients(store)


def main() -> None:
    args = parse_args()
    try:
        ssl_context = build_server_ssl_context(
            str(resolve_project_path(args.certfile)),
            str(resolve_project_path(args.keyfile)),
            minimum_version=parse_tls_version(args.tls_min_version),
        )
        ca_certificate = load_ca_certificate(resolve_project_path(args.ca_cert))
        ca_private_key = load_ca_private_key(resolve_project_path(args.ca_key))
        accounts = AccountRegistry(resolve_project_path(args.accounts_file))
        asyncio.run(
            run_server(
                args.host,
                args.port,
                ssl_context,
                accounts,
                ca_certificate,
                ca_private_key,
            )
        )
    except KeyboardInterrupt:
        log("stopped by keyboard interrupt")
    except (AccountRegistryError, CertificateError, OSError, ssl.SSLError) as exc:
        log(f"TLS setup error: {exc}")


if __name__ == "__main__":
    main()
