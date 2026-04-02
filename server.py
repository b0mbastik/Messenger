"""Async TLS-protected messaging server for the terminal messenger."""

from __future__ import annotations

import argparse
import asyncio
import ssl

from identity import IdentityError, validate_public_identity
from protocol import DEFAULT_HOST, DEFAULT_PORT, ProtocolError, read_message, send_message
from storage import SessionStore
from tls_utils import build_server_ssl_context, parse_tls_version


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS-protected terminal messenger server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument(
        "--certfile",
        default="certs/server-cert.pem",
        help="Path to the TLS server certificate PEM file",
    )
    parser.add_argument(
        "--keyfile",
        default="certs/server-key.pem",
        help="Path to the TLS server private key PEM file",
    )
    parser.add_argument(
        "--tls-min-version",
        choices=("1.2", "1.3"),
        default="1.3",
        help="Minimum TLS version to allow. Defaults to 1.3.",
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


def is_valid_username(username: str) -> bool:
    return bool(username.strip()) and " " not in username and len(username) <= 32


async def safe_send(writer: asyncio.StreamWriter, message: dict[str, object]) -> bool:
    try:
        await send_message(writer, message)
        return True
    except (ConnectionError, OSError, asyncio.CancelledError):
        return False


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, store: SessionStore
) -> None:
    address = format_address(writer)
    log(f"connect {address} {format_tls_details(writer)}")

    try:
        first_message = await read_message(reader, allowed_types={"register"})
        if first_message is None:
            log(f"disconnect {address} before registration")
            return

        username = first_message["username"].strip()
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
                    "text": "Username must be 1-32 characters and contain no spaces.",
                },
            )
            log(f"rejected registration from {address}: invalid username '{username}'")
            return

        registered, error = store.register(username, writer, address, public_identity)
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

        await send_message(writer, {"type": "register_ok", "username": username})
        await send_message(
            writer,
            {
                "type": "system_message",
                "text": f"Welcome, {username}. Type /help to see commands.",
            },
        )
        log(
            "registered "
            f"{username} from {address} "
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

            if message_type == "direct_message":
                recipient_name = message["to"]
                text = message["text"]
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

                delivered = await safe_send(
                    recipient.writer,
                    {
                        "type": "incoming_message",
                        "from": session.username,
                        "text": text,
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

                log(f"message {session.username} -> {recipient_name}: {text!r}")
                continue

            if message_type == "rename":
                new_username = message["new_username"].strip()
                if not is_valid_username(new_username):
                    await send_message(
                        writer,
                        {
                            "type": "rename_error",
                            "text": "Username must be 1-32 characters and contain no spaces.",
                        },
                    )
                    continue

                old_username = session.username
                if new_username == old_username:
                    await send_message(writer, {"type": "rename_ok", "username": new_username})
                    continue

                renamed, error = store.rename(writer, new_username)
                if not renamed:
                    await send_message(
                        writer,
                        {"type": "rename_error", "text": error or "Rename failed."},
                    )
                    log(f"rename rejected for {old_username}: {error}")
                    continue

                await send_message(writer, {"type": "rename_ok", "username": new_username})
                log(f"rename {old_username} -> {new_username}")
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


async def run_server(host: str, port: int, ssl_context: ssl.SSLContext) -> None:
    store = SessionStore()
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, store),
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
            args.certfile,
            args.keyfile,
            minimum_version=parse_tls_version(args.tls_min_version),
        )
        asyncio.run(run_server(args.host, args.port, ssl_context))
    except KeyboardInterrupt:
        log("stopped by keyboard interrupt")
    except (OSError, ssl.SSLError) as exc:
        log(f"TLS setup error: {exc}")


if __name__ == "__main__":
    main()
