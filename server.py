"""Async plaintext messaging server for the baseline messenger."""

from __future__ import annotations

import argparse
import asyncio

from protocol import DEFAULT_HOST, DEFAULT_PORT, ProtocolError, read_message, send_message
from storage import SessionStore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plaintext terminal messenger server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    return parser.parse_args()


def log(message: str) -> None:
    print(f"[server] {message}")


def format_address(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{peer[0]}:{peer[1]}"
    return str(peer or "unknown")


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
    log(f"connect {address}")

    try:
        first_message = await read_message(reader, allowed_types={"register"})
        if first_message is None:
            log(f"disconnect {address} before registration")
            return

        username = first_message["username"].strip()
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

        if not store.register(username, writer, address):
            await safe_send(
                writer,
                {
                    "type": "register_error",
                    "text": f"Username '{username}' is already connected.",
                },
            )
            log(f"rejected registration from {address}: duplicate username '{username}'")
            return

        await send_message(writer, {"type": "register_ok", "username": username})
        await send_message(
            writer,
            {
                "type": "system_message",
                "text": f"Welcome, {username}. Type /help to see commands.",
            },
        )
        log(f"registered {username} from {address}")

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


async def run_server(host: str, port: int) -> None:
    store = SessionStore()
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, store),
        host,
        port,
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
        asyncio.run(run_server(args.host, args.port))
    except KeyboardInterrupt:
        log("stopped by keyboard interrupt")


if __name__ == "__main__":
    main()
