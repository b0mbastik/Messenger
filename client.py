"""Async terminal client for the TLS-protected messenger."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import ssl
import sys

from identity import (
    ClientIdentity,
    IdentityError,
    default_identity_dir_for_username,
    load_or_create_identity,
)
from protocol import DEFAULT_HOST, DEFAULT_PORT, ProtocolError, read_message, send_message
from tls_utils import build_client_ssl_context, parse_tls_version


HELP_TEXT = """Available commands:
/help                  show this help text
/users                 list currently connected users
/msg <user> <text>     send a direct message
/name <new_name>       change your username
/quit                  disconnect and exit"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS-protected terminal messenger client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument(
        "--ca-cert",
        default="certs/ca-cert.pem",
        help="Path to the CA certificate PEM file used to verify the server",
    )
    parser.add_argument(
        "--server-name",
        default=None,
        help="TLS server name for certificate verification. Defaults to the host value.",
    )
    parser.add_argument(
        "--tls-min-version",
        choices=("1.2", "1.3"),
        default="1.3",
        help="Minimum TLS version to require. Defaults to 1.3.",
    )
    parser.add_argument(
        "--identity-dir",
        default=None,
        help="Directory used to store this client's long-term identity keys",
    )
    return parser.parse_args()


def print_line(prefix: str, text: str, *, reprompt: bool = False) -> None:
    sys.stdout.write(f"\r{prefix}{text}\n")
    if reprompt:
        sys.stdout.write("> ")
    sys.stdout.flush()


def is_valid_username(username: str) -> bool:
    return bool(username.strip()) and " " not in username and len(username) <= 32


async def open_stdin_reader() -> asyncio.StreamReader:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


async def prompt_line(
    reader: asyncio.StreamReader, prompt: str, stop_event: asyncio.Event | None = None
) -> str | None:
    sys.stdout.write(prompt)
    sys.stdout.flush()

    line_task = asyncio.create_task(reader.readline())
    wait_tasks: set[asyncio.Task[object]] = {line_task}

    stop_task: asyncio.Task[bool] | None = None
    if stop_event is not None:
        stop_task = asyncio.create_task(stop_event.wait())
        wait_tasks.add(stop_task)

    done, pending = await asyncio.wait(wait_tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()

    if stop_task is not None and stop_task in done:
        line_task.cancel()
        return None

    data = await line_task
    if data == b"":
        return None
    return data.decode("utf-8").rstrip("\n")


class MessengerClient:
    def __init__(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_name: str,
        identity_dir: str | None,
    ) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.server_name = server_name
        self.identity_dir = identity_dir
        self.identity: ClientIdentity | None = None
        self.username: str | None = None
        self.stop_event = asyncio.Event()
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def run(self) -> None:
        print("TLS Messenger")
        print(f"Connecting securely to {self.host}:{self.port} ...")
        self.reader, self.writer = await asyncio.open_connection(
            self.host,
            self.port,
            ssl=self.ssl_context,
            server_hostname=self.server_name,
        )
        stdin_reader = await open_stdin_reader()

        print_line("[system]: ", f"connected with {self.tls_details()}")
        await self.register(stdin_reader)
        print(HELP_TEXT)

        receiver_task = asyncio.create_task(self.receive_loop())
        try:
            await self.command_loop(stdin_reader)
        finally:
            self.stop_event.set()
            receiver_task.cancel()
            await asyncio.gather(receiver_task, return_exceptions=True)
            await self.close()

    def tls_details(self) -> str:
        assert self.writer is not None
        ssl_object = self.writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return "no TLS"

        protocol = ssl_object.version() or "unknown TLS version"
        cipher = ssl_object.cipher()
        cipher_name = cipher[0] if cipher else "unknown cipher"
        return f"{protocol} ({cipher_name})"

    async def register(self, stdin_reader: asyncio.StreamReader) -> None:
        assert self.reader is not None
        assert self.writer is not None

        while True:
            username = await prompt_line(stdin_reader, "Username: ", self.stop_event)
            if username is None:
                raise SystemExit(0)

            username = username.strip()
            if not is_valid_username(username):
                print_line(
                    "[error]: ",
                    "Username must be 1-32 characters and contain no spaces.",
                )
                continue

            identity = load_or_create_identity(self.resolve_identity_dir(username))
            self.identity = identity
            print_line(
                "[system]: ",
                "identity loaded "
                f"from {identity.path.parent} "
                f"(sign={identity.signing_fingerprint[:16]}, "
                f"x25519={identity.key_agreement_fingerprint[:16]})",
            )
            register_message = {"type": "register", "username": username}
            register_message.update(identity.public_identity.as_message_fields())
            await send_message(self.writer, register_message)
            response = await read_message(
                self.reader, allowed_types={"register_ok", "register_error", "system_message"}
            )
            if response is None:
                raise ConnectionError("server closed the connection during registration")

            if response["type"] == "register_ok":
                self.username = response["username"]
                print_line("[system]: ", f"registered as {self.username}")

                welcome = await read_message(self.reader, allowed_types={"system_message"})
                if welcome is not None:
                    print_line("[system]: ", welcome["text"])
                return

            print_line("[error]: ", response["text"])

    def resolve_identity_dir(self, username: str) -> Path:
        if self.identity_dir:
            return Path(self.identity_dir)
        return default_identity_dir_for_username(username)

    async def command_loop(self, stdin_reader: asyncio.StreamReader) -> None:
        assert self.writer is not None

        while not self.stop_event.is_set():
            line = await prompt_line(stdin_reader, "> ", self.stop_event)
            if line is None:
                await self.send_disconnect()
                return

            command = line.strip()
            if not command:
                continue

            if command == "/help":
                print(HELP_TEXT)
                continue

            if command == "/users":
                await send_message(self.writer, {"type": "list_users"})
                continue

            if command.startswith("/msg "):
                parts = command.split(" ", 2)
                if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
                    print_line("[error]: ", "Usage: /msg <user> <text>")
                    continue

                target = parts[1].strip()
                text = parts[2].strip()
                await send_message(
                    self.writer,
                    {"type": "direct_message", "to": target, "text": text},
                )
                print_line(f"[to {target}]: ", text)
                continue

            if command.startswith("/name "):
                new_name = command[6:].strip()
                if not is_valid_username(new_name):
                    print_line(
                        "[error]: ",
                        "Username must be 1-32 characters and contain no spaces.",
                    )
                    continue

                await send_message(
                    self.writer,
                    {"type": "rename", "new_username": new_name},
                )
                continue

            if command == "/quit":
                await self.send_disconnect()
                return

            print_line("[error]: ", "Unknown command. Type /help for usage.")

    async def receive_loop(self) -> None:
        assert self.reader is not None

        try:
            while not self.stop_event.is_set():
                message = await read_message(self.reader)
                if message is None:
                    print_line("[system]: ", "server disconnected")
                    self.stop_event.set()
                    return

                self.handle_server_message(message)
        except ProtocolError as exc:
            print_line("[error]: ", f"protocol error: {exc}")
            self.stop_event.set()
        except (ConnectionError, OSError) as exc:
            print_line("[error]: ", f"connection error: {exc}")
            self.stop_event.set()

    def handle_server_message(self, message: dict[str, object]) -> None:
        message_type = message["type"]

        if message_type == "incoming_message":
            print_line(
                f"[from {message['from']}]: ",
                str(message["text"]),
                reprompt=not self.stop_event.is_set(),
            )
            return

        if message_type == "users_list":
            users = ", ".join(message["users"]) if message["users"] else "(none)"
            print_line("[system]: ", f"connected users: {users}", reprompt=True)
            return

        if message_type == "delivery_error":
            print_line("[error]: ", str(message["text"]), reprompt=True)
            return

        if message_type == "system_message":
            print_line("[system]: ", str(message["text"]), reprompt=True)
            return

        if message_type == "rename_ok":
            self.username = str(message["username"])
            print_line("[system]: ", f"username changed to {self.username}", reprompt=True)
            return

        if message_type == "rename_error":
            print_line("[error]: ", str(message["text"]), reprompt=True)
            return

        print_line("[system]: ", f"received unexpected message: {message}", reprompt=True)

    async def send_disconnect(self) -> None:
        if self.stop_event.is_set():
            return

        self.stop_event.set()
        if self.writer is None or self.writer.is_closing():
            return

        try:
            await send_message(self.writer, {"type": "disconnect"})
        except (ConnectionError, OSError):
            pass

    async def close(self) -> None:
        if self.writer is None or self.writer.is_closing():
            return

        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def main_async() -> None:
    args = parse_args()
    ssl_context = build_client_ssl_context(
        args.ca_cert,
        minimum_version=parse_tls_version(args.tls_min_version),
    )
    client = MessengerClient(
        args.host,
        args.port,
        ssl_context,
        args.server_name or args.host,
        args.identity_dir,
    )
    await client.run()


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print_line("[system]: ", "client stopped")
    except ConnectionRefusedError:
        print_line("[error]: ", "could not connect to the server")
    except ssl.SSLError as exc:
        print_line("[error]: ", f"TLS error: {exc}")
    except IdentityError as exc:
        print_line("[error]: ", f"identity error: {exc}")
    except OSError as exc:
        print_line("[error]: ", str(exc))


if __name__ == "__main__":
    main()
