"""Integration and protocol tests for the TLS messenger."""

from __future__ import annotations

import asyncio
import json
import shutil
import ssl
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from identity import (
    DEFAULT_IDENTITIES_DIR,
    IdentityError,
    default_identity_dir_for_username,
    decode_key_bytes,
    load_or_create_identity,
    validate_public_identity,
)
from protocol import ProtocolError, read_message, send_message, validate_message
from server import handle_client, shutdown_clients
from storage import SessionStore
from tls_utils import build_client_ssl_context, build_server_ssl_context, parse_tls_version


class TestPeer:
    """Small async client used to exercise the server in tests."""

    def __init__(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_name: str,
        signing_public_key: str,
        key_agreement_public_key: str,
    ) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.server_name = server_name
        self.signing_public_key = signing_public_key
        self.key_agreement_public_key = key_agreement_public_key
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            self.host,
            self.port,
            ssl=self.ssl_context,
            server_hostname=self.server_name,
        )

    async def register(self, username: str) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        await self.send(
            {
                "type": "register",
                "username": username,
                "signing_public_key": self.signing_public_key,
                "key_agreement_public_key": self.key_agreement_public_key,
            }
        )
        response = await self.recv()
        if response is None or response["type"] != "register_ok":
            return response, None
        welcome = await self.recv()
        return response, welcome

    async def send(self, message: dict[str, object]) -> None:
        assert self.writer is not None
        await send_message(self.writer, message)

    async def send_raw(self, raw_text: str) -> None:
        assert self.writer is not None
        self.writer.write(raw_text.encode("utf-8"))
        await self.writer.drain()

    async def recv(self, timeout: float = 1.0) -> dict[str, object] | None:
        assert self.reader is not None
        return await asyncio.wait_for(read_message(self.reader), timeout=timeout)

    async def close(self) -> None:
        if self.writer is None or self.writer.is_closing():
            return
        self.writer.close()
        await self.writer.wait_closed()


class MessengerServerTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("openssl is required to generate test TLS certificates")

        cls._temp_dir = tempfile.TemporaryDirectory()
        cls._cert_dir = Path(cls._temp_dir.name)
        cls._ca_cert = cls._cert_dir / "ca-cert.pem"
        cls._ca_key = cls._cert_dir / "ca-key.pem"
        cls._server_key = cls._cert_dir / "server-key.pem"
        cls._server_csr = cls._cert_dir / "server.csr"
        cls._server_cert = cls._cert_dir / "server-cert.pem"
        cls._server_ext = cls._cert_dir / "server-ext.cnf"

        cls._server_ext.write_text(
            textwrap.dedent(
                """
                basicConstraints=critical,CA:false
                keyUsage=critical,digitalSignature,keyEncipherment
                subjectAltName=DNS:localhost,IP:127.0.0.1
                extendedKeyUsage=serverAuth
                subjectKeyIdentifier=hash
                authorityKeyIdentifier=keyid,issuer
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-days",
                "1",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(cls._ca_key),
                "-out",
                str(cls._ca_cert),
                "-subj",
                "/CN=Messenger Test CA",
                "-addext",
                "basicConstraints=critical,CA:true",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                openssl,
                "req",
                "-new",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(cls._server_key),
                "-out",
                str(cls._server_csr),
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                openssl,
                "x509",
                "-req",
                "-days",
                "1",
                "-in",
                str(cls._server_csr),
                "-CA",
                str(cls._ca_cert),
                "-CAkey",
                str(cls._ca_key),
                "-CAcreateserial",
                "-out",
                str(cls._server_cert),
                "-extfile",
                str(cls._server_ext),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp_dir.cleanup()

    async def asyncSetUp(self) -> None:
        self.store = SessionStore()
        self.server_ssl_context = build_server_ssl_context(
            str(self._server_cert),
            str(self._server_key),
            minimum_version=ssl.TLSVersion.TLSv1_3,
        )
        self.client_ssl_context = build_client_ssl_context(
            str(self._ca_cert),
            minimum_version=ssl.TLSVersion.TLSv1_3,
        )
        self.server = await asyncio.start_server(
            lambda reader, writer: handle_client(reader, writer, self.store),
            "127.0.0.1",
            0,
            ssl=self.server_ssl_context,
        )
        socket = self.server.sockets[0]
        self.host, self.port = socket.getsockname()[:2]
        self.peers: list[TestPeer] = []

    async def asyncTearDown(self) -> None:
        await shutdown_clients(self.store)
        self.server.close()
        await self.server.wait_closed()
        for peer in self.peers:
            await peer.close()

    async def make_peer(self) -> TestPeer:
        identity = load_or_create_identity(Path(self._cert_dir) / f"peer-{len(self.peers)}")
        public_identity = identity.public_identity
        peer = TestPeer(
            self.host,
            self.port,
            self.client_ssl_context,
            "localhost",
            public_identity.signing_public_key,
            public_identity.key_agreement_public_key,
        )
        await peer.connect()
        self.peers.append(peer)
        return peer

    async def test_register_and_list_users(self) -> None:
        alice = await self.make_peer()
        bob = await self.make_peer()

        register_ok, welcome = await alice.register("alice")
        self.assertEqual(register_ok, {"type": "register_ok", "username": "alice"})
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, alice. Type /help to see commands."},
        )

        register_ok, welcome = await bob.register("bob")
        self.assertEqual(register_ok, {"type": "register_ok", "username": "bob"})
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, bob. Type /help to see commands."},
        )

        await alice.send({"type": "list_users"})
        users_list = await alice.recv()
        self.assertIsNotNone(users_list)
        self.assertEqual(users_list["type"], "users_list")
        self.assertCountEqual(users_list["users"], ["alice", "bob"])

    async def test_duplicate_username_is_rejected(self) -> None:
        alice = await self.make_peer()
        dupe = await self.make_peer()

        response, _ = await alice.register("alice")
        self.assertEqual(response, {"type": "register_ok", "username": "alice"})

        response, welcome = await dupe.register("alice")
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Username 'alice' is already connected.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await dupe.recv())

    async def test_invalid_username_is_rejected(self) -> None:
        peer = await self.make_peer()

        response, welcome = await peer.register("bad name")
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Username must be 1-32 characters and contain no spaces.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await peer.recv())

    async def test_direct_message_is_delivered(self) -> None:
        alice = await self.make_peer()
        bob = await self.make_peer()
        await alice.register("alice")
        await bob.register("bob")

        await alice.send({"type": "direct_message", "to": "bob", "text": "hello"})
        incoming = await bob.recv()
        self.assertEqual(
            incoming,
            {"type": "incoming_message", "from": "alice", "text": "hello"},
        )

    async def test_direct_message_to_missing_user_returns_delivery_error(self) -> None:
        alice = await self.make_peer()
        await alice.register("alice")

        await alice.send({"type": "direct_message", "to": "nobody", "text": "hello"})
        response = await alice.recv()
        self.assertEqual(
            response,
            {
                "type": "delivery_error",
                "text": "User 'nobody' is not connected.",
            },
        )

    async def test_rename_success_updates_directory(self) -> None:
        alice = await self.make_peer()
        bob = await self.make_peer()
        await alice.register("alice")
        await bob.register("bob")

        await bob.send({"type": "rename", "new_username": "robert"})
        rename_ok = await bob.recv()
        self.assertEqual(rename_ok, {"type": "rename_ok", "username": "robert"})

        await alice.send({"type": "list_users"})
        users_list = await alice.recv()
        self.assertIsNotNone(users_list)
        self.assertCountEqual(users_list["users"], ["alice", "robert"])

    async def test_rename_conflict_is_rejected(self) -> None:
        alice = await self.make_peer()
        bob = await self.make_peer()
        await alice.register("alice")
        await bob.register("bob")

        await bob.send({"type": "rename", "new_username": "alice"})
        response = await bob.recv()
        self.assertEqual(
            response,
            {"type": "rename_error", "text": "username is already in use"},
        )

    async def test_rename_invalid_username_is_rejected(self) -> None:
        alice = await self.make_peer()
        await alice.register("alice")

        await alice.send({"type": "rename", "new_username": "bad name"})
        response = await alice.recv()
        self.assertEqual(
            response,
            {
                "type": "rename_error",
                "text": "Username must be 1-32 characters and contain no spaces.",
            },
        )

    async def test_disconnect_removes_user_from_connected_list(self) -> None:
        alice = await self.make_peer()
        bob = await self.make_peer()
        await alice.register("alice")
        await bob.register("bob")

        await alice.send({"type": "disconnect"})
        self.assertIsNone(await alice.recv())

        await bob.send({"type": "list_users"})
        users_list = await bob.recv()
        self.assertEqual(users_list, {"type": "users_list", "users": ["bob"]})

    async def test_first_message_must_be_register(self) -> None:
        peer = await self.make_peer()

        await peer.send({"type": "list_users"})
        response = await peer.recv()
        self.assertEqual(
            response,
            {
                "type": "system_message",
                "text": "Protocol error: message type 'list_users' is not allowed here",
            },
        )
        self.assertIsNone(await peer.recv())

    async def test_malformed_json_disconnects_bad_client_but_server_keeps_working(self) -> None:
        bad = await self.make_peer()
        await bad.send_raw('{"type":"register","username":"alice"\n')

        response = await bad.recv()
        self.assertEqual(
            response,
            {"type": "system_message", "text": "Protocol error: message was not valid JSON"},
        )
        self.assertIsNone(await bad.recv())

        good = await self.make_peer()
        register_ok, welcome = await good.register("bob")
        self.assertEqual(register_ok, {"type": "register_ok", "username": "bob"})
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, bob. Type /help to see commands."},
        )

    async def test_server_shutdown_notifies_connected_clients(self) -> None:
        alice = await self.make_peer()
        await alice.register("alice")

        await shutdown_clients(self.store)
        response = await alice.recv()
        self.assertEqual(
            response,
            {"type": "system_message", "text": "Server is shutting down."},
        )
        self.assertIsNone(await alice.recv())

    async def test_client_rejects_server_with_untrusted_ca(self) -> None:
        wrong_ca_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        wrong_ca_context.minimum_version = ssl.TLSVersion.TLSv1_3

        with self.assertRaises(ssl.SSLCertVerificationError):
            await asyncio.open_connection(
                self.host,
                self.port,
                ssl=wrong_ca_context,
                server_hostname="localhost",
            )

    async def test_register_stores_public_identity_on_session(self) -> None:
        alice = await self.make_peer()
        await alice.register("alice")

        session = self.store.get_by_username("alice")
        assert session is not None
        self.assertEqual(session.public_identity.signing_public_key, alice.signing_public_key)
        self.assertEqual(
            session.public_identity.key_agreement_public_key,
            alice.key_agreement_public_key,
        )

    async def test_register_rejects_invalid_public_identity(self) -> None:
        peer = await self.make_peer()
        await peer.send(
            {
                "type": "register",
                "username": "alice",
                "signing_public_key": "not-base64",
                "key_agreement_public_key": peer.key_agreement_public_key,
            }
        )
        response = await peer.recv()
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Client identity error: Identity key data is not valid base64.",
            },
        )
        self.assertIsNone(await peer.recv())

    async def test_register_rejects_duplicate_active_signing_identity(self) -> None:
        alice = await self.make_peer()
        alias_peer = TestPeer(
            self.host,
            self.port,
            self.client_ssl_context,
            "localhost",
            alice.signing_public_key,
            alice.key_agreement_public_key,
        )
        await alias_peer.connect()
        self.peers.append(alias_peer)

        response, _ = await alice.register("alice")
        self.assertEqual(response, {"type": "register_ok", "username": "alice"})

        response, welcome = await alias_peer.register("alias")
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "This long-term signing identity is already connected as another user.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await alias_peer.recv())


class ProtocolValidationTests(unittest.TestCase):
    def test_validate_message_rejects_unknown_type(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "unknown"})

    def test_validate_message_rejects_empty_required_field(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "direct_message", "to": "bob", "text": "   "})

    def test_validate_message_rejects_invalid_users_list(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "users_list", "users": ["alice", ""]})

    def test_validate_message_requires_identity_fields_for_register(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "register", "username": "alice"})


class TlsConfigurationTests(unittest.TestCase):
    def test_parse_tls_version(self) -> None:
        self.assertEqual(parse_tls_version("1.2"), ssl.TLSVersion.TLSv1_2)
        self.assertEqual(parse_tls_version("1.3"), ssl.TLSVersion.TLSv1_3)

    def test_client_context_requires_peer_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ca_cert = Path(temp_dir) / "ca-cert.pem"
            ca_cert.write_text("", encoding="utf-8")

            with self.assertRaises(ssl.SSLError):
                build_client_ssl_context(
                    str(ca_cert),
                    minimum_version=ssl.TLSVersion.TLSv1_3,
                )


class IdentityTests(unittest.TestCase):
    def test_default_identity_dir_uses_username(self) -> None:
        expected = Path(DEFAULT_IDENTITIES_DIR) / "alice"
        self.assertEqual(default_identity_dir_for_username("alice"), expected)

    def test_default_identity_dir_sanitizes_username(self) -> None:
        expected = Path(DEFAULT_IDENTITIES_DIR) / "alice_team_1"
        self.assertEqual(default_identity_dir_for_username("alice/team#1"), expected)

    def test_identity_persists_across_loads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first = load_or_create_identity(temp_dir)
            second = load_or_create_identity(temp_dir)

            self.assertEqual(first.signing_fingerprint, second.signing_fingerprint)
            self.assertEqual(
                first.key_agreement_fingerprint,
                second.key_agreement_fingerprint,
            )

    def test_identity_file_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = load_or_create_identity(temp_dir)
            payload = json.loads(identity.path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], 1)
            self.assertIn("signing_private_key", payload)
            self.assertIn("key_agreement_private_key", payload)

    def test_validate_public_identity_accepts_generated_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = load_or_create_identity(temp_dir)
            public_identity = identity.public_identity

            validated = validate_public_identity(
                public_identity.signing_public_key,
                public_identity.key_agreement_public_key,
            )
            self.assertEqual(validated.signing_public_key, public_identity.signing_public_key)
            self.assertEqual(
                validated.key_agreement_public_key,
                public_identity.key_agreement_public_key,
            )

    def test_validate_public_identity_rejects_malformed_key_length(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = load_or_create_identity(temp_dir)
            public_identity = identity.public_identity

            with self.assertRaises(IdentityError):
                validate_public_identity(
                    public_identity.signing_public_key,
                    "AQ==",
                )

    def test_decode_key_bytes_rejects_non_base64(self) -> None:
        with self.assertRaises(IdentityError):
            decode_key_bytes("bad@@@")


if __name__ == "__main__":
    unittest.main()
