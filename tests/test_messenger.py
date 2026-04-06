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

from ca.cert_utils import load_ca_certificate, load_ca_private_key
from ca.tls_utils import build_client_ssl_context, build_server_ssl_context, parse_tls_version
from server.accounts import AccountRegistry
from server.app import handle_client, shutdown_clients
from server.storage import SessionStore
from shared.e2ee import (
    MessageCryptoError,
    RecipientBundle,
    decrypt_message_from_sender,
    encrypt_message_for_recipient,
    validate_recipient_bundle,
)
from shared.identity import (
    DEFAULT_IDENTITIES_DIR,
    IdentityError,
    default_certificate_path,
    default_identity_dir_for_username,
    decode_key_bytes,
    load_or_create_identity,
    validate_public_identity,
)
from shared.protocol import ProtocolError, read_message, send_message, validate_message


class TestPeer:
    """Small async client used to exercise the server in tests."""

    def __init__(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_name: str,
        ca_certificate: object,
        username: str,
        identity_dir: Path,
    ) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.server_name = server_name
        self.ca_certificate = ca_certificate
        self.username = username
        self.identity = load_or_create_identity(identity_dir)
        self.signing_public_key = self.identity.public_identity.signing_public_key
        self.key_agreement_public_key = self.identity.public_identity.key_agreement_public_key
        self.certificate_path = default_certificate_path(self.identity.path.parent)
        self.certificate_pem = self._load_certificate()
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            self.host,
            self.port,
            ssl=self.ssl_context,
            server_hostname=self.server_name,
        )

    async def authenticate(
        self, username: str | None = None
    ) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        if self.certificate_pem is None:
            return await self.register(username)
        return await self.login(username)

    async def register(
        self, username: str | None = None
    ) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        claimed_username = username or self.username
        await self.send(
            {
                "type": "register",
                "username": claimed_username,
                "signing_public_key": self.signing_public_key,
                "key_agreement_public_key": self.key_agreement_public_key,
                "key_agreement_signature": self.identity.sign_key_agreement_binding(
                    claimed_username
                ),
            }
        )
        return await self._receive_auth_response()

    async def login(
        self,
        username: str | None = None,
        *,
        certificate_pem: str | None = None,
    ) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        claimed_username = username or self.username
        certificate = certificate_pem or self.certificate_pem
        if certificate is None:
            raise AssertionError("login requires a stored certificate")

        await self.send(
            {
                "type": "login",
                "username": claimed_username,
                "signing_public_key": self.signing_public_key,
                "key_agreement_public_key": self.key_agreement_public_key,
                "key_agreement_signature": self.identity.sign_key_agreement_binding(
                    claimed_username
                ),
                "identity_certificate": certificate,
            }
        )
        return await self._receive_auth_response()

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

    async def lookup_user(self, username: str) -> dict[str, object] | None:
        await self.send({"type": "lookup_user", "username": username})
        return await self.recv()

    async def send_encrypted_message(self, recipient: str, plaintext: str) -> None:
        response = await self.lookup_user(recipient)
        if response is None or response["type"] != "user_bundle":
            raise AssertionError(f"expected recipient bundle for {recipient}, got {response!r}")

        bundle = validate_recipient_bundle(
            RecipientBundle(
                username=str(response["username"]),
                signing_public_key=str(response["signing_public_key"]),
                key_agreement_public_key=str(response["key_agreement_public_key"]),
                key_agreement_signature=str(response["key_agreement_signature"]),
                identity_certificate=str(response["identity_certificate"]),
            ),
            self.ca_certificate,
        )
        envelope = encrypt_message_for_recipient(
            self.identity,
            self.username,
            bundle,
            plaintext,
        )
        await self.send({"type": "direct_message", "to": recipient, **envelope})

    def decrypt_incoming_message(self, message: dict[str, object]) -> str:
        return decrypt_message_from_sender(
            self.identity,
            self.username,
            str(message["from"]),
            str(message["signing_public_key"]),
            str(message["identity_certificate"]),
            str(message["sender_ephemeral_public_key"]),
            str(message["nonce"]),
            str(message["ciphertext"]),
            str(message["signature"]),
            self.ca_certificate,
        )

    async def disconnect(self) -> None:
        if self.writer is None or self.writer.is_closing():
            return
        await send_message(self.writer, {"type": "disconnect"})
        self.writer.close()
        await self.writer.wait_closed()

    async def close(self) -> None:
        if self.writer is None or self.writer.is_closing():
            return
        self.writer.close()
        await self.writer.wait_closed()

    async def _receive_auth_response(
        self,
    ) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        response = await self.recv()
        if response is None or response["type"] != "register_ok":
            return response, None

        self._store_certificate(str(response["identity_certificate"]))
        welcome = await self.recv()
        return response, welcome

    def _load_certificate(self) -> str | None:
        try:
            return self.certificate_path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _store_certificate(self, certificate_pem: str) -> None:
        self.certificate_path.parent.mkdir(parents=True, exist_ok=True)
        self.certificate_path.write_text(certificate_pem, encoding="utf-8")
        self.certificate_pem = certificate_pem


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
        self._runtime_dir = tempfile.TemporaryDirectory()
        self.runtime_dir = Path(self._runtime_dir.name)
        self.accounts_file = self.runtime_dir / "accounts.json"
        self.peers: list[TestPeer] = []
        await self.start_server()

    async def asyncTearDown(self) -> None:
        for peer in self.peers:
            await peer.close()
        await self.stop_server()
        self._runtime_dir.cleanup()

    async def start_server(self) -> None:
        self.store = SessionStore()
        self.accounts = AccountRegistry(self.accounts_file)
        self.ca_certificate = load_ca_certificate(str(self._ca_cert))
        self.ca_private_key = load_ca_private_key(str(self._ca_key))
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
            lambda reader, writer: handle_client(
                reader,
                writer,
                self.store,
                self.accounts,
                self.ca_certificate,
                self.ca_private_key,
            ),
            "127.0.0.1",
            0,
            ssl=self.server_ssl_context,
        )
        socket = self.server.sockets[0]
        self.host, self.port = socket.getsockname()[:2]

    async def stop_server(self) -> None:
        await shutdown_clients(self.store)
        self.server.close()
        await self.server.wait_closed()

    async def restart_server(self) -> None:
        await self.stop_server()
        await self.start_server()

    async def make_peer(self, username: str, *, identity_dir: Path | None = None) -> TestPeer:
        identity_path = identity_dir or self.runtime_dir / f"peer-{len(self.peers)}"
        peer = TestPeer(
            self.host,
            self.port,
            self.client_ssl_context,
            "localhost",
            self.ca_certificate,
            username,
            identity_path,
        )
        await peer.connect()
        self.peers.append(peer)
        return peer

    async def test_first_registration_issues_certificate_and_persists_account(self) -> None:
        alice = await self.make_peer("alice")

        register_ok, welcome = await alice.register()
        self.assertEqual(register_ok["type"], "register_ok")
        self.assertEqual(register_ok["username"], "alice")
        self.assertIn("BEGIN CERTIFICATE", str(register_ok["identity_certificate"]))
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, alice. Type /help to see commands."},
        )
        self.assertTrue(alice.certificate_path.exists())

        account = self.accounts.get("alice")
        self.assertIsNotNone(account)
        assert account is not None
        self.assertEqual(account.signing_public_key, alice.signing_public_key)
        self.assertEqual(account.key_agreement_public_key, alice.key_agreement_public_key)

    async def test_later_login_with_stored_certificate_succeeds(self) -> None:
        alice = await self.make_peer("alice")
        await alice.register()
        alice_identity_dir = alice.identity.path.parent
        await alice.disconnect()

        alice_again = await self.make_peer("alice", identity_dir=alice_identity_dir)
        login_ok, welcome = await alice_again.login()
        self.assertEqual(login_ok["type"], "register_ok")
        self.assertEqual(login_ok["username"], "alice")
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, alice. Type /help to see commands."},
        )

    async def test_account_persists_across_server_restart(self) -> None:
        alice = await self.make_peer("alice")
        await alice.register()
        alice_identity_dir = alice.identity.path.parent
        await alice.disconnect()

        await self.restart_server()

        alice_again = await self.make_peer("alice", identity_dir=alice_identity_dir)
        login_ok, welcome = await alice_again.login()
        self.assertEqual(login_ok["username"], "alice")
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, alice. Type /help to see commands."},
        )

    async def test_register_and_list_users(self) -> None:
        alice = await self.make_peer("alice")
        bob = await self.make_peer("bob")

        await alice.authenticate()
        await bob.authenticate()

        await alice.send({"type": "list_users"})
        users_list = await alice.recv()
        self.assertIsNotNone(users_list)
        self.assertEqual(users_list["type"], "users_list")
        self.assertCountEqual(users_list["users"], ["alice", "bob"])

    async def test_register_rejects_taken_username_with_different_identity(self) -> None:
        alice = await self.make_peer("alice")
        impostor = await self.make_peer("alice")

        response, _ = await alice.register()
        self.assertEqual(response["username"], "alice")

        response, welcome = await impostor.register()
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Username 'alice' is already registered.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await impostor.recv())

    async def test_login_rejects_unregistered_username(self) -> None:
        alice = await self.make_peer("alice")
        alice.certificate_pem = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"

        response, welcome = await alice.login()
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Username 'alice' is not registered.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await alice.recv())

    async def test_login_rejects_certificate_username_mismatch(self) -> None:
        alice = await self.make_peer("alice")
        await alice.register()
        alice_certificate = alice.certificate_pem
        await alice.disconnect()

        bob_real = await self.make_peer("bob")
        await bob_real.register()
        bob_identity_dir = bob_real.identity.path.parent
        await bob_real.disconnect()

        bob = await self.make_peer("bob", identity_dir=bob_identity_dir)
        response, welcome = await bob.login(username="bob", certificate_pem=alice_certificate)
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Client certificate error: Client certificate common name does not match the username.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await bob.recv())

    async def test_direct_message_is_delivered(self) -> None:
        alice = await self.make_peer("alice")
        bob = await self.make_peer("bob")
        await alice.authenticate()
        await bob.authenticate()

        await alice.send_encrypted_message("bob", "hello")
        incoming = await bob.recv()
        self.assertIsNotNone(incoming)
        assert incoming is not None
        self.assertEqual(incoming["type"], "incoming_message")
        self.assertEqual(incoming["from"], "alice")
        self.assertEqual(bob.decrypt_incoming_message(incoming), "hello")

    async def test_direct_message_to_missing_user_returns_delivery_error(self) -> None:
        alice = await self.make_peer("alice")
        await alice.authenticate()

        await alice.send(
            {
                "type": "direct_message",
                "to": "nobody",
                "sender_ephemeral_public_key": alice.key_agreement_public_key,
                "nonce": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AQ==",
                "signature": "AQ==",
            }
        )
        response = await alice.recv()
        self.assertEqual(
            response,
            {
                "type": "delivery_error",
                "text": "User 'nobody' is not connected.",
            },
        )

    async def test_lookup_user_returns_certified_key_bundle(self) -> None:
        alice = await self.make_peer("alice")
        bob = await self.make_peer("bob")
        await alice.authenticate()
        await bob.authenticate()

        response = await alice.lookup_user("bob")
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["type"], "user_bundle")
        self.assertEqual(response["username"], "bob")
        self.assertEqual(response["signing_public_key"], bob.signing_public_key)
        self.assertEqual(response["key_agreement_public_key"], bob.key_agreement_public_key)

    async def test_tampered_incoming_message_fails_signature_verification(self) -> None:
        alice = await self.make_peer("alice")
        bob = await self.make_peer("bob")
        await alice.authenticate()
        await bob.authenticate()

        await alice.send_encrypted_message("bob", "hello")
        incoming = await bob.recv()
        self.assertIsNotNone(incoming)
        assert incoming is not None
        tampered = dict(incoming)
        tampered["ciphertext"] = "Ag=="

        with self.assertRaises(MessageCryptoError):
            bob.decrypt_incoming_message(tampered)

    async def test_rename_is_rejected(self) -> None:
        alice = await self.make_peer("alice")
        await alice.authenticate()

        await alice.send({"type": "rename", "new_username": "robert"})
        response = await alice.recv()
        self.assertEqual(
            response,
            {
                "type": "rename_error",
                "text": "Usernames are bound to CA-signed certificates and cannot be changed.",
            },
        )

    async def test_disconnect_removes_user_from_connected_list(self) -> None:
        alice = await self.make_peer("alice")
        bob = await self.make_peer("bob")
        await alice.authenticate()
        await bob.authenticate()

        await alice.send({"type": "disconnect"})
        self.assertIsNone(await alice.recv())

        await bob.send({"type": "list_users"})
        users_list = await bob.recv()
        self.assertEqual(users_list, {"type": "users_list", "users": ["bob"]})

    async def test_first_message_must_be_register_or_login(self) -> None:
        peer = await self.make_peer("alice")

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
        bad = await self.make_peer("alice")
        await bad.send_raw('{"type":"register","username":"alice"\n')

        response = await bad.recv()
        self.assertEqual(
            response,
            {"type": "system_message", "text": "Protocol error: message was not valid JSON"},
        )
        self.assertIsNone(await bad.recv())

        good = await self.make_peer("bob")
        register_ok, welcome = await good.register()
        self.assertEqual(register_ok["username"], "bob")
        self.assertEqual(
            welcome,
            {"type": "system_message", "text": "Welcome, bob. Type /help to see commands."},
        )

    async def test_server_shutdown_notifies_connected_clients(self) -> None:
        alice = await self.make_peer("alice")
        await alice.authenticate()

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

    async def test_authenticated_session_stores_public_identity(self) -> None:
        alice = await self.make_peer("alice")
        await alice.authenticate()

        session = self.store.get_by_username("alice")
        assert session is not None
        self.assertEqual(session.public_identity.signing_public_key, alice.signing_public_key)
        self.assertEqual(
            session.public_identity.key_agreement_public_key,
            alice.key_agreement_public_key,
        )

    async def test_register_rejects_invalid_public_identity(self) -> None:
        peer = await self.make_peer("alice")
        await peer.send(
            {
                "type": "register",
                "username": "alice",
                "signing_public_key": "not-base64",
                "key_agreement_public_key": peer.key_agreement_public_key,
                "key_agreement_signature": peer.identity.sign_key_agreement_binding("alice"),
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

    async def test_register_rejects_invalid_key_binding_signature(self) -> None:
        peer = await self.make_peer("alice")
        await peer.send(
            {
                "type": "register",
                "username": "alice",
                "signing_public_key": peer.signing_public_key,
                "key_agreement_public_key": peer.key_agreement_public_key,
                "key_agreement_signature": peer.identity.sign_key_agreement_binding("mallory"),
            }
        )
        response = await peer.recv()
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "Client identity error: Key-agreement public key signature is invalid.",
            },
        )
        self.assertIsNone(await peer.recv())

    async def test_signing_identity_cannot_register_second_username(self) -> None:
        alice = await self.make_peer("alice")
        await alice.authenticate()

        alias_peer = await self.make_peer("alias", identity_dir=alice.identity.path.parent)
        response, welcome = await alias_peer.register()
        self.assertEqual(
            response,
            {
                "type": "register_error",
                "text": "This signing identity is already permanently bound to username 'alice'.",
            },
        )
        self.assertIsNone(welcome)
        self.assertIsNone(await alias_peer.recv())

    async def test_invalid_username_is_rejected(self) -> None:
        peer = await self.make_peer("alice")

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


class ProtocolValidationTests(unittest.TestCase):
    def test_validate_message_rejects_unknown_type(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "unknown"})

    def test_validate_message_rejects_empty_required_field(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message(
                {
                    "type": "direct_message",
                    "to": "bob",
                    "sender_ephemeral_public_key": "abc",
                    "nonce": "def",
                    "ciphertext": "   ",
                    "signature": "ghi",
                }
            )

    def test_validate_message_rejects_invalid_users_list(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "users_list", "users": ["alice", ""]})

    def test_validate_message_requires_identity_fields_for_register(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "register", "username": "alice"})

    def test_validate_message_requires_certificate_for_login(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message(
                {
                    "type": "login",
                    "username": "alice",
                    "signing_public_key": "a",
                    "key_agreement_public_key": "b",
                    "key_agreement_signature": "c",
                }
            )

    def test_validate_message_requires_certificate_in_register_ok(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "register_ok", "username": "alice"})

    def test_validate_message_requires_bundle_fields_in_user_bundle(self) -> None:
        with self.assertRaises(ProtocolError):
            validate_message({"type": "user_bundle", "username": "alice"})


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
