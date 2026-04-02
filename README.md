# TLS Terminal Messenger

This project is a minimal terminal-based client/server messenger written in Python. Clients connect to the server over TLS, register usernames, list connected users, send direct messages, and optionally rename themselves.

This version now protects the client-server transport with TLS and server certificate verification. Each client also has its own long-term identity keys: one Ed25519 key for signatures and one X25519 key for key agreement. It still does not provide end-to-end encryption, user accounts, passwords, message signatures in the chat flow, or client certificate authentication yet. The goal is to secure the transport first, then build the application-layer crypto.

## Files

- `server.py`: asyncio TCP server that accepts clients and routes messages
- `client.py`: terminal client with interactive commands
- `protocol.py`: newline-delimited JSON framing and protocol validation
- `storage.py`: in-memory connected-user session store
- `identity.py`: long-term Ed25519/X25519 identity key management
- `tls_utils.py`: TLS context configuration helpers
- `generate_dev_certs.sh`: helper script for local CA and server certificate generation
- `requirements.txt`: dependency file for the project

## Requirements

- Python 3.11 or newer
- `cryptography` Python package
- OpenSSL command-line tool for generating local development certificates

Install Python dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

## How to Run

## Generate Development Certificates

The easiest way to generate a correct local CA and server certificate is:

```bash
./generate_dev_certs.sh
```

This script creates the `certs/` directory automatically, then writes a CA certificate with the required CA extensions and a server certificate valid for both `localhost` and `127.0.0.1`.

If you want to generate them manually, use these exact commands.

Create an OpenSSL extension file for the server certificate:

```bash
cat > certs/server-ext.cnf <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
```

Create a local CA certificate with explicit CA extensions:

```bash
openssl req -x509 -new -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/ca-key.pem \
  -out certs/ca-cert.pem \
  -subj "/CN=Messenger Local CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

Create a server key and certificate signing request:

```bash
openssl req -new -nodes -newkey rsa:2048 \
  -keyout certs/server-key.pem \
  -out certs/server.csr \
  -subj "/CN=localhost"
```

Sign the server certificate with the local CA:

```bash
openssl x509 -req -days 365 \
  -in certs/server.csr \
  -CA certs/ca-cert.pem \
  -CAkey certs/ca-key.pem \
  -CAcreateserial \
  -out certs/server-cert.pem \
  -extfile certs/server-ext.cnf
```

If you previously generated certificates using the older instructions, delete the old files in `certs/` and regenerate them. The old CA certificate is what triggers:

```text
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: CA cert does not include key usage extension
```

## How to Run

Start the TLS server:

```bash
python3 server.py
```

Optional arguments:

```bash
python3 server.py --host 127.0.0.1 --port 8888 \
  --certfile certs/server-cert.pem \
  --keyfile certs/server-key.pem \
  --tls-min-version 1.3
```

Start one or more clients in separate terminals:

```bash
python3 client.py
```

Optional arguments:

```bash
python3 client.py --host 127.0.0.1 --port 8888 \
  --ca-cert certs/ca-cert.pem \
  --server-name localhost \
  --tls-min-version 1.3 \
  --identity-dir identities/alice
```

Default connection settings:

- Host: `127.0.0.1`
- Port: `8888`
- Minimum TLS version: `1.3`
- Default identity directory: `identities/<username>`

## Long-Term Client Identity Keys

Each client profile stores two long-term private keys locally:

- Ed25519 for future signing and identity verification
- X25519 for future key agreement

The client stores them in `identity.json` inside the selected identity directory. By default, if you do not pass `--identity-dir`, the client uses `identities/<username>` after you enter the username. On first use the keys are generated automatically; on later runs they are loaded from disk and reused.

If you want multiple local clients to have different long-term identities on the same machine, give each one a different identity directory, for example:

```bash
python3 client.py --identity-dir client-identities/alice
python3 client.py --identity-dir client-identities/bob
```

If you do not pass `--identity-dir`, these two commands now also work safely by default because the identity path is derived from the username you enter in each client:

```bash
python3 client.py
python3 client.py
```

## Client Commands

- `/help` show available commands
- `/users` request the list of connected users
- `/msg <user> <text>` send a direct message to a connected user
- `/name <new_name>` change your username if the new name is available
- `/quit` disconnect cleanly and exit

## Example Session

1. Start `server.py`.
2. Open two terminals and run `client.py` in each.
3. Register usernames such as `alice` and `bob`.
4. From Alice's client, run:

```text
/msg bob hello
```

5. Bob will see:

```text
[from alice]: hello
```

## Current Limitations

- No end-to-end encryption yet
- No user authentication
- No passwords or accounts
- No client certificate authentication
- Long-term identity keys exist but are not yet used to sign chat messages
- No offline message delivery
- No persistent storage or database
- Connected users and their public identity keys are stored in memory only
- Direct messages only, no group chats

## Extension Path

This layout is designed to be extended later with:

- Authentication and identity management
- Public/private key infrastructure
- End-to-end encryption
- Signed messages
- Persistent or offline message storage

## Testing

Run the automated tests with:

```bash
python3 -m unittest -v test_messenger.py
```
