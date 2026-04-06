# TLS Terminal Messenger

This project is a minimal terminal-based client/server messenger written in Python. Clients connect to the server over TLS, register usernames, list connected users, and send direct messages.

The transport is protected with TLS and server certificate verification. Each client has a long-term Ed25519 identity key and a long-term X25519 key-agreement key. User trust is handled with a small local CA and a persistent server-side account registry:

`CA -> username -> Ed25519 identity key -> X25519 key`

On first registration the server checks that the username is free, issues a certificate for the user's Ed25519 identity key, and stores the permanent binding. On later logins the client presents that stored certificate and the server verifies the binding before allowing the session.

## Files

- `server.py`: asyncio TCP server that accepts clients, registers users, and routes messages
- `client.py`: terminal client with interactive commands
- `protocol.py`: newline-delimited JSON framing and protocol validation
- `storage.py`: in-memory connected-session store
- `accounts.py`: persistent account registry for long-term username bindings
- `identity.py`: long-term Ed25519/X25519 identity key management
- `cert_utils.py`: CA-backed X.509 certificate issuance and verification helpers
- `tls_utils.py`: TLS context configuration helpers
- `setup_messenger.sh`: one-step setup script for the CA and server certificate
- `requirements.txt`: dependency file for the project

## Requirements

- Python 3.11 or newer
- `cryptography` Python package
- OpenSSL command-line tool for generating local development certificates

Install Python dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

## Initial Setup

Run the setup script once:

```bash
./setup_messenger.sh
```

It creates:

- `certs/ca-cert.pem` and `certs/ca-key.pem`
- `certs/server-cert.pem` and `certs/server-key.pem`

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

If you previously generated certificates using older instructions, delete the old files in `certs/` and regenerate them. An older CA without the proper extensions can trigger:

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
  --ca-cert certs/ca-cert.pem \
  --ca-key certs/ca-key.pem \
  --accounts-file data/accounts.json \
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
- Default account registry: `data/accounts.json`

## Registration and Login

Each client profile stores two long-term private keys locally:

- Ed25519 as the certified long-term signing and identity key
- X25519 as the long-term key-agreement key

The client stores them in `identity.json` inside the selected identity directory. By default, if you do not pass `--identity-dir`, the client uses `identities/<username>` after you enter the username.

On first use for a new username:

- the client asks for a username
- the client generates or loads the local Ed25519/X25519 identity
- the client sends the username, the two public keys, and an Ed25519 signature over `username || X25519 public key`
- if the username is free, the server signs and returns a client certificate for that username and Ed25519 key
- the client stores that certificate locally as `identity-cert.pem`

On later logins:

- the client loads the stored certificate
- the client sends the certificate plus the identity bundle
- the server verifies that the certificate is signed by the CA
- the server verifies that the certificate subject matches the username
- the server verifies that the Ed25519 key matches the certificate
- the server verifies that the Ed25519 key signs the current X25519 key

The server stores the permanent username binding in `data/accounts.json`, so usernames remain bound to the same Ed25519 identity across server restarts.

Because the username is part of the long-term identity:

- usernames are permanent once registered
- rename is intentionally rejected
- if a user loses their private keys, account recovery is out of scope

If you want multiple local clients on the same machine, give each one a different identity directory, for example:

```bash
python3 client.py --identity-dir client-identities/alice
python3 client.py --identity-dir client-identities/bob
```

## Client Commands

- `/help` show available commands
- `/users` request the list of connected users
- `/msg <user> <text>` send a direct message to a connected user
- `/quit` disconnect cleanly and exit

## Example Session

1. Start `server.py`.
2. Open two terminals and run `client.py` in each.
3. On first use, register usernames such as `alice` and `bob`.
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
- No password-based accounts
- No application-layer message signatures yet
- No offline message delivery
- No message history or persistent message storage
- Connected sessions are stored in memory only while users are online
- Direct messages only, no group chats

## Extension Path

This layout is designed to be extended later with:

- end-to-end encryption
- signed application messages
- persistent or offline message storage
- richer account management
- group chats

## Testing

Run the automated tests with:

```bash
python3 -m unittest -v test_messenger.py
```
