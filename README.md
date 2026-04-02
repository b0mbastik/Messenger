# TLS Terminal Messenger

This project is a minimal terminal-based client/server messenger written in Python. Clients connect to the server over TLS, register usernames, list connected users, send direct messages, and optionally rename themselves.

This version now protects the client-server transport with TLS and server certificate verification. It still does not provide end-to-end encryption, user accounts, passwords, message signatures, or client certificate authentication. The goal is to secure the transport first, then extend the system further.

## Files

- `server.py`: asyncio TCP server that accepts clients and routes messages
- `client.py`: terminal client with interactive commands
- `protocol.py`: newline-delimited JSON framing and protocol validation
- `storage.py`: in-memory connected-user session store
- `tls_utils.py`: TLS context configuration helpers
- `generate_dev_certs.sh`: helper script for local CA and server certificate generation
- `requirements.txt`: dependency file for the project

## Requirements

- Python 3.11 or newer
- No Python package dependencies
- OpenSSL command-line tool for generating local development certificates

## How to Run

## Generate Development Certificates

Create a local `certs/` directory:

```bash
mkdir -p certs
```

The easiest way to generate a correct local CA and server certificate is:

```bash
./generate_dev_certs.sh
```

This script creates a CA certificate with the required CA extensions and a server certificate valid for both `localhost` and `127.0.0.1`.

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
  --tls-min-version 1.3
```

Default connection settings:

- Host: `127.0.0.1`
- Port: `8888`
- Minimum TLS version: `1.3`

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
- No message signing or non-repudiation yet
- No offline message delivery
- No persistent storage or database
- Connected users are stored in memory only
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
