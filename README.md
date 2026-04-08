# TLS Terminal Messenger

This project is a terminal-based secure messenger written in Python. Clients connect to a central server over TLS, authenticate with a password plus a CA-backed identity certificate, and exchange end-to-end encrypted direct messages.

Each client has a long-term Ed25519 identity key and a long-term X25519 key-agreement key. User trust is handled with a small local CA and a persistent server-side account registry:

`CA -> username -> Ed25519 identity key -> X25519 key`

On first registration the server checks that the username is free, stores a password verifier, issues a certificate for the user's Ed25519 identity key, and stores the permanent binding. On later logins the client presents the stored certificate and password, and the server verifies both before allowing the session.

Direct messages are also end-to-end encrypted at the application layer. The sender fetches the recipient's currently connected X25519 bundle, verifies the CA-issued Ed25519 certificate and X25519 binding signature locally, generates an ephemeral X25519 key for the message, derives an AES-256-GCM key via HKDF-SHA256, encrypts the plaintext, and signs the encrypted envelope with the sender's Ed25519 identity key. The server only forwards ciphertext and metadata needed for recipient-side verification.

## Layout

- `client/`: interactive client entrypoint and local client identity storage
- `server/`: server entrypoint, account registry, and server-side runtime data
- `ca/`: certificate and TLS helpers, setup script, and generated CA/server certs
- `shared/`: shared protocol and identity code used by both sides
- `tests/`: automated test suite
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
bash ./ca/setup.sh
```

Use `bash` here because `setup.sh` is a shell script. `python3 -m ...` is only for running Python modules like the server and client.

It creates:

- `ca/certs/ca-cert.pem` and `ca/certs/ca-key.pem`
- `ca/certs/server-cert.pem` and `ca/certs/server-key.pem`

## How to Run

Start the server in one terminal:

```bash
python3 -m server
```
Use `python3 -m server` because `server` is a Python package with an entrypoint.

Start a client in another terminal:

```bash
python3 -m client
```
Use `python3 -m client` because `client` is also a Python package with an entrypoint.

Start another client in a third terminal:

```bash
python3 -m client
```

Default connection settings:

- Host: `127.0.0.1`
- Port: `8888`
- Minimum TLS version: `1.3`
- Default identity directory: `client/identities/<username>`
- Default account registry: `server/data/accounts.json`

## Registration and Login

Each client profile stores two long-term private keys locally:

- Ed25519 as the certified long-term signing and identity key
- X25519 as the long-term key-agreement key

The client stores them in `identity.json` inside the selected identity directory. The private keys are encrypted on disk with a password-protected PKCS#8 keystore. By default, if you do not pass `--identity-dir`, the client uses `client/identities/<username>` after you enter the username.

The same password is used for both account login and local identity unlock, so the client only asks for one secret. After a successful login, the client stores an encrypted remembered session in the identity directory so later launches on the same machine can reuse it automatically. For non-interactive runs, you can provide the password with `MESSENGER_PASSWORD`. The older `MESSENGER_IDENTITY_PASSPHRASE` variable is still accepted as a fallback.

On first use for a new username:

- the client asks for a username
- the client asks you to create a password
- the client generates or loads the local Ed25519/X25519 identity using that password
- the client sends the username, password, the two public keys, and an Ed25519 signature over `username || X25519 public key`
- if the username is free, the server stores a password hash, signs and returns a client certificate for that username and Ed25519 key
- the client stores that certificate locally as `identity-cert.pem`
- the client stores a remembered local session alongside the identity files

On later logins:

- the client loads the stored certificate and remembered local session if present
- otherwise the client asks for the password
- the client uses that password to unlock the local identity
- the client sends the password, certificate, and identity bundle
- the server verifies the password against the stored scrypt hash
- the server verifies that the certificate is signed by the CA
- the server verifies that the certificate subject matches the username
- the server verifies that the Ed25519 key matches the certificate
- the server verifies that the Ed25519 key signs the current X25519 key

The server stores the permanent username binding and password verifier in `server/data/accounts.json`, so usernames remain bound to the same Ed25519 identity across server restarts.

Because the username is part of the long-term identity:

- usernames are permanent once registered
- rename is intentionally rejected
- if a user loses their private keys, account recovery is out of scope

By default, each username uses its own identity directory under `client/identities/<username>`, so running multiple local clients is fine as long as you log in with different usernames.

## Client Commands

- `/help` show available commands
- `/users` request the list of connected users
- `/msg <user> <text>` send a direct message to a connected user
- `/quit` disconnect cleanly and exit

## Example Session

1. Start `python3 -m server`.
2. Open two terminals and run `python3 -m client` in each.
3. On first use, register usernames such as `alice` and `bob`.
4. From Alice's client, run:

```text
/msg bob hello
```

5. Bob will see:

```text
[from alice]: hello
```

## Testing

Run the automated tests with:

```bash
python3 -m unittest -v tests.test_messenger
```
