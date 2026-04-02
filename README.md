# Plaintext Terminal Messenger

This project is a minimal terminal-based client/server messenger written in Python. It provides the baseline messaging architecture only: multiple clients can connect to a TCP server, register usernames, list connected users, send direct messages, and optionally rename themselves.

This version is intentionally insecure. It uses plaintext TCP connections with no encryption, no authentication, no TLS, no certificates, and no account system. The goal is to establish a clean baseline that can be extended later with security features.

## Files

- `server.py`: asyncio TCP server that accepts clients and routes messages
- `client.py`: terminal client with interactive commands
- `protocol.py`: newline-delimited JSON framing and protocol validation
- `storage.py`: in-memory connected-user session store
- `requirements.txt`: dependency file for the project

## Requirements

- Python 3.11 or newer
- No external dependencies

## How to Run

Start the server:

```bash
python3 server.py
```

Optional arguments:

```bash
python3 server.py --host 127.0.0.1 --port 8888
```

Start one or more clients in separate terminals:

```bash
python3 client.py
```

Optional arguments:

```bash
python3 client.py --host 127.0.0.1 --port 8888
```

Default connection settings:

- Host: `127.0.0.1`
- Port: `8888`

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

- Plaintext transport only
- No user authentication
- No passwords or accounts
- No end-to-end encryption
- No message signing or non-repudiation yet
- No offline message delivery
- No persistent storage or database
- Connected users are stored in memory only
- Direct messages only, no group chats

## Extension Path

This layout is designed to be extended later with:

- TLS for client/server transport protection
- Authentication and identity management
- Public/private key infrastructure
- End-to-end encryption
- Signed messages
- Persistent or offline message storage
