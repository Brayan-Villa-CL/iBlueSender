# iBlueSender

> iMessage automation toolkit written in Python

---

## Features

- Register new iMessage identities
- Send iMessages to any destination
- Receive iMessage notifications
- 2FA support (SMS & Trusted Device)
- BAA Authentication
- Session caching for quick relogin

---

## Installation

### Windows

    cd iBlueSender
    python -m pip install requests pbkdf2 pycryptodome srp cryptography

### macOS

    cd iBlueSender
    python3 -m venv Blue
    source Blue/bin/activate
    python3 -m pip install requests pbkdf2 pycryptodome srp cryptography

---

## Usage

### 1. Register Identity

    python login_im.py -e user@icloud.com -p yourpassword

    Options:
    -e    Apple ID email
    -p    Apple ID password

    Note: You may receive a 2FA prompt via SMS or Trusted Device.

### 2. Copy Session Cache

After successful registration, copy the session to the working directory:

    cp tmp/session_cache.json ./

### 3. Send iMessages

    python iMessage.py --to destination@email.com --message "Hello!"

    Options:
    --to       Destination (email or phone)
    --message  Message text

    Examples:

    # Send to email
    python iMessage.py --to user@icloud.com --message "Hello!"

    # Send to phone
    python iMessage.py --to tel:+1234567890 --message "Hello!"

### 4. Listen for Messages

    python iMessage.py --listen

    Options:
    --listen           Start listening for incoming messages
    --listen-timeout   Timeout in seconds (optional)

---

## Project Structure

    iBlueSender/
    ├── login_im.py          # Registration script
    ├── query.py             # lookup identity's
    ├── iMessage.py          # Send/Receive messages
    ├── tmp/
    │   └── session_cache.json
    └── README.md

---

## Requirements

- Python 3.8+
- Active Apple ID
- Network connection
