# Secure TCP Chat Application

## Project Description

This project is a secure client-server messaging system based on TCP sockets, developed in Python. It allows multiple clients to authenticate with a server and exchange AES-encrypted text messages. The server manages client sessions concurrently using multi-threading.

**Team:** Student team of four (for a 3-week network programming project).

## Features

-   **Client-Server Architecture:** Uses TCP sockets for reliable communication.
-   **User Authentication:** Clients must authenticate with a username and password. User credentials (hashed passwords) are stored in `data/users.json`.
-   **AES Encryption:** All messages exchanged between clients and the server are encrypted using AES (CBC mode with PKCS7 padding). A fixed encryption key is currently used (defined in `client/crypto.py` and `server/crypto.py`).
-   **Concurrent Client Handling:** The server uses multi-threading to manage multiple client connections simultaneously.
-   **Basic CLI Interface:** Clients interact through a command-line interface.
-   **Client Commands:**
    -   `/login <username> <password>`: Authenticate with the server.
    -   `/list`: View a list of currently online users.
    -   `/quit`: Disconnect from the server.
    -   `/help`: Display available commands.
    -   Any other text input is treated as a chat message to be broadcast.
-   **Server-Side Logging:** Key server activities (connections, disconnections, authentications, errors) are logged to files in `data/logs/` and to the console.

## Folder Structure

```
SecureChatTCP/
├── server/
│   ├── server.py         # Main server logic, connection handling, message routing
│   ├── auth.py           # User authentication logic
│   ├── crypto.py         # AES encryption/decryption utilities (copied from client/)
│   └── utils.py          # (Currently unused, placeholder for server utilities)
├── client/
│   ├── client.py         # Main client logic, connection to server, message sending/receiving
│   ├── interface.py      # (Currently, CLI is in client.py, placeholder for future GUI/CLI)
│   └── crypto.py         # AES encryption/decryption utilities
├── data/
│   ├── users.json        # Stores user credentials (usernames and hashed passwords)
│   └── logs/             # Directory for server log files
├── tests/
│   └── test_crypto.py    # Unit tests for encryption/decryption functions
├── README.md             # This file
└── requirements.txt      # Python package dependencies
```

## Setup and Installation

1.  **Clone the repository (if applicable):**
    ```bash
    git clone <repository_url>
    cd SecureChatTCP
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    This will install `cryptography` for AES encryption and `werkzeug` for password hashing.

4.  **Prepare User Data:**
    -   A sample `data/users.json` file is provided with pre-hashed passwords for `testuser` (password: `password123`) and `anotheruser` (password: `password123`).
    -   To add new users or change passwords:
        -   You can manually edit `data/users.json` if you have a pre-hashed password (using `pbkdf2:sha256:600000$<salt>$<hash>`).
        -   Alternatively, the `server/auth.py` script can be modified or run with example code to add users (it includes an `add_user` function that hashes passwords). For example, you could temporarily uncomment and run the `add_user` lines in its `if __name__ == '__main__':` block.

## How to Run

1.  **Start the Server:**
    Open a terminal, navigate to the project root directory (`SecureChatTCP/`), and run:
    ```bash
    python server/server.py
    ```
    The server will start listening on `127.0.0.1:65432`. Log messages will appear in the console and be saved to `data/logs/`.

2.  **Start the Client(s):**
    Open one or more new terminals, navigate to the project root directory, and run:
    ```bash
    python client/client.py
    ```
    -   The client will attempt to connect to the server.
    -   Upon connection, the server will prompt for authentication.
    -   Type `/login <username> <password>` (e.g., `/login testuser password123`).
    -   Once authenticated, you can send messages or use other commands like `/list`, `/help`, or `/quit`.

## Running Tests

To run the unit tests for the cryptography module:
```bash
python -m unittest tests/test_crypto.py
```

## Security Considerations & Future Improvements

-   **Key Management:** Currently, a fixed AES key is used. In a production system, secure key generation, distribution, and rotation mechanisms (e.g., Diffie-Hellman key exchange, TLS for key negotiation) would be crucial.
-   **Authentication Security:**
    -   The current `users.json` is simple. A database (like SQLite) would be more robust for user management.
    -   Consider measures against timing attacks for password verification if not already handled by `werkzeug`.
-   **Integrity Checks:** HMAC or other hash verification could be added to messages to ensure integrity alongside confidentiality.
-   **Error Handling:** More granular error handling and reporting to the client can be implemented.
-   **Server Robustness:** Implement more advanced server features like rate limiting, banning abusive users, etc.
-   **Client Interface:** The CLI is basic. A GUI (e.g., using Tkinter, PyQt, Kivy) could be developed.
-   **Private Messaging:** Implement direct messages between users (e.g., `/msg <user> <message>`).
-   **Scalability:** For a large number of users, asynchronous I/O (e.g., `asyncio`) might be more scalable than threading, though threading is suitable for moderate loads.
-   **Configuration:** Use configuration files for server host, port, key paths, etc., instead of hardcoding.

## Contribution

This is a student project. Contributions, suggestions, and feedback are welcome.
(If this were an open-source project, add guidelines for contributing here).