import socket
import threading
import logging
import os
from datetime import datetime
from crypto import generate_key, encrypt_message, decrypt_message
from auth import verify_user # Import authentication functions

HOST = '127.0.0.1'
PORT = 65432
KEY = generate_key()

# Setup Logging
LOG_DIR = "data/logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

log_file_name = datetime.now().strftime("server_%Y-%m-%d_%H-%M-%S.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, log_file_name)),
        logging.StreamHandler() # Also log to console
    ]
)
logger = logging.getLogger(__name__)


# Store client connections and their authenticated state/username
# Using a dictionary: {conn: {"addr": addr, "username": None, "authenticated": False}}
connected_clients_info = {}
clients_info_lock = threading.Lock()

def send_encrypted_message(sock, message):
    """Helper function to encrypt and send a message."""
    try:
        sock.sendall(encrypt_message(KEY, message))
    except Exception as e:
        logger.error(f"Error sending encrypted message to {sock.getpeername() if sock.fileno() != -1 else 'N/A'}: {e}")

def broadcast_message(message_text, source_username, source_conn):
    """
    Broadcasts a message to all *authenticated* clients except the source.
    """
    full_message = f"<{source_username}> {message_text}"
    # Log a snippet of the message to avoid overly verbose logs with long messages.
    log_message_snippet = message_text[:100] + ('...' if len(message_text) > 100 else '')
    logger.info(f"Broadcasting from {source_username} (to others): \"{log_message_snippet}\"")
    with clients_info_lock:
        for conn, info in connected_clients_info.items():
            if info["authenticated"] and conn != source_conn:
                send_encrypted_message(conn, full_message)

def handle_client(conn, addr):
    """
    Handles a single client connection, including authentication and message routing.
    """
    logger.info(f"New connection from {addr}. Waiting for authentication.")
    current_username = None
    authenticated = False

    with clients_info_lock:
        connected_clients_info[conn] = {"addr": addr, "username": None, "authenticated": False}

    try:
        # Authentication phase
        send_encrypted_message(conn, "AUTH_REQUIRED Please login using /login <username> <password>")

        auth_attempts = 0
        max_auth_attempts = 3

        while not authenticated and auth_attempts < max_auth_attempts:
            encrypted_auth_data = conn.recv(4096)
            if not encrypted_auth_data:
                print(f"[{addr}] Disconnected during authentication.")
                return # Exit handler

            try:
                auth_message = decrypt_message(KEY, encrypted_auth_data).strip()
                print(f"[{addr}] Auth attempt: {auth_message!r}")
                parts = auth_message.split(maxsplit=2) # /login username password

                if len(parts) == 3 and parts[0].lower() == "/login":
                    username, password = parts[1], parts[2]
                    if verify_user(username, password):
                        authenticated = True
                        current_username = username
                        with clients_info_lock:
                            connected_clients_info[conn]["username"] = username
                            connected_clients_info[conn]["authenticated"] = True
                        send_encrypted_message(conn, f"AUTH_SUCCESS Welcome {username}!")
                        print(f"[{addr}] User {username} authenticated successfully.")
                        broadcast_message(f"{username} has joined the chat.", "System", conn) # Inform others
                    else:
                        auth_attempts += 1
                        send_encrypted_message(conn, f"AUTH_FAIL Invalid credentials. Attempts left: {max_auth_attempts - auth_attempts}")
                        print(f"[{addr}] Authentication failed for {username}. Attempts: {auth_attempts}")
                else:
                    auth_attempts += 1 # Count malformed attempts too
                    send_encrypted_message(conn, f"AUTH_FAIL Invalid login command format. Use /login <username> <password>. Attempts left: {max_auth_attempts - auth_attempts}")
            except Exception as e:
                print(f"[{addr}] Error during authentication: {e}")
                auth_attempts += 1 # Count as an attempt
                send_encrypted_message(conn, f"AUTH_ERROR An error occurred. Attempts left: {max_auth_attempts - auth_attempts}")

        if not authenticated:
            print(f"[{addr}] Failed to authenticate after {max_auth_attempts} attempts. Closing connection.")
            send_encrypted_message(conn, "AUTH_FAIL_MAX_ATTEMPTS Max authentication attempts reached. Disconnecting.")
            return # Exit handler, connection will be closed in finally

        # Authenticated phase - message handling
        while True:
            encrypted_data = conn.recv(4096)
            if not encrypted_data:
                print(f"[{addr}] ({current_username}) Client closed connection.")
                break

            try:
                decrypted_message = decrypt_message(KEY, encrypted_data).strip()
                print(f"[{addr}] ({current_username}) Decrypted: {decrypted_message!r}")

                if decrypted_message.lower() == '/quit':
                    print(f"[{addr}] ({current_username}) Sent /quit. Closing connection.")
                    broadcast_message(f"{current_username} has left the chat.", "System", conn)
                    break
                elif decrypted_message.lower() == '/list':
                    print(f"[{addr}] ({current_username}) Requested user list.")
                    with clients_info_lock:
                        online_users = [info["username"] for info in connected_clients_info.values() if info["authenticated"] and info["username"]]
                    user_list_message = "SERVER_INFO_LIST Currently online users: " + ", ".join(sorted(online_users))
                    send_encrypted_message(conn, user_list_message)
                else:
                    # Simple message broadcasting
                    broadcast_message(decrypted_message, current_username, conn)

            except Exception as e:
                print(f"[{addr}] ({current_username}) Error processing message: {e}")
                send_encrypted_message(conn, "SERVER_ERROR Error processing your message.")
                # Optionally break or continue based on error severity

    except ConnectionResetError:
        print(f"[CONNECTION RESET] {addr} ({current_username or 'unauthenticated'}) connection reset by peer.")
    except Exception as e:
        print(f"[ERROR] Unhandled exception for {addr} ({current_username or 'unauthenticated'}): {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled exception for {addr}: {e}")
    finally:
        print(f"[DISCONNECTED] {addr} disconnected.")
        with clients_info_lock:
            if conn in connected_clients_info:
                del connected_clients_info[conn]
        conn.close()

def start_server():
    """
    Starts the TCP chat server.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
        s.bind((HOST, PORT))
        s.listen()
        print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

        try:
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.daemon = True # Daemonize thread to allow main program to exit
                thread.start()
        except KeyboardInterrupt:
            print("\n[SHUTTING DOWN] Server is shutting down...")
        finally:
            with clients_info_lock:
                for client_conn in list(connected_clients_info.keys()):
                    client_conn.close()
            s.close()
            print("[SERVER CLOSED]")

if __name__ == "__main__":
    start_server()
