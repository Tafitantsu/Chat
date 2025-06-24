import socket
import threading
import sys
from crypto import generate_key, encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 65432
KEY = generate_key()

authenticated = False
stop_threads = threading.Event() # Event to signal threads to stop

def send_encrypted(sock, message_text):
    """Helper to encrypt and send a message."""
    try:
        encrypted_msg = encrypt_message(KEY, message_text)
        sock.sendall(encrypted_msg)
    except Exception as e:
        print(f"Error sending message: {e}")
        # Potentially signal to close connection if send fails critically
        stop_threads.set()


def receive_messages(sock):
    """
    Handles receiving messages from the server and decrypts them.
    Also handles authentication prompts from the server.
    """
    global authenticated
    try:
        while not stop_threads.is_set():
            encrypted_message_encoded = sock.recv(4096)
            if not encrypted_message_encoded:
                print("Connection closed by the server.")
                stop_threads.set()
                break

            try:
                decrypted_message = decrypt_message(KEY, encrypted_message_encoded)
                print(f"{decrypted_message}") # Display decrypted message

                if decrypted_message.startswith("AUTH_REQUIRED"):
                    authenticated = False
                    print("Please log in as prompted by the server.")
                elif decrypted_message.startswith("AUTH_SUCCESS"):
                    authenticated = True
                    print("Authentication successful.")
                elif decrypted_message.startswith("AUTH_FAIL"):
                    authenticated = False
                    # Server might disconnect after too many failures, or client might choose to quit.
                    if "Max authentication attempts reached" in decrypted_message:
                        print("Max authentication attempts reached. Disconnecting.")
                        stop_threads.set()
                        break
                elif decrypted_message.startswith("AUTH_ERROR"):
                    authenticated = False
                    print("Authentication error on server. Try again or check credentials.")
                elif decrypted_message.startswith("SERVER_INFO_LIST"):
                    # Server sends list like "SERVER_INFO_LIST Currently online users: user1, user2"
                    # We've already printed it, so nothing specific to do here unless we want to format it.
                    # The print(f"{decrypted_message}") in the outer loop already handles it.
                    pass # Message is already printed by the main print statement.

            except Exception as e:
                print(f"Error decrypting/processing server message: {e}. Raw: {encrypted_message_encoded[:100]}") # Show partial raw
                # If critical error, maybe stop
                # stop_threads.set()
                # break

    except ConnectionResetError:
        if not stop_threads.is_set(): print("Connection to the server was lost.")
    except Exception as e:
        if not stop_threads.is_set(): print(f"Error receiving message: {e}")
    finally:
        stop_threads.set() # Ensure other threads know to stop
        if sock.fileno() != -1:
             try:
                sock.shutdown(socket.SHUT_RDWR)
             except OSError:
                pass # Ignore if already closed
             finally:
                sock.close()
        print("Receive thread stopped.")


def send_messages(sock):
    """
    Handles sending user input to the server after encrypting it.
    """
    global authenticated
    try:
        while not stop_threads.is_set():
            try:
                message_to_send = input()
            except EOFError: # Handle Ctrl+D or piped input ending
                print("Input stream closed. Sending /quit.")
                message_to_send = "/quit"
            except KeyboardInterrupt: # Handle Ctrl+C
                print("Ctrl+C detected. Sending /quit.")
                message_to_send = "/quit"
                # To ensure it gets sent before threads might be stopped abruptly elsewhere
                send_encrypted(sock, message_to_send)
                stop_threads.set()
                break

            if stop_threads.is_set(): # Check if stop was signaled by receive_messages or Ctrl+C
                break

            if not message_to_send: # Ignore empty input
                continue

            # Handle /help locally
            if message_to_send.lower() == '/help':
                print("\nAvailable commands:")
                print("  /login <username> <password> - Log in to the server (if not authenticated).")
                print("  /list                       - List currently online users.")
                print("  /quit                       - Disconnect from the server.")
                print("  /help                       - Show this help message.")
                print("Any other text will be sent as a chat message if authenticated.\n")
                continue # Don't send /help to the server

            send_encrypted(sock, message_to_send)

            if message_to_send.lower() == '/quit':
                print("Disconnecting...")
                stop_threads.set()
                break

            # Small delay to allow receive_messages to process server responses (like auth status)
            # This is a bit of a hack; proper state management is better.
            # threading.Event or Condition could be used for more robust synchronization.
            # if not authenticated and message_to_send.lower().startswith("/login"):
            #    time.sleep(0.1) # wait for auth response

    except Exception as e:
        if not stop_threads.is_set(): print(f"Error sending message: {e}")
    finally:
        # sock.shutdown(socket.SHUT_WR) # Signal that we're done sending
        # The receive_messages thread will close the socket fully when server closes connection
        pass


def start_client():
    """
    Starts the TCP chat client.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")
            print("Type your messages and press Enter. Type '/quit' to exit.")

            # Start a thread for receiving messages
            receive_thread = threading.Thread(target=receive_messages, args=(s,), daemon=True)
            receive_thread.start()

            # Use the main thread for sending messages
            send_messages(s)

        except ConnectionRefusedError:
            print(f"Connection refused. Ensure the server is running at {HOST}:{PORT}.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Client shutting down.")
            # The socket should be closed by receive_messages or if connect fails
            # If send_messages loop exits (e.g. /quit), we wait for receive_thread to finish if needed
            if receive_thread.is_alive():
                 # A more graceful shutdown might involve signaling receive_thread
                 # For now, if server closes connection, receive_thread will exit.
                 # If client types /quit, send_messages exits, but receive_thread keeps running
                 # until server connection is also closed or an error occurs.
                 # This is a simplification; proper shutdown needs careful handling.
                 pass
            if s.fileno() != -1: # Check if socket is still open
                s.close()


if __name__ == "__main__":
    start_client()
