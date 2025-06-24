import json
from werkzeug.security import check_password_hash, generate_password_hash

USERS_FILE = 'data/users.json'
users_data = {}

def load_users():
    """Loads user data from the JSON file."""
    global users_data
    try:
        with open(USERS_FILE, 'r') as f:
            users_data = json.load(f)
    except FileNotFoundError:
        print(f"Warning: Users file '{USERS_FILE}' not found. No users loaded.")
        users_data = {}
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{USERS_FILE}'.")
        users_data = {}

def verify_user(username, password):
    """Verifies user credentials."""
    if not users_data:
        load_users() # Attempt to load if not already loaded

    user = users_data.get(username)
    if user and user.get('password_hash') == password:
        return True
    return False

def add_user(username, password):
    """Adds a new user to the store (in memory and attempts to save to file)."""
    if not users_data:
        load_users()

    if username in users_data:
        print(f"User {username} already exists.")
        return False

    users_data[username] = {'password_hash': generate_password_hash(password)}
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users_data, f, indent=2)
        print(f"User {username} added and saved.")
        return True
    except IOError:
        print(f"Error: Could not write to users file '{USERS_FILE}'. User {username} added in memory only.")
        return False # Or True, depending on desired behavior if save fails

# Load users when the module is imported
load_users()

if __name__ == '__main__':
    # Example usage and a way to add users if running this script directly
    print("Current users:", users_data)
    # To add a new user:
    # new_username = "newuser"
    # new_password = "securepassword"
    # if add_user(new_username, new_password):
    #     print(f"User {new_username} added.")
    # else:
    #     print(f"Failed to add user {new_username}.")

    # Test verification
    # print("Verify 'testuser' with 'password123':", verify_user("testuser", "password123"))
    # print("Verify 'testuser' with 'wrongpassword':", verify_user("testuser", "wrongpassword"))
    # print("Verify 'nonexistentuser' with 'password123':", verify_user("nonexistentuser", "password123"))
    pass
