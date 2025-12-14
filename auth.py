# auth.py
import bcrypt
import os
import re
import secrets
from pathlib import Path

# ----- Configuration -----
BASE_DIR = Path(r"C:\Users\Master Jaden\OneDrive\Desktop\1510 CW2")
BASE_DIR.mkdir(parents=True, exist_ok=True)

USER_DATA_FILE = BASE_DIR / "users.txt"

print(f"DEBUG: users file path -> {USER_DATA_FILE}")

# ----- Core security functions -----
def hash_password(plain_text_password: str) -> str:
    pw_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pw_bytes, salt)
    return hashed.decode("utf-8")

def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_text_password.encode("utf-8"),
        
        hashed_password.encode("utf-8")
    )

# ----- File / user helpers -----
def user_exists(username: str) -> bool:
    if not USER_DATA_FILE.exists():
        return False

    with USER_DATA_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            if line.split(",")[0] == username:
                return True
    return False

def register_user(username: str, password: str, role: str = "user") -> bool:
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False

    hashed = hash_password(password)

    with USER_DATA_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{username},{hashed},{role}\n")

    print(f"Success: User '{username}' registered successfully!")
    return True

def login_user(username: str, password: str) -> bool:
    if not USER_DATA_FILE.exists():
        print("Error: No users registered yet.")
        return False

    with USER_DATA_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split(",")
            if parts[0] == username:
                if verify_password(password, parts[1]):
                    print(f"Success: Welcome, {username}!")
                    return True
                else:
                    print("Error: Invalid password.")
                    return False

    print("Error: Username not found.")
    return False

# ----- Validation helpers -----
def validate_username(username: str) -> tuple:
    if not (3 <= len(username) <= 20):
        return False, "Username must be 3–20 characters."
    if not re.match(r'^[A-Za-z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, '_' or '-'."
    return True, ""

def validate_password(password: str) -> tuple:
    if not (6 <= len(password) <= 50):
        return False, "Password must be between 6 and 50 characters."
    if not re.search(r'[a-z]', password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r'[A-Z]', password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r'\d', password):
        return False, "Password must include at least one digit."
    return True, ""

# ----- Session token -----
def create_session(username: str) -> str:
    return secrets.token_hex(16)

# ----- Menu -----
def display_menu():
    print("\n" + "=" * 50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("=" * 50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 50)

def main():
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            valid, msg = validate_username(username)
            if not valid:
                print("Error:", msg)
                continue

            password = input("Enter a password: ").strip()
            valid, msg = validate_password(password)
            if not valid:
                print("Error:", msg)
                continue

            confirm = input("Confirm password: ").strip()
            if password != confirm:
                print("Error: Passwords do not match.")
                continue

            register_user(username, password)

        elif choice == '2':
            print("\n--- USER LOGIN ---")
            username = input("Username: ").strip()
            password = input("Password: ").strip()

            if login_user(username, password):
                token = create_session(username)
                print(f"(session token: {token})")
                input("Press Enter to continue...")

        elif choice == '3':
            print("Goodbye.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
