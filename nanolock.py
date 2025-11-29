import base64
import os
import getpass
import sys
from cryptography.fernet import Fernet, InvalidToken
from argon2.low_level import hash_secret_raw, Type


def get_key(password, salt):
    """Derive a Fernet key using Argon2id"""
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=4,          # 4 passes over memory
        memory_cost=1048576,  # 1 GiB – adjust down to 524288 (512 MiB) 262144 (256 MiB) or even to 65536 (64 MiB) on weak devices
        parallelism=4,        # use 4 cores
        hash_len=32,
        type=Type.ID,         # Argon2id = most secure variant
    )
    return base64.urlsafe_b64encode(key)


def main():
    print(r"""
 _   _                   _               _    
| \ | | __ _ _ __   ___ | |    ___   ___| | __
|  \| |/ _` | '_ \ / _ \| |   / _ \ / __| |/ /
| |\  | (_| | | | | (_) | |__| (_) | (__|   < 
|_| \_|\__,_|_| |_|\___/|_____\___/ \___|_|\_\                                               
    """)
    mode = input("Select -> (E)ncrypt or (D)ecrypt: ").strip().upper()

    if mode not in ["E", "D"]:
        print("Invalid mode.")
        return

    # Ask password AFTER mode so we can confirm only on encryption
    password = getpass.getpass("Enter password: ").encode()
    if not password:
        print("Password cannot be empty.")
        return

    if mode == "E":
        confirm = getpass.getpass("Confirm password: ").encode()
        if password != confirm:
            print("Passwords do not match!")
            return

        text = input("Enter text to encrypt: ").encode()

        salt = os.urandom(16)
        key = get_key(password, salt)
        token = Fernet(key).encrypt(text)

        result = base64.urlsafe_b64encode(salt + token)
        print("\nENCRYPTED OUTPUT:")
        print(result.decode())

    elif mode == "D":
        encrypted_input = input("Paste encrypted text: ").strip()

        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_input)
            if len(decoded_data) <= 16:
                raise ValueError("Invalid data")

            salt, token = decoded_data[:16], decoded_data[16:]
            key = get_key(password, salt)

            original_text = Fernet(key).decrypt(token).decode()
            print("\nDECRYPTED TEXT:")
            print(original_text)

        except InvalidToken:
            print("\nERROR: Wrong password or corrupted data.")
        except Exception as e:
            print(f"\nERROR: Invalid input – {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye!")
        sys.exit(0)
