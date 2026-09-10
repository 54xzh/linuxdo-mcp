"""Command-line helpers for MCP OAuth setup."""

import getpass

from .security import hash_password


def generate_password_hash() -> None:
    password = getpass.getpass("OAuth admin password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    print(hash_password(password))


if __name__ == "__main__":
    generate_password_hash()
