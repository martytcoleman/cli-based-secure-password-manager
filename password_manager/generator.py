"""random password generator - uses secrets, never random, so the output can't be predicted"""

import secrets
import string

MIN_LENGTH = 12       # ~75 bits, same floor as the master password
DEFAULT_LENGTH = 20   # ~125 bits, and i never have to type it anyway
SYMBOLS = "!@#$%^&*-_=+?"  # skipped quotes and backslashes, some sites choke on them
CHARACTER_SETS = (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS)
ALPHABET = "".join(CHARACTER_SETS)


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    """random password with at least one of each character type.
    regenerates until that's true instead of forcing characters in, so nothing about it is predictable"""
    if length < MIN_LENGTH:
        raise ValueError(f"generated passwords need at least {MIN_LENGTH} characters")
    while True:
        password = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(c in chars for c in password) for chars in CHARACTER_SETS):
            return password
