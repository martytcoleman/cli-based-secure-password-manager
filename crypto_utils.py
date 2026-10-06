"""crypto helpers - turning the master password into a key, and locking/unlocking the vault"""

import base64
import json
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16          # 16 bytes = 128 bits, way more than enough that no two vaults share a salt
ITERATIONS = 2_000_000  # owasp's minimum is 600k, but that took only 0.06s here so i bumped it


def generate_salt() -> bytes:
    """grab a fresh random salt from the os's secure random source (not the random module)"""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """stretch the password into a fernet key. slow on purpose so every guess costs an attacker"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # fernet wants 32 bytes: half for aes, half for the hmac seal
        salt=salt,
        iterations=iterations,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    # fernet expects the key as url-safe base64 text. this is just encoding, not encryption
    return base64.urlsafe_b64encode(raw_key)


def encrypt_vault(entries: dict, key: bytes) -> str:
    """turn the whole vault into json and lock it up as a single fernet token"""
    plaintext = json.dumps(entries).encode("utf-8")
    return Fernet(key).encrypt(plaintext).decode("ascii")


def decrypt_vault(token: str, key: bytes) -> dict:
    """unlock the token and rebuild the vault dict.
    throws InvalidToken if the key is wrong or anyone messed with the file"""
    plaintext = Fernet(key).decrypt(token.encode("ascii"))
    return json.loads(plaintext)
