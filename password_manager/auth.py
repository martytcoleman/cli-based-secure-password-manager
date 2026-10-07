"""register and login - glues the crypto helpers into the two things a user actually does"""

import base64

from cryptography.fernet import InvalidToken

from crypto_utils import (
    ITERATIONS,
    check_verifier,
    decrypt_vault,
    derive_key,
    encrypt_vault,
    generate_salt,
    make_verifier,
)

MIN_PASSWORD_LENGTH = 12  # nist: length beats "must have a symbol" rules


class WrongPassword(Exception):
    """the master password didn't match the verifier"""


class VaultTampered(Exception):
    """password was right but the vault won't decrypt, so the file was changed or corrupted"""


def _to_text(raw: bytes) -> str:
    """json can't hold raw bytes, so salts get stored as base64 text"""
    return base64.b64encode(raw).decode("ascii")


def _from_text(text: str) -> bytes:
    return base64.b64decode(text)


def register(password: str) -> tuple[dict, bytes]:
    """set up a brand new vault. gives back the record to save and the key to keep in memory"""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"master password needs at least {MIN_PASSWORD_LENGTH} characters")

    salt_key = generate_salt()
    salt_verifier = generate_salt()  # its own salt so the verifier can never double as the key
    key = derive_key(password, salt_key)

    record = {
        "salt_key": _to_text(salt_key),
        "salt_verifier": _to_text(salt_verifier),
        "iterations": ITERATIONS,
        "verifier": make_verifier(password, salt_verifier).decode("ascii"),
        "vault": encrypt_vault({}, key),  # start with an empty vault, already locked
    }
    return record, key


def login(password: str, record: dict) -> tuple[dict, bytes]:
    """check the password first, then unlock the vault. gives back the entries and the key"""
    iterations = record["iterations"]  # use whatever count this vault was created with
    stored = record["verifier"].encode("ascii")

    if not check_verifier(password, _from_text(record["salt_verifier"]), stored, iterations):
        raise WrongPassword

    key = derive_key(password, _from_text(record["salt_key"]), iterations)
    try:
        entries = decrypt_vault(record["vault"], key)
    except InvalidToken:
        # the verifier already said the password is right, so this means the file was messed with
        raise VaultTampered from None
    return entries, key
