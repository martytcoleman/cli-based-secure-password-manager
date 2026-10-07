import base64

import pytest
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto_utils import (
    ITERATIONS,
    check_verifier,
    decrypt_vault,
    derive_key,
    encrypt_vault,
    generate_salt,
    make_verifier,
)

VAULT = {"github.com": {"username": "marty", "password": "s3cret!"}}


def flip_middle_char(token):
    i = len(token) // 2
    return token[:i] + ("A" if token[i] != "A" else "B") + token[i + 1:]


# login only works if the same password + salt rebuilds the exact same key
def test_same_password_and_salt_give_same_key():
    salt = generate_salt()
    assert derive_key("hunter2", salt) == derive_key("hunter2", salt)


# the whole point of a salt - same password, different salt, totally different key
def test_different_salt_changes_the_key():
    assert derive_key("hunter2", generate_salt()) != derive_key("hunter2", generate_salt())


# i swapped derive_key over to hashlib to match the spec, this proves nothing changed
def test_hashlib_matches_old_pbkdf2hmac():
    salt = generate_salt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    assert derive_key("hunter2", salt) == base64.urlsafe_b64encode(kdf.derive(b"hunter2"))


# lock it, unlock it, get the exact same vault back
def test_round_trip():
    key = derive_key("hunter2", generate_salt())
    assert decrypt_vault(encrypt_vault(VAULT, key), key) == VAULT


# new random iv every time, so nobody can tell if the vault changed between saves
def test_same_vault_encrypts_differently_each_time():
    key = derive_key("hunter2", generate_salt())
    assert encrypt_vault(VAULT, key) != encrypt_vault(VAULT, key)


# wrong password means wrong key, and fernet should flat out refuse
def test_wrong_key_cant_decrypt():
    salt = generate_salt()
    token = encrypt_vault(VAULT, derive_key("hunter2", salt))
    with pytest.raises(InvalidToken):
        decrypt_vault(token, derive_key("hunter3", salt))


# change one character and the hmac seal should catch it
def test_tampered_token_is_rejected():
    key = derive_key("hunter2", generate_salt())
    with pytest.raises(InvalidToken):
        decrypt_vault(flip_middle_char(encrypt_vault(VAULT, key)), key)


# the login check lets the right password in and keeps the wrong one out
def test_verifier_only_accepts_right_password():
    salt = generate_salt()
    stored = make_verifier("hunter2", salt)
    assert check_verifier("hunter2", salt, stored)
    assert not check_verifier("hunter3", salt, stored)


# different salts mean the saved verifier can never be used as the key
def test_verifier_is_not_the_key():
    assert make_verifier("hunter2", generate_salt()) != derive_key("hunter2", generate_salt())
