import copy

import pytest

from auth import VaultTampered, WrongPassword, _to_text, login, register
from crypto_utils import generate_salt, make_verifier

PW = "correct horse battery"


@pytest.fixture(scope="module")
def registered():
    # register is slow on purpose (2m rounds) so i only do it once for this file
    return register(PW)


# under 12 characters shouldn't even be allowed to make a vault
def test_short_password_rejected():
    with pytest.raises(ValueError):
        register("short")


# the key must only live in memory, never in what gets saved
def test_key_never_ends_up_in_the_record(registered):
    record, key = registered
    assert key.decode() not in record.values()


# logging in should rebuild the exact key from register, and the new vault starts empty
def test_login_gives_back_the_same_key(registered):
    record, key = registered
    entries, login_key = login(PW, record)
    assert entries == {}
    assert login_key == key


# wrong password gets stopped at the verifier
def test_wrong_password(registered):
    record, _ = registered
    with pytest.raises(WrongPassword):
        login("wrong horse battery", record)


# right password but someone edited the vault - should be flagged as tampering, not a typo
def test_edited_vault_is_caught(registered):
    record = copy.deepcopy(registered[0])
    v = record["vault"]
    i = len(v) // 2
    record["vault"] = v[:i] + ("A" if v[i] != "A" else "B") + v[i + 1:]
    with pytest.raises(VaultTampered):
        login(PW, record)


# attacker drops in a verifier for their own password. gets past the check, not the lock
def test_swapped_in_verifier_still_cant_open_vault(registered):
    record = copy.deepcopy(registered[0])
    salt = generate_salt()
    record["salt_verifier"] = _to_text(salt)
    record["verifier"] = make_verifier("attacker-password", salt).decode()
    with pytest.raises(VaultTampered):
        login("attacker-password", record)


# setting iterations to 1 doesn't make my vault cheaper to crack, it just breaks login
def test_lowering_iterations_doesnt_help(registered):
    record = copy.deepcopy(registered[0])
    record["iterations"] = 1
    with pytest.raises(WrongPassword):
        login(PW, record)
