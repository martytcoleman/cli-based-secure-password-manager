import random
import string

import pytest

from generator import ALPHABET, DEFAULT_LENGTH, MIN_LENGTH, SYMBOLS, generate_password


# default should be long enough that guessing is hopeless (~125 bits)
def test_default_length():
    assert len(generate_password()) == DEFAULT_LENGTH


# every password needs lower, upper, digit and symbol or some sites will reject it
def test_always_has_every_character_type():
    for _ in range(200):
        pw = generate_password()
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


# nothing outside the allowed characters sneaks in
def test_only_uses_allowed_characters():
    assert set(generate_password(100)) <= set(ALPHABET)


# a thousand passwords and no repeats, if it's really random
def test_no_repeats():
    assert len({generate_password() for _ in range(1000)}) == 1000


# seeding random makes random repeat itself. if my generator used it, these would match
def test_not_using_the_random_module():
    random.seed(55)
    a = generate_password()
    random.seed(55)
    b = generate_password()
    assert a != b


# the minimum itself is allowed, anything under it is too weak
def test_minimum_length():
    assert len(generate_password(MIN_LENGTH)) == MIN_LENGTH
    with pytest.raises(ValueError):
        generate_password(MIN_LENGTH - 1)
