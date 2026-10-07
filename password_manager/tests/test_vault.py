import pytest

from auth import login, register
from crypto_utils import encrypt_vault
from storage import load_record, save_record
from vault import (
    EntryExists,
    EntryNotFound,
    add_entry,
    delete_entry,
    edit_entry,
    get_password,
    search,
)


@pytest.fixture
def entries():
    # a small vault to poke at. each test gets a fresh copy
    e = {}
    add_entry(e, "github.com", "marty", "s3cret!")
    add_entry(e, "github.com", "marty-work", "w0rk!")
    add_entry(e, "chase.com", "marty", "b4nk!")
    return e


# the basic thing: put a password in, get it back out
def test_add_then_get(entries):
    assert get_password(entries, "chase.com", "marty") == "b4nk!"


# messy capitals and spaces should still find the same site
def test_service_names_are_normalized(entries):
    assert get_password(entries, "  GitHub.COM ", "marty") == "s3cret!"


# two accounts on one site live side by side under the same tab
def test_two_accounts_same_site(entries):
    assert entries["github.com"] == {"marty": "s3cret!", "marty-work": "w0rk!"}


# adding the same account twice shouldn't quietly overwrite my old password
def test_duplicate_add_is_refused(entries):
    with pytest.raises(EntryExists):
        add_entry(entries, "github.com", "marty", "oops")
    assert get_password(entries, "github.com", "marty") == "s3cret!"


# blank fields are almost certainly a mistake
def test_empty_password_is_refused(entries):
    with pytest.raises(ValueError):
        add_entry(entries, "gitlab.com", "marty", "")


# asking for something that isn't there gives a clear error
def test_missing_entry(entries):
    with pytest.raises(EntryNotFound):
        get_password(entries, "netflix.com", "marty")


# changing just the password keeps the username
def test_edit_password_only(entries):
    edit_entry(entries, "chase.com", "marty", new_password="n3w!")
    assert get_password(entries, "chase.com", "marty") == "n3w!"


# changing just the username keeps the password
def test_edit_username_only(entries):
    edit_entry(entries, "chase.com", "marty", new_username="marty.c")
    assert get_password(entries, "chase.com", "marty.c") == "b4nk!"
    with pytest.raises(EntryNotFound):
        get_password(entries, "chase.com", "marty")


# renaming onto an account that already exists would wipe it out, so refuse
def test_edit_cant_clobber_another_account(entries):
    with pytest.raises(EntryExists):
        edit_entry(entries, "github.com", "marty", new_username="marty-work")


# deleting the last account on a site removes the site too, no empty tabs left over
def test_delete_cleans_up_empty_site(entries):
    delete_entry(entries, "chase.com", "marty")
    assert "chase.com" not in entries


# can't delete something that was never there
def test_delete_missing(entries):
    with pytest.raises(EntryNotFound):
        delete_entry(entries, "netflix.com", "marty")


# search matches part of the site name and never hands back passwords
def test_search_shows_no_passwords(entries):
    results = search(entries, "git")
    assert results == [("github.com", "marty"), ("github.com", "marty-work")]
    assert "s3cret!" not in str(results)


# an empty search lists everything, sorted
def test_empty_search_lists_all(entries):
    assert search(entries) == [
        ("chase.com", "marty"),
        ("github.com", "marty"),
        ("github.com", "marty-work"),
    ]


# the real flow main.py will use: change entries, re-lock, save, log back in, still there
def test_changes_survive_save_and_login(tmp_path):
    path = str(tmp_path / "storage.json")
    record, key = register("correct horse battery")
    entries, _ = login("correct horse battery", record)

    add_entry(entries, "github.com", "marty", "s3cret!")
    record["vault"] = encrypt_vault(entries, key)
    save_record(record, path)

    entries_again, _ = login("correct horse battery", load_record(path))
    assert get_password(entries_again, "github.com", "marty") == "s3cret!"
