import json
import os
import stat

import pytest

from auth import login, register
from storage import StorageCorrupted, load_record, save_record, vault_exists

RECORD = {
    "salt_key": "bM5rHp1c1ZTmK58lYBxIrA==",
    "salt_verifier": "5ZTYMlAhWaiPhUFaa8SWtg==",
    "iterations": 2000000,
    "verifier": "IVk2X2mG9cdyF4EnRpD27WroUDq76kGEBeEeied2vJs=",
    "vault": "gAAAAABfake",
}


@pytest.fixture
def path(tmp_path):
    # pytest hands every test its own empty temp folder, so my real vault never gets touched
    return str(tmp_path / "storage.json")


# save then load should give back exactly what went in
def test_save_then_load(path):
    save_record(RECORD, path)
    assert load_record(path) == RECORD


# no file yet means first run, which is how the app knows to register instead of log in
def test_vault_exists(path):
    assert not vault_exists(path)
    save_record(RECORD, path)
    assert vault_exists(path)


# only my user should be able to read or write the vault file
def test_file_is_owner_only(path):
    save_record(RECORD, path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# saving over an old vault replaces it cleanly and doesn't leave a temp file lying around
def test_overwrite_leaves_no_tmp_file(path):
    save_record(RECORD, path)
    save_record({**RECORD, "vault": "gAAAAABnewer"}, path)
    assert load_record(path)["vault"] == "gAAAAABnewer"
    assert not os.path.exists(path + ".tmp")


# fake a crash halfway through saving - the old vault has to survive untouched
def test_crash_mid_save_keeps_old_vault(path, monkeypatch):
    save_record(RECORD, path)

    def disk_dies(*args):
        raise OSError("disk died")

    monkeypatch.setattr(os, "fsync", disk_dies)
    with pytest.raises(OSError):
        save_record({**RECORD, "vault": "gAAAAABhalfwritten"}, path)
    assert load_record(path) == RECORD


# garbage in the file should give a clear error, not some weird crash later
def test_garbage_file_is_flagged(path):
    with open(path, "w") as f:
        f.write("this is not json")
    with pytest.raises(StorageCorrupted):
        load_record(path)


# valid json but missing the vault fields is just as broken
def test_missing_fields_is_flagged(path):
    with open(path, "w") as f:
        json.dump({"vault": "gAAAAABfake"}, f)
    with pytest.raises(StorageCorrupted):
        load_record(path)


# the whole loop for real: register, save to disk, load it back, log in. and no plaintext on disk
def test_register_save_load_login(path):
    record, key = register("correct horse battery")
    save_record(record, path)
    with open(path) as f:
        assert "correct horse battery" not in f.read()
    entries, login_key = login("correct horse battery", load_record(path))
    assert entries == {}
    assert login_key == key
