"""saving and loading storage.json - the only part of the app that touches the disk"""

import json
import os

# keep storage.json right next to the code, like the spec's folder layout
STORAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage.json")
REQUIRED_FIELDS = {"salt_key", "salt_verifier", "iterations", "verifier", "vault"}


class StorageCorrupted(Exception):
    """storage.json exists but isn't a vault i can read"""


def vault_exists(path: str = STORAGE_PATH) -> bool:
    return os.path.exists(path)


def load_record(path: str = STORAGE_PATH) -> dict:
    """read storage.json back into the record that auth.login expects"""
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
    except json.JSONDecodeError:
        raise StorageCorrupted("storage.json isn't valid json") from None
    if not isinstance(record, dict) or not REQUIRED_FIELDS <= record.keys():
        raise StorageCorrupted("storage.json is missing vault fields")
    return record


def save_record(record: dict, path: str = STORAGE_PATH) -> None:
    """write to a temp file first, then swap it in, so a crash mid-save can't wreck the vault"""
    tmp = path + ".tmp"
    # 0o600 = only my user can read/write. set at creation so it's never readable by others, even briefly
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
        f.flush()
        os.fsync(f.fileno())  # make sure it actually hit the disk, not just the os's memory
    os.replace(tmp, path)  # atomic swap: storage.json is always the full old or the full new version
