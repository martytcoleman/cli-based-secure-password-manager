"""the command-line app - register or log in, then a menu for the vault"""

import sys
from getpass import getpass

from auth import MIN_PASSWORD_LENGTH, VaultTampered, WrongPassword, login, register
from crypto_utils import encrypt_vault
from storage import StorageCorrupted, load_record, save_record, vault_exists
from vault import (
    EntryExists,
    EntryNotFound,
    add_entry,
    delete_entry,
    edit_entry,
    get_password,
    search,
)

MAX_LOGIN_ATTEMPTS = 3

MENU = """
1) add       2) get password    3) search
4) edit      5) delete          6) list all
q) quit"""


def first_time_setup():
    print("no vault yet, let's make one.")
    print(f"pick a master password, at least {MIN_PASSWORD_LENGTH} characters.")
    print("there's no way to recover it if you forget it.\n")
    while True:
        password = getpass("master password: ")
        if getpass("type it again: ") != password:
            print("those didn't match, try again.\n")
            continue
        try:
            record, key = register(password)
        except ValueError as e:
            print(f"{e}\n")
            continue
        save_record(record)
        print("vault created.")
        return record, {}, key


def unlock():
    try:
        record = load_record()
    except StorageCorrupted as e:
        sys.exit(f"can't read the vault: {e}")

    for _ in range(MAX_LOGIN_ATTEMPTS):
        try:
            entries, key = login(getpass("master password: "), record)
            print("unlocked.")
            return record, entries, key
        except WrongPassword:
            print("wrong password.")
        except VaultTampered:
            # leave the file exactly as it is so nothing gets overwritten
            sys.exit("password is right but the vault won't decrypt - storage.json was changed or corrupted.")
    sys.exit("too many wrong attempts.")


def save(record, entries, key):
    record["vault"] = encrypt_vault(entries, key)  # re-lock the whole thing, fresh iv every time
    save_record(record)


def pick_account(entries):
    """list matching accounts by number and let me pick one, so i never have to type a username"""
    matches = search(entries, input("site (blank for all): "))
    if not matches:
        raise EntryNotFound("nothing matches that")
    if len(matches) == 1:
        return matches[0]
    for n, (service, username) in enumerate(matches, start=1):
        print(f"  {n}) {service:25} {username}")
    choice = input("which one? ")
    if not choice.isdigit() or not 1 <= int(choice) <= len(matches):
        raise ValueError("pick one of the numbers")
    return matches[int(choice) - 1]


def show_accounts(matches):
    if not matches:
        print("nothing found.")
    for service, username in matches:
        print(f"  {service:25} {username}")


def main():
    record, entries, key = unlock() if vault_exists() else first_time_setup()

    while True:
        print(MENU)
        choice = input("> ").strip().lower()
        try:
            if choice == "1":
                service, username = input("site: "), input("username: ")
                add_entry(entries, service, username, getpass("password (hidden): "))
                save(record, entries, key)
                print("saved.")

            elif choice == "2":
                print("password:", get_password(entries, *pick_account(entries)))

            elif choice == "3":
                show_accounts(search(entries, input("search sites for: ")))

            elif choice == "4":
                service, username = pick_account(entries)
                new_username = input("new username (blank keeps it): ")
                new_password = getpass("new password (hidden, blank keeps it): ")
                edit_entry(entries, service, username, new_username, new_password)
                save(record, entries, key)
                print("updated.")

            elif choice == "5":
                service, username = pick_account(entries)
                if input(f"delete {username} @ {service}? type yes: ") == "yes":
                    delete_entry(entries, service, username)
                    save(record, entries, key)
                    print("deleted.")

            elif choice == "6":
                show_accounts(search(entries))

            elif choice == "q":
                break

            else:
                print("pick one of the options.")

        except (EntryExists, EntryNotFound, ValueError) as e:
            print(e)

    print("locked. bye.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nlocked. bye.")  # ctrl+c / ctrl+d shouldn't dump a scary traceback
