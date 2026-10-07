"""the command-line app - register or log in, then a menu for the vault"""

import sys
from getpass import getpass

import ui
from auth import MIN_PASSWORD_LENGTH, VaultTampered, WrongPassword, login, register
from crypto_utils import encrypt_vault
from generator import DEFAULT_LENGTH, MIN_LENGTH, generate_password
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


def quit_with_error(msg):
    ui.error(msg)
    sys.exit(1)


def first_time_setup():
    print("no vault yet, let's make one.")
    print(f"pick a master password, at least {MIN_PASSWORD_LENGTH} characters.")
    ui.warn("there's no way to recover it if you forget it.")
    print()
    while True:
        password = getpass("master password: ")
        if getpass("type it again: ") != password:
            ui.error("those didn't match, try again.")
            print()
            continue
        try:
            record, key = register(password)
        except ValueError as e:
            ui.error(str(e))
            print()
            continue
        save_record(record)
        ui.success("vault created.")
        return record, {}, key


def unlock():
    try:
        record = load_record()
    except StorageCorrupted as e:
        quit_with_error(f"can't read the vault: {e}")

    for _ in range(MAX_LOGIN_ATTEMPTS):
        try:
            entries, key = login(getpass("master password: "), record)
            ui.success("unlocked.")
            return record, entries, key
        except WrongPassword:
            ui.error("wrong password.")
        except VaultTampered:
            # leave the file exactly as it is so nothing gets overwritten
            quit_with_error("password is right but the vault won't decrypt - storage.json was changed or corrupted.")
    quit_with_error("too many wrong attempts.")


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
    ui.accounts(matches, numbered=True)
    choice = input("which one? ")
    if not choice.isdigit() or not 1 <= int(choice) <= len(matches):
        raise ValueError("pick one of the numbers")
    return matches[int(choice) - 1]


def new_generated_password():
    length = input(f"length (blank for {DEFAULT_LENGTH}, min {MIN_LENGTH}): ").strip()
    if length and not length.isdigit():
        raise ValueError("length has to be a number")
    return generate_password(int(length) if length else DEFAULT_LENGTH)


def warn_if_short(password):
    """typed passwords aren't blocked (old accounts, sites with limits) but i still get a nudge"""
    if len(password) < MIN_LENGTH:
        ui.warn(f"heads up: that's only {len(password)} characters. a generated one would be much stronger.")


def main():
    record, entries, key = unlock() if vault_exists() else first_time_setup()

    while True:
        ui.menu()
        choice = input("> ").strip().lower()
        try:
            if choice == "1":
                service, username = input("site: "), input("username: ")
                typed = getpass("password (hidden, blank to generate one): ")
                password = typed or new_generated_password()
                add_entry(entries, service, username, password)
                save(record, entries, key)
                ui.success("saved.")
                if not typed:
                    ui.secret("generated password", password)  # shown once so i can paste it into the site
                else:
                    warn_if_short(typed)

            elif choice == "2":
                ui.secret("password", get_password(entries, *pick_account(entries)))

            elif choice == "3":
                ui.accounts(search(entries, input("search sites for: ")))

            elif choice == "4":
                service, username = pick_account(entries)
                new_username = input("new username (blank keeps it): ")
                new_password = getpass("new password (hidden, blank keeps it, g to generate): ")
                generated = new_password == "g"
                if generated:
                    new_password = new_generated_password()
                edit_entry(entries, service, username, new_username, new_password)
                save(record, entries, key)
                ui.success("updated.")
                if generated:
                    ui.secret("generated password", new_password)
                elif new_password:
                    warn_if_short(new_password)

            elif choice == "5":
                service, username = pick_account(entries)
                if input(ui.style(f"delete {username} @ {service}? type yes: ", ui.YELLOW)) == "yes":
                    delete_entry(entries, service, username)
                    save(record, entries, key)
                    ui.success("deleted.")

            elif choice == "6":
                ui.accounts(search(entries))

            elif choice == "q":
                break

            else:
                ui.error("pick one of the options.")

        except (EntryExists, EntryNotFound, ValueError) as e:
            ui.error(str(e))

    print("locked. bye.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nlocked. bye.")  # ctrl+c / ctrl+d shouldn't dump a scary traceback
