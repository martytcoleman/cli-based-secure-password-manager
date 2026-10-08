# cli-based-secure-password-manager

A command-line password manager I built for COSC 55 (Security and Privacy). Everything is stored locally in one encrypted file, and the only way in is a master password.

## Features

**Required**

- Master password registration and login (salted and hashed with PBKDF2)
- Add, retrieve, search, edit and delete credentials (site, username, password)
- Everything encrypted with Fernet. Nothing is ever written to disk in plaintext
- Credentials only get decrypted in memory while the app is running

**Bonus**

- Random password generator. Leave the password blank when adding (or type `g` when editing) and it makes a 20-character one

**Extra usability stuff**

- Numbered account picker, so you never have to type a username to find an entry
- A short-password warning when you type in a password under 12 characters
- A simple color pass (green = worked, red = error, yellow = careful), kept in its own file

## Setup

Needs Python 3.10+ (I built it on 3.13).

```bash
git clone https://github.com/martytcoleman/cli-based-secure-password-manager.git
cd cli-based-secure-password-manager
python3 -m venv .venv
source .venv/bin/activate
pip install -r password_manager/requirements.txt
```

## Usage

```bash
cd password_manager
python main.py
```

The first run asks you to pick a master password (at least 12 characters, typed twice). After that it asks for the master password and drops you into the menu:

```
1) add  2) get password  3) search  4) edit  5) delete  6) list all  q) quit
```

There is no password recovery. If you forget the master password, the vault is gone. That's the point: nobody else can get in either.

To start over, delete `password_manager/storage.json`.

## Project structure

```
password_manager/
  main.py           # the CLI: setup, login, menu
  auth.py           # register and login
  crypto_utils.py   # salts, key derivation, Fernet encrypt/decrypt, the verifier
  storage.py        # reading and writing storage.json safely
  vault.py          # add / get / edit / delete / search on the unlocked vault
  generator.py      # random password generator
  ui.py             # all the terminal colors
  storage.json      # the encrypted vault (created on first run, gitignored)
  requirements.txt
  tests/            # pytest tests for every module
```

`main.py`, `auth.py`, `crypto_utils.py`, `storage.json` and `requirements.txt` follow the layout from the assignment. I split the rest into their own files so each one has a single job: `storage.py` is the only thing that touches the disk, `vault.py` never sees the key, and `main.py` never deals with crypto directly.

## How it works



### Register (first run)

```
master password + salt_key      -> PBKDF2 -> KEY        (kept in memory only, never saved)
master password + salt_verifier -> PBKDF2 -> VERIFIER   (saved)
empty vault -> Fernet(KEY) -> encrypted token           (saved)
```



### Login

```
1. typed password + salt_verifier -> PBKDF2 -> matches the saved VERIFIER?  no -> "wrong password"
2. typed password + salt_key      -> PBKDF2 -> KEY -> Fernet decrypt -> vault in memory
   (if step 1 passed but this fails, the file was tampered with or corrupted)
```

Every add, edit or delete re-encrypts the whole vault and saves it right away.

### What's in storage.json

```json
{
  "salt_key": "yUW6N8dTfX+ul6Y0/5GU7g==",
  "salt_verifier": "N9ZblmtC4zEE4jDjVkhYuQ==",
  "iterations": 2000000,
  "verifier": "73oi8U8xdSsjTcPb8jV0GmHdJmhTh_l7GKOJBTSeIcg=",
  "vault": "gAAAAABqxm5PzHKSORRumglnqEt0afXP..."
}
```

All of this is fine to be public. The salts, iteration count and verifier don't let you decrypt anything, and the vault is one Fernet token, so even the site names and usernames are hidden. The key itself is never written anywhere. It gets rebuilt from the master password every time you log in.

### Design decisions


| Decision                                         | Why                                                                                                                                               |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| PBKDF2-HMAC-SHA256, 2,000,000 iterations         | Slow on purpose. OWASP's minimum is 600k, but that only took 0.06s on my laptop, so I raised it. One derivation takes about 0.13s now             |
| Random 16-byte salts from `os.urandom`           | Kills precomputed tables and forces an attacker to go after each vault separately                                                                 |
| Two separate salts (key and verifier)            | With one salt, the saved verifier would literally be the key, and anyone with the file could decrypt the vault                                    |
| Whole-vault encryption (one Fernet token)        | Encrypting each entry separately would leak which sites I have accounts on, and an attacker could swap or delete entries without it being noticed |
| Fernet (AES-128-CBC + HMAC-SHA256)               | Handles the IV, padding and tamper check correctly, so I'm not rolling my own crypto                                                              |
| `hmac.compare_digest` for the login check        | Constant-time comparison, so response timing doesn't leak how close a guess was                                                                   |
| Atomic writes (temp file, `fsync`, `os.replace`) | A crash mid-save leaves the old vault intact instead of a half-written file                                                                       |
| File created with `0o600` permissions            | Only my user can read it. Set at creation so there's no window where it's readable by others                                                      |
| `getpass` for every password                     | Nothing secret shows on screen or ends up in shell history                                                                                        |
| `secrets` for the generator, never `random`      | `random` is predictable (same seed, same output). `secrets` uses the OS's secure randomness                                                       |
| Master password: 12+ characters, typed twice     | Length beats complexity rules (NIST guidance), and typing it twice catches typos that would lock me out forever                                   |


The assignment lists `hashlib` for hashing and names PBKDF2HMAC in the security design. I use `hashlib.pbkdf2_hmac`, which is the same algorithm as the `cryptography` library's `PBKDF2HMAC`. One of the tests checks they produce identical keys. The `cryptography` library is only used for Fernet.

## Threat model



### What it protects against

- **Someone stealing storage.json.** They can only guess master passwords offline, and every guess costs 2 million PBKDF2 rounds. The salts mean no precomputed tables and no cracking many vaults at once. The verifier doesn't give them a shortcut either: checking a guess against it costs exactly the same as trying to decrypt the vault.
- **Tampering with the vault.** Fernet's HMAC catches any change to the encrypted data. If the password is right but the vault won't decrypt, the app says the file was changed and exits without saving, so it doesn't overwrite anything.
- **Tampering with the other fields.** The salts, iteration count and verifier aren't covered by Fernet's HMAC, but changing them can only make login fail. Swapping in your own verifier gets you past the password check but not the encryption, and lowering the iteration count doesn't make my existing vault any cheaper to crack. There are tests for both.
- **Other user accounts on the same computer.** The file is `600`.
- **Someone looking over my shoulder.** Passwords are never echoed, and search/list only show site and username.
- **Crashes and power loss mid-save.** Atomic writes.



### What it doesn't protect against

- **A weak master password.** This is the big one. If it's on a common password list, the slow hashing only buys minutes. Everything depends on the master password being long and not guessable.
- **Malware or a keylogger running as me.** It has my permissions, so it can read the file and see what I type.
- **Root/admin**, or someone with my physical disk if disk encryption (FileVault) is off.
- **Secrets in memory.** Python doesn't let me reliably wipe strings from memory, so the key and passwords sit in RAM while the app is open.
- **Passwords I choose to display.** "Get password" prints it, so it stays in the terminal scrollback until I clear it.
- **Metadata.** The Fernet token includes an unencrypted timestamp of the last save, and the token's length gives a rough idea of how big the vault is.
- **Deleting the file.** Someone with access can't read the vault, but they can delete it. Backups are on me.
- **Forgetting the master password.** No recovery, by design.

The 3-attempt login limit is just a convenience. Someone who steals storage.json never uses my app at all, they just run their own guessing program against the file.

## Tests

```bash
cd password_manager
python -m pytest -v
```

47 tests, takes about 5 seconds (the PBKDF2 ones are slow on purpose). Some of the more interesting ones:

- a wrong password, an edited vault, a swapped-in verifier and lowered iterations all get rejected
- a fake disk crash in the middle of a save leaves the old vault untouched
- the saved file is exactly `600` and never contains the master password
- the generator always includes every character type, never repeats, and isn't using `random`

## What I'd add next

- Auto-lock after inactivity (the other optional feature from the assignment)
- Argon2 instead of PBKDF2. It's memory-hard, so GPU guessing gets much more expensive
- Copy to clipboard with an auto-clear, instead of printing passwords
- Changing the master password (new salts, re-encrypt, atomic save)
- Rejecting master passwords from a list of common passwords
- Covering the salts, iterations and verifier with an HMAC too, so tampering with them is reported as tampering instead of a wrong password

