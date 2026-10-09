"""the vault actions - add, get, edit, delete, search. works on the unlocked dict in memory, never touches disk"""


class EntryExists(Exception):
    """that site + username is already in the vault"""


class EntryNotFound(Exception):
    """no entry for that site + username"""


def normalize(service: str) -> str:
    """so "GitHub.com " and "github.com" count as the same site"""
    return service.strip().lower()


def _require(**fields):
    for name, value in fields.items():
        if not value:
            raise ValueError(f"{name} can't be empty")


def check_can_add(entries: dict, service: str, username: str) -> None:
    """complain about a blank or duplicate account before i bother typing a password"""
    service = normalize(service)
    _require(service=service, username=username)
    if username in entries.get(service, {}):
        raise EntryExists(f"{username} @ {service} already exists, edit it instead")


def add_entry(entries: dict, service: str, username: str, password: str) -> None:
    check_can_add(entries, service, username)
    _require(password=password)
    entries.setdefault(normalize(service), {})[username] = password


def get_password(entries: dict, service: str, username: str) -> str:
    service = normalize(service)
    try:
        return entries[service][username]
    except KeyError:
        raise EntryNotFound(f"no entry for {username} @ {service}") from None


def edit_entry(entries: dict, service: str, username: str,
               new_username: str | None = None, new_password: str | None = None) -> None:
    """change the username, the password, or both. anything left blank stays the same"""
    password = get_password(entries, service, username)  # also blows up if it doesn't exist
    service = normalize(service)
    new_username = new_username or username
    new_password = new_password or password
    if new_username != username and new_username in entries[service]:
        raise EntryExists(f"{new_username} @ {service} already exists")
    del entries[service][username]
    entries[service][new_username] = new_password


def delete_entry(entries: dict, service: str, username: str) -> None:
    get_password(entries, service, username)  # raises EntryNotFound if it isn't there
    service = normalize(service)
    del entries[service][username]
    if not entries[service]:
        del entries[service]  # drop the site's tab once its last account is gone


def search(entries: dict, query: str = "") -> list[tuple[str, str]]:
    """(site, username) pairs for every site matching the query. never includes passwords"""
    query = normalize(query)
    matches = []
    for service, accounts in entries.items():
        if query in service:
            for username in accounts:
                matches.append((service, username))
    return sorted(matches)
