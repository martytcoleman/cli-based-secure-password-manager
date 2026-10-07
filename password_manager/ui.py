"""a simple color pass for the terminal. all styling lives here, main.py just says what to show"""

import os
import sys

# no colors if output is piped to a file or the user set NO_COLOR
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

GREEN, YELLOW, RED, CYAN, BOLD = "32", "33", "31", "36", "1"


def style(text, *codes):
    if not USE_COLOR:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def success(msg):
    print(style(msg, GREEN))


def warn(msg):
    print(style(msg, YELLOW))


def error(msg):
    print(style(msg, RED))


def secret(label, value):
    """passwords stand out so it's obvious something sensitive is on screen"""
    print(f"{label}: {style(value, BOLD, YELLOW)}")


def menu():
    items = [("1", "add"), ("2", "get password"), ("3", "search"),
             ("4", "edit"), ("5", "delete"), ("6", "list all"), ("q", "quit")]
    print()
    print("  ".join(f"{style(key, BOLD, CYAN)}) {label}" for key, label in items))


def accounts(matches, numbered=False):
    if not matches:
        print("nothing found.")
    for n, (service, username) in enumerate(matches, start=1):
        number = f"{style(str(n), CYAN)}) " if numbered else ""
        print(f"  {number}{service:25} {username}")
