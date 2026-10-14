"""Entry manipulation and password generation for the decrypted vault."""

from __future__ import annotations

import secrets
import string
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_password(length: int = 20, include_numbers: bool = True, include_symbols: bool = True) -> str:
    """Generate a password using cryptographically secure randomness."""
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256 characters.")
    pools = [string.ascii_lowercase, string.ascii_uppercase]
    if include_numbers:
        pools.append(string.digits)
    if include_symbols:
        pools.append("!@#$%^&*()-_=+[]{}:,.?")
    alphabet = "".join(pools)
    required = [secrets.choice(pool) for pool in pools]
    generated = required + [secrets.choice(alphabet) for _ in range(length - len(required))]
    secrets.SystemRandom().shuffle(generated)
    return "".join(generated)


def password_strength(password: str) -> tuple[str, int]:
    """Return a local, intentionally simple strength label and 0-100 score."""
    if not password:
        return "Empty", 0
    categories = sum((any(c.islower() for c in password), any(c.isupper() for c in password), any(c.isdigit() for c in password), any(not c.isalnum() for c in password)))
    score = min(100, len(password) * 4 + categories * 10)
    if score < 40:
        return "Weak", score
    if score < 70:
        return "Fair", score
    if score < 90:
        return "Strong", score
    return "Very strong", score


def _require_entry_fields(site: str, username: str, password: str, notes: str) -> None:
    if not site.strip():
        raise ValueError("Site or application name is required.")
    if not isinstance(username, str) or not isinstance(password, str) or not isinstance(notes, str):
        raise ValueError("Entry fields must be text.")


def add_entry(vault: dict[str, Any], site: str, username: str, password: str, notes: str = "") -> dict[str, Any]:
    _require_entry_fields(site, username, password, notes)
    timestamp = utc_now()
    entry = {"id": str(uuid.uuid4()), "site": site.strip(), "username": username, "password": password, "notes": notes, "created_at": timestamp, "updated_at": timestamp}
    vault["entries"].append(entry)
    return entry


def get_entry(vault: dict[str, Any], entry_id: str) -> dict[str, Any]:
    for entry in vault["entries"]:
        if entry.get("id") == entry_id:
            return entry
    raise KeyError("Entry not found.")


def update_entry(vault: dict[str, Any], entry_id: str, site: str, username: str, password: str, notes: str = "") -> dict[str, Any]:
    _require_entry_fields(site, username, password, notes)
    entry = get_entry(vault, entry_id)
    entry.update({"site": site.strip(), "username": username, "password": password, "notes": notes, "updated_at": utc_now()})
    return entry


def delete_entry(vault: dict[str, Any], entry_id: str) -> None:
    entries = vault["entries"]
    for index, entry in enumerate(entries):
        if entry.get("id") == entry_id:
            del entries[index]
            return
    raise KeyError("Entry not found.")


def search_entries(vault: dict[str, Any], query: str) -> list[dict[str, Any]]:
    needle = query.strip().casefold()
    entries: Iterable[dict[str, Any]] = vault["entries"]
    if needle:
        entries = (entry for entry in entries if needle in entry.get("site", "").casefold() or needle in entry.get("username", "").casefold() or needle in entry.get("notes", "").casefold())
    return sorted((deepcopy(entry) for entry in entries), key=lambda entry: (entry.get("site", "").casefold(), entry.get("username", "").casefold()))
