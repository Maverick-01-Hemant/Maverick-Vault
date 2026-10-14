"""Cryptographic storage for the local password vault.

The on-disk format is exactly: 16-byte salt || 12-byte nonce || AES-GCM data.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65_536  # KiB (64 MiB)
ARGON2_PARALLELISM = 4


class VaultError(Exception):
    """Base class for vault errors that are safe to show to a user."""


class InvalidMasterPassword(VaultError):
    """The supplied password cannot authenticate this vault."""


class CorruptVault(VaultError):
    """The vault is malformed or does not contain valid vault data."""


def derive_key(master_password: str, salt: bytes) -> bytearray:
    """Derive a 256-bit AES key with Argon2id.

    The caller owns the returned mutable buffer and should overwrite it when done.
    """
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("A non-empty master password is required.")
    if len(salt) != SALT_BYTES:
        raise ValueError("Vault salt has an invalid length.")
    return bytearray(
        hash_secret_raw(
            secret=master_password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_BYTES,
            type=Type.ID,
        )
    )


def wipe_key(buffer: bytearray | None) -> None:
    """Best-effort overwrite of a mutable derived-key buffer."""
    if buffer is not None:
        buffer[:] = b"\x00" * len(buffer)


def _validate_data(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("entries"), list):
        raise CorruptVault("The vault data is not valid.")
    return data


def _read_parts(path: str | os.PathLike[str]) -> tuple[bytes, bytes, bytes]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise VaultError("The vault file could not be read.") from exc
    if len(raw) <= SALT_BYTES + NONCE_BYTES + 16:  # GCM tag is 16 bytes
        raise CorruptVault("The vault file is too short.")
    return raw[:SALT_BYTES], raw[SALT_BYTES:SALT_BYTES + NONCE_BYTES], raw[SALT_BYTES + NONCE_BYTES:]


def vault_salt(path: str | os.PathLike[str]) -> bytes:
    """Return the non-secret salt from a structurally valid vault file."""
    return _read_parts(path)[0]


def _serialize(data: Mapping[str, Any]) -> bytes:
    _validate_data(data)
    try:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VaultError("Vault data could not be encoded.") from exc


def _atomic_write(path: str | os.PathLike[str], contents: bytes) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent, prefix=".vault-", delete=False) as temp:
            temporary_name = temp.name
            temp.write(contents)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    except OSError as exc:
        raise VaultError("The vault file could not be saved.") from exc
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def unlock_vault_with_key(key: bytes | bytearray, path: str | os.PathLike[str]) -> dict[str, Any]:
    """Decrypt a vault using an already-derived session key."""
    salt, nonce, ciphertext = _read_parts(path)
    if len(key) != KEY_BYTES:
        raise ValueError("Vault key has an invalid length.")
    try:
        plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise InvalidMasterPassword("Incorrect master password or a modified vault file.") from exc
    try:
        return _validate_data(json.loads(plaintext.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptVault("The decrypted vault data is invalid.") from exc


def save_vault_with_key(
    data: Mapping[str, Any], key: bytes | bytearray, path: str | os.PathLike[str], salt: bytes | None = None
) -> None:
    """Encrypt and atomically save vault data using an already-derived key."""
    if len(key) != KEY_BYTES:
        raise ValueError("Vault key has an invalid length.")
    if salt is None:
        salt = _read_parts(path)[0]
    if len(salt) != SALT_BYTES:
        raise ValueError("Vault salt has an invalid length.")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, _serialize(data), None)
    _atomic_write(path, salt + nonce + ciphertext)


def create_vault(master_password: str, path: str | os.PathLike[str]) -> None:
    """Create an empty vault. Refuses to overwrite an existing file."""
    vault_path = Path(path)
    if vault_path.exists():
        raise FileExistsError("A vault already exists at this location.")
    salt = os.urandom(SALT_BYTES)
    key = derive_key(master_password, salt)
    try:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, _serialize({"version": 1, "entries": []}), None)
        _atomic_write(vault_path, salt + nonce + ciphertext)
    finally:
        wipe_key(key)


def unlock_vault(master_password: str, path: str | os.PathLike[str]) -> dict[str, Any]:
    """Unlock and return a decrypted vault dictionary."""
    salt, _, _ = _read_parts(path)
    key = derive_key(master_password, salt)
    try:
        return unlock_vault_with_key(key, path)
    finally:
        wipe_key(key)


def save_vault(data: Mapping[str, Any], master_password: str, path: str | os.PathLike[str]) -> None:
    """Re-encrypt and atomically save data, deriving a transient key from password."""
    salt, _, _ = _read_parts(path)
    key = derive_key(master_password, salt)
    try:
        save_vault_with_key(data, key, path, salt)
    finally:
        wipe_key(key)


def encrypted_backup(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
    """Atomically copy an already-encrypted vault as an encrypted backup."""
    source_path = Path(source)
    raw = source_path.read_bytes()
    if len(raw) <= SALT_BYTES + NONCE_BYTES + 16:
        raise CorruptVault("The backup source is not a valid vault file.")
    _atomic_write(destination, raw)


def change_master_password(data: Mapping[str, Any], new_master_password: str, path: str | os.PathLike[str]) -> None:
    """Save data under a freshly salted key derived from a new master password."""
    salt = os.urandom(SALT_BYTES)
    key = derive_key(new_master_password, salt)
    try:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, _serialize(data), None)
        _atomic_write(path, salt + nonce + ciphertext)
    finally:
        wipe_key(key)


if __name__ == "__main__":
    # A non-sensitive smoke test. It deliberately never prints secret values.
    import shutil

    test_dir = Path(tempfile.mkdtemp(prefix="password-vault-test-"))
    test_path = test_dir / "vault.dat"
    try:
        create_vault("test-master-password", test_path)
        vault = unlock_vault("test-master-password", test_path)
        vault["entries"].append({"id": "test", "site": "example.test", "username": "user", "password": "fake", "notes": "", "created_at": "test", "updated_at": "test"})
        save_vault(vault, "test-master-password", test_path)
        assert unlock_vault("test-master-password", test_path)["entries"][0]["site"] == "example.test"
        print("Crypto self-test passed.")
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)
