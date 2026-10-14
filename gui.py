"""Tkinter interface for the local-only password vault."""

from __future__ import annotations

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

import pyperclip

from vault_crypto import (
    CorruptVault,
    InvalidMasterPassword,
    VaultError,
    change_master_password,
    create_vault,
    derive_key,
    encrypted_backup,
    unlock_vault_with_key,
    vault_salt,
    wipe_key,
)
from vault_manager import add_entry, delete_entry, generate_password, password_strength, search_entries, update_entry

APP_NAME = "Maverick Vault"
AUTOLOCK_MINUTES = 5


def default_vault_path() -> Path:
    app_data = os.environ.get("APPDATA")
    base = Path(app_data) if app_data else Path.home() / "AppData" / "Roaming"
    return base / "PasswordVault" / "vault.dat"


class PasswordVaultApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.minsize(850, 520)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.vault_path = default_vault_path()
        self.data: dict[str, Any] | None = None
        self.key: bytearray | None = None
        self.salt: bytes | None = None
        self.last_activity = 0
        self.autolock_minutes = AUTOLOCK_MINUTES
        self.search_var = tk.StringVar()
        self._setup_style()
        self.root.bind_all("<KeyPress>", self._activity, add=True)
        self.root.bind_all("<Button>", self._activity, add=True)
        self.show_unlock()
        self.root.after(1_000, self._autolock_check)

    def _setup_style(self) -> None:
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#555555")

    def _activity(self, _event: tk.Event | None = None) -> None:
        if self.key is not None:
            self.last_activity = self.root.tk.call("clock", "seconds")

    def _clear_screen(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()

    def _container(self, padding: int = 24) -> ttk.Frame:
        frame = ttk.Frame(self.root, padding=padding)
        frame.pack(fill="both", expand=True)
        return frame

    def show_unlock(self, error: str = "") -> None:
        self._clear_screen()
        outer = self._container()
        outer.columnconfigure(0, weight=1)
        card = ttk.Frame(outer, padding=24)
        card.grid(row=0, column=0, sticky="n", pady=(55, 0))
        ttk.Label(card, text=APP_NAME, style="Title.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        if self.vault_path.exists():
            ttk.Label(card, text="Enter your master password to unlock your local vault.", style="Hint.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 18))
            password = tk.StringVar()
            ttk.Label(card, text="Master password").grid(row=2, column=0, sticky="w")
            field = ttk.Entry(card, textvariable=password, show="•", width=36)
            field.grid(row=3, column=0, sticky="ew", pady=(4, 8))
            ttk.Button(card, text="Unlock", command=lambda: self._unlock(password.get())).grid(row=4, column=0, sticky="w")
            field.bind("<Return>", lambda _event: self._unlock(password.get()))
        else:
            ttk.Label(card, text="Create a new local encrypted vault.", style="Hint.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 18))
            password, confirm = tk.StringVar(), tk.StringVar()
            ttk.Label(card, text="New master password").grid(row=2, column=0, sticky="w")
            first = ttk.Entry(card, textvariable=password, show="•", width=36)
            first.grid(row=3, column=0, sticky="ew", pady=(4, 8))
            ttk.Label(card, text="Confirm master password").grid(row=4, column=0, sticky="w")
            second = ttk.Entry(card, textvariable=confirm, show="•", width=36)
            second.grid(row=5, column=0, sticky="ew", pady=(4, 8))
            ttk.Button(card, text="Create new vault", command=lambda: self._create(password.get(), confirm.get())).grid(row=6, column=0, sticky="w")
            second.bind("<Return>", lambda _event: self._create(password.get(), confirm.get()))
            first.focus_set()
        if error:
            ttk.Label(card, text=error, foreground="#b00020", wraplength=330).grid(row=7, column=0, columnspan=2, sticky="w", pady=(14, 0))

    def _create(self, password: str, confirm: str) -> None:
        if len(password) < 12:
            self.show_unlock("Use a master password of at least 12 characters.")
            return
        if password != confirm:
            self.show_unlock("The master passwords do not match.")
            return
        try:
            create_vault(password, self.vault_path)
            self._unlock(password)
        except (ValueError, VaultError, OSError) as exc:
            self.show_unlock(str(exc))

    def _unlock(self, password: str) -> None:
        if not password:
            self.show_unlock("Enter your master password.")
            return
        key: bytearray | None = None
        try:
            salt = vault_salt(self.vault_path)
            key = derive_key(password, salt)
            data = unlock_vault_with_key(key, self.vault_path)
        except InvalidMasterPassword:
            self.show_unlock("Incorrect master password, or the vault has been modified.")
            return
        except (ValueError, VaultError, OSError) as exc:
            self.show_unlock(str(exc))
            return
        finally:
            # Ownership transfers only after a successful activation below.
            if key is not None and 'data' not in locals():
                wipe_key(key)
        self.key, self.data, self.salt = key, data, salt
        self._activity()
        self.show_main()

    def lock(self, _notice: bool = False) -> None:
        if self.key is not None:
            wipe_key(self.key)
        self.key, self.data, self.salt = None, None, None
        self.show_unlock("Vault locked after inactivity." if _notice else "")

    def _autolock_check(self) -> None:
        if self.key is not None:
            now = int(self.root.tk.call("clock", "seconds"))
            if now - self.last_activity >= self.autolock_minutes * 60:
                self.lock(True)
        self.root.after(1_000, self._autolock_check)

    def close(self) -> None:
        if self.key is not None:
            wipe_key(self.key)
        self.root.destroy()

    def _save(self) -> bool:
        from vault_crypto import save_vault_with_key
        try:
            assert self.data is not None and self.key is not None and self.salt is not None
            save_vault_with_key(self.data, self.key, self.vault_path, self.salt)
            return True
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.root)
            return False

    def show_main(self) -> None:
        self._clear_screen()
        self.search_var = tk.StringVar()
        outer = self._container(16)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)
        header = ttk.Frame(outer)
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Lock", command=self.lock).pack(side="right")
        ttk.Button(header, text="Change master password", command=self.change_password_dialog).pack(side="right", padx=(0, 6))
        ttk.Button(header, text="Backup", command=self.export_backup).pack(side="right", padx=(0, 6))
        ttk.Button(header, text="Import backup", command=self.import_backup).pack(side="right", padx=(0, 6))
        bar = ttk.Frame(outer)
        bar.grid(row=1, column=0, sticky="ew", pady=(16, 8))
        ttk.Label(bar, text="Search").pack(side="left")
        search = ttk.Entry(bar, textvariable=self.search_var, width=42)
        search.pack(side="left", padx=8)
        ttk.Button(bar, text="Add entry", command=lambda: self.open_editor()).pack(side="right")
        self.search_var.trace_add("write", lambda *_args: self.refresh_entries())
        table_box = ttk.Frame(outer)
        table_box.grid(row=2, column=0, sticky="nsew")
        table_box.columnconfigure(0, weight=1)
        table_box.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(table_box, columns=("site", "username"), show="headings", selectmode="browse")
        self.tree.heading("site", text="Site / app")
        self.tree.heading("username", text="Username / email")
        self.tree.column("site", width=300, anchor="w")
        self.tree.column("username", width=430, anchor="w")
        scrollbar = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<Double-1>", lambda _event: self.edit_selected())
        ttk.Button(outer, text="Edit selected entry", command=self.edit_selected).grid(row=3, column=0, sticky="e", pady=(10, 0))
        self.refresh_entries()
        search.focus_set()

    def refresh_entries(self) -> None:
        if not hasattr(self, "tree") or self.data is None:
            return
        selected = self.tree.selection()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for entry in search_entries(self.data, self.search_var.get()):
            self.tree.insert("", "end", iid=entry["id"], values=(entry["site"], entry["username"]))
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected[0])

    def edit_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo(APP_NAME, "Select an entry first.", parent=self.root)
            return
        entry = next((item for item in self.data["entries"] if item["id"] == selected[0]), None) if self.data else None
        if entry:
            self.open_editor(entry)

    def open_editor(self, entry: dict[str, Any] | None = None) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit entry" if entry else "Add entry")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        box = ttk.Frame(dialog, padding=20)
        box.grid(sticky="nsew")
        site = tk.StringVar(value=entry.get("site", "") if entry else "")
        username = tk.StringVar(value=entry.get("username", "") if entry else "")
        password = tk.StringVar(value=entry.get("password", "") if entry else "")
        visible = tk.BooleanVar(value=False)
        strength = tk.StringVar()
        fields = (("Site / app", site), ("Username / email", username))
        for row, (label, variable) in enumerate(fields):
            ttk.Label(box, text=label).grid(row=row * 2, column=0, sticky="w")
            ttk.Entry(box, textvariable=variable, width=52).grid(row=row * 2 + 1, column=0, columnspan=3, sticky="ew", pady=(3, 9))
        ttk.Label(box, text="Password").grid(row=4, column=0, sticky="w")
        password_field = ttk.Entry(box, textvariable=password, show="•", width=38)
        password_field.grid(row=5, column=0, sticky="ew", pady=(3, 4))
        ttk.Checkbutton(box, text="Show", variable=visible, command=lambda: password_field.configure(show="" if visible.get() else "•")).grid(row=5, column=1, padx=6)
        ttk.Button(box, text="Generate", command=lambda: password.set(generate_password())).grid(row=5, column=2, sticky="e")
        ttk.Label(box, textvariable=strength, style="Hint.TLabel").grid(row=6, column=0, columnspan=3, sticky="w", pady=(0, 9))
        ttk.Label(box, text="Notes").grid(row=7, column=0, sticky="w")
        notes = tk.Text(box, width=52, height=5, wrap="word")
        notes.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(3, 12))
        if entry:
            notes.insert("1.0", entry.get("notes", ""))
        def update_strength(*_args: object) -> None:
            label, score = password_strength(password.get())
            strength.set(f"Strength: {label} ({score}/100)")
        password.trace_add("write", update_strength)
        update_strength()
        def save() -> None:
            try:
                assert self.data is not None
                if entry:
                    update_entry(self.data, entry["id"], site.get(), username.get(), password.get(), notes.get("1.0", "end-1c"))
                else:
                    add_entry(self.data, site.get(), username.get(), password.get(), notes.get("1.0", "end-1c"))
                if self._save():
                    dialog.destroy()
                    self.refresh_entries()
            except ValueError as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=dialog)
        controls = ttk.Frame(box)
        controls.grid(row=9, column=0, columnspan=3, sticky="ew")
        ttk.Button(controls, text="Copy username", command=lambda: self.copy_to_clipboard(username.get())).pack(side="left")
        ttk.Button(controls, text="Copy password", command=lambda: self.copy_to_clipboard(password.get())).pack(side="left", padx=6)
        if entry:
            ttk.Button(controls, text="Delete", command=lambda: self.delete_from_dialog(entry["id"], dialog)).pack(side="right")
        ttk.Button(controls, text="Save", command=save).pack(side="right", padx=6)
        ttk.Button(controls, text="Cancel", command=dialog.destroy).pack(side="right")
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.wait_visibility()
        dialog.focus_set()

    def delete_from_dialog(self, entry_id: str, dialog: tk.Toplevel) -> None:
        if not messagebox.askyesno(APP_NAME, "Delete this entry? This cannot be undone.", icon="warning", parent=dialog):
            return
        assert self.data is not None
        delete_entry(self.data, entry_id)
        if self._save():
            dialog.destroy()
            self.refresh_entries()

    def copy_to_clipboard(self, value: str) -> None:
        if not value:
            return
        try:
            pyperclip.copy(value)
        except pyperclip.PyperclipException:
            messagebox.showerror(APP_NAME, "The clipboard is unavailable.", parent=self.root)
            return
        def clear_if_unchanged(copied_value: str = value) -> None:
            try:
                if pyperclip.paste() == copied_value:
                    pyperclip.copy("")
            except pyperclip.PyperclipException:
                pass
        self.root.after(25_000, clear_if_unchanged)

    def export_backup(self) -> None:
        path = filedialog.asksaveasfilename(parent=self.root, title="Save encrypted backup", defaultextension=".dat", filetypes=[("Vault backup", "*.dat"), ("All files", "*.*")])
        if not path:
            return
        try:
            encrypted_backup(self.vault_path, path)
            messagebox.showinfo(APP_NAME, "Encrypted backup saved.", parent=self.root)
        except (OSError, VaultError) as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.root)

    def import_backup(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Select encrypted backup", filetypes=[("Vault backup", "*.dat"), ("All files", "*.*")])
        if not path:
            return
        if not messagebox.askyesno(APP_NAME, "Replace the current vault with this backup?", icon="warning", parent=self.root):
            return
        try:
            # Exports preserve salt/key, so the current unlocked key verifies imports.
            imported = unlock_vault_with_key(self.key or bytearray(), path)
            imported_salt = vault_salt(path)
            encrypted_backup(path, self.vault_path)
            self.data, self.salt = imported, imported_salt
            self.refresh_entries()
            messagebox.showinfo(APP_NAME, "Encrypted backup imported.", parent=self.root)
        except (InvalidMasterPassword, CorruptVault):
            messagebox.showerror(APP_NAME, "This backup does not match the current vault's master password or is invalid.", parent=self.root)
        except (OSError, VaultError, ValueError) as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.root)

    def change_password_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Change master password")
        dialog.transient(self.root)
        dialog.grab_set()
        box = ttk.Frame(dialog, padding=20)
        box.grid()
        old, new, confirm = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for row, (label, variable) in enumerate((("Current password", old), ("New password", new), ("Confirm new password", confirm))):
            ttk.Label(box, text=label).grid(row=row * 2, column=0, sticky="w")
            ttk.Entry(box, textvariable=variable, show="•", width=38).grid(row=row * 2 + 1, column=0, sticky="ew", pady=(3, 8))
        def change() -> None:
            candidate: bytearray | None = None
            try:
                if len(new.get()) < 12:
                    raise ValueError("Use a new master password of at least 12 characters.")
                if new.get() != confirm.get():
                    raise ValueError("The new master passwords do not match.")
                candidate = derive_key(old.get(), vault_salt(self.vault_path))
                unlock_vault_with_key(candidate, self.vault_path)  # authenticate old password
                assert self.data is not None
                change_master_password(self.data, new.get(), self.vault_path)
                new_salt = vault_salt(self.vault_path)
                new_key = derive_key(new.get(), new_salt)
                if self.key is not None:
                    wipe_key(self.key)
                self.key, self.salt = new_key, new_salt
                dialog.destroy()
                messagebox.showinfo(APP_NAME, "Master password changed.", parent=self.root)
            except (ValueError, VaultError, OSError) as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=dialog)
            finally:
                if candidate is not None:
                    wipe_key(candidate)
        ttk.Button(box, text="Cancel", command=dialog.destroy).grid(row=6, column=0, sticky="w")
        ttk.Button(box, text="Change password", command=change).grid(row=6, column=0, sticky="e")

    def run(self) -> None:
        self.root.mainloop()
