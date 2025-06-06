import sys
import os
import json
import secrets
import string
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QCheckBox,
    QPushButton, QSpinBox, QLineEdit, QListWidget, QMessageBox,
    QInputDialog, QDialog, QFormLayout, QComboBox, QGraphicsDropShadowEffect, QFileDialog
)
from PyQt6.QtCore import Qt, QDateTime
from PyQt6.QtGui import QIcon, QColor

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

CONFIG_FILE = "config.json"
DATA_FOLDER = "password_data"
ICONS_FOLDER = "icons"

NEON_RED = "#ff003c"
DARK_BG = "#141218"
PANEL_BG = "#1e1c22"
INPUT_BG = "#26232c"
TEXT_COLOR = "#f6f7f9"
BORDER_COLOR = "#ff003c"
BTN_BG = "#18171c"
BTN_BG_HOVER = "#ff003c"
BTN_TEXT = "#fff"

QSS = f"""
QWidget {{
    background-color: {DARK_BG};
    color: {TEXT_COLOR};
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 15px;
}}
QLabel[headline="true"] {{
    font-size: 30px;
    font-weight: bold;
    color: {NEON_RED};
    letter-spacing: 2px;
    margin-bottom: 10px;
}}
QPushButton {{
    background-color: {BTN_BG};
    color: {BTN_TEXT};
    border: 2px solid {BORDER_COLOR};
    border-radius: 8px;
    min-height: 36px;
    min-width: 100px;
    font-size: 15px;
    font-weight: 600;
    padding: 8px 23px;
}}
QPushButton:hover {{
    background-color: {BTN_BG_HOVER};
    color: {BTN_TEXT};
    border: 2px solid {BTN_BG_HOVER};
}}
QLineEdit, QSpinBox, QComboBox {{
    background: {INPUT_BG};
    color: {TEXT_COLOR};
    border: 1.5px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 15px;
}}
QListWidget {{
    background: {PANEL_BG};
    color: {TEXT_COLOR};
    border-radius: 6px;
    font-size: 15px;
    padding: 7px;
}}
QFormLayout > QLabel {{
    min-width: 80px;
}}
"""

def generate_salt(length=16):
    return secrets.token_bytes(length)

def hash_master_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt(data, key):
    iv = secrets.token_bytes(12)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ct = encryptor.update(data.encode("utf-8")) + encryptor.finalize()
    return iv + encryptor.tag + ct

def decrypt(encrypted_data, key):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ct = encrypted_data[28:]
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

def password_strength(pw):
    length = len(pw)
    upper = any(c.isupper() for c in pw)
    lower = any(c.islower() for c in pw)
    digit = any(c.isdigit() for c in pw)
    sym = any(c in string.punctuation for c in pw)
    score = sum([upper, lower, digit, sym]) + (length >= 12)
    if score >= 5:
        return "Very Strong 🔥"
    elif score == 4:
        return "Strong"
    elif score == 3:
        return "Medium"
    else:
        return "Weak"

for folder in [DATA_FOLDER, ICONS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

class EditPanel(QDialog):
    def __init__(self, parent, key):
        super().__init__(parent)
        self.setWindowTitle("Edit Folders / Files")
        self.setStyleSheet(QSS)
        self.setMinimumSize(470, 350)
        self.key = key
        self.layout = QVBoxLayout(self)
        headline = QLabel("Edit Folders / Files")
        headline.setProperty("headline", True)
        self.layout.addWidget(headline)
        self.folder_list = QListWidget()
        self.folder_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.folder_list.setMaximumHeight(110)
        self.layout.addWidget(QLabel("Folders:"))
        self.layout.addWidget(self.folder_list)
        folder_btns = QHBoxLayout()
        self.add_folder_btn = QPushButton("Add Folder")
        self.add_folder_btn.clicked.connect(self.add_folder)
        self.rename_folder_btn = QPushButton("Rename")
        self.rename_folder_btn.clicked.connect(self.rename_folder)
        self.delete_folder_btn = QPushButton("Delete")
        self.delete_folder_btn.clicked.connect(self.delete_folder)
        folder_btns.addWidget(self.add_folder_btn)
        folder_btns.addWidget(self.rename_folder_btn)
        folder_btns.addWidget(self.delete_folder_btn)
        self.layout.addLayout(folder_btns)
        self.file_list = QListWidget()
        self.layout.addWidget(QLabel("Files in Folder:"))
        self.layout.addWidget(self.file_list)
        file_btns = QHBoxLayout()
        self.add_file_btn = QPushButton("Add File")
        self.add_file_btn.clicked.connect(self.add_file)
        self.rename_file_btn = QPushButton("Rename")
        self.rename_file_btn.clicked.connect(self.rename_file)
        self.delete_file_btn = QPushButton("Delete")
        self.delete_file_btn.clicked.connect(self.delete_file)
        file_btns.addWidget(self.add_file_btn)
        file_btns.addWidget(self.rename_file_btn)
        file_btns.addWidget(self.delete_file_btn)
        self.layout.addLayout(file_btns)
        self.folder_list.currentItemChanged.connect(self.update_files)
        self.refresh_folders()
        # Neon shadow for all edit buttons
        for btn in [self.add_folder_btn, self.rename_folder_btn, self.delete_folder_btn,
                    self.add_file_btn, self.rename_file_btn, self.delete_file_btn]:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(22)
            shadow.setColor(QColor(NEON_RED))
            shadow.setOffset(0, 0)
            btn.setGraphicsEffect(shadow)

    def refresh_folders(self):
        self.folder_list.clear()
        folders = [f for f in os.listdir(DATA_FOLDER) if os.path.isdir(os.path.join(DATA_FOLDER, f))]
        self.folder_list.addItems(sorted(folders))
        self.file_list.clear()

    def update_files(self):
        self.file_list.clear()
        folder = self.get_selected_folder()
        if folder:
            folder_path = os.path.join(DATA_FOLDER, folder)
            files = [f for f in os.listdir(folder_path) if f.endswith(".txt")]
            self.file_list.addItems(sorted(files))

    def get_selected_folder(self):
        item = self.folder_list.currentItem()
        return item.text() if item else None

    def get_selected_file(self):
        item = self.file_list.currentItem()
        return item.text() if item else None

    def add_folder(self):
        name, ok = QInputDialog.getText(self, "Add Folder", "Folder name:")
        if ok and name:
            os.makedirs(os.path.join(DATA_FOLDER, name), exist_ok=True)
            self.refresh_folders()

    def rename_folder(self):
        folder = self.get_selected_folder()
        if not folder:
            return
        new_name, ok = QInputDialog.getText(self, "Rename Folder", "New name:", QLineEdit.EchoMode.Normal, folder)
        if ok and new_name and new_name != folder:
            old_path = os.path.join(DATA_FOLDER, folder)
            new_path = os.path.join(DATA_FOLDER, new_name)
            if os.path.exists(old_path):
                os.rename(old_path, new_path)
            self.refresh_folders()

    def delete_folder(self):
        folder = self.get_selected_folder()
        if not folder:
            return
        confirm = QMessageBox.question(self, "Delete Folder", f"Delete '{folder}' and all its files?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            folder_path = os.path.join(DATA_FOLDER, folder)
            for root, dirs, files in os.walk(folder_path, topdown=False):
                for file in files:
                    os.remove(os.path.join(root, file))
                for directory in dirs:
                    os.rmdir(os.path.join(root, directory))
            os.rmdir(folder_path)
            self.refresh_folders()

    def add_file(self):
        folder = self.get_selected_folder()
        if not folder:
            return
        name, ok = QInputDialog.getText(self, "Add File", "File name (without extension):")
        if ok and name:
            file_path = os.path.join(DATA_FOLDER, folder, f"{name}.txt")
            if not os.path.exists(file_path):
                encrypted_data = encrypt(json.dumps([]), self.key)
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)
                self.update_files()

    def rename_file(self):
        folder = self.get_selected_folder()
        file = self.get_selected_file()
        if not folder or not file:
            return
        new_name, ok = QInputDialog.getText(self, "Rename File", "New name (without extension):", QLineEdit.EchoMode.Normal, file[:-4])
        if ok and new_name and new_name + ".txt" != file:
            folder_path = os.path.join(DATA_FOLDER, folder)
            old_path = os.path.join(folder_path, file)
            new_path = os.path.join(folder_path, f"{new_name}.txt")
            if os.path.exists(old_path):
                os.rename(old_path, new_path)
            self.update_files()

    def delete_file(self):
        folder = self.get_selected_folder()
        file = self.get_selected_file()
        if not folder or not file:
            return
        file_path = os.path.join(DATA_FOLDER, folder, file)
        confirm = QMessageBox.question(self, "Delete File", f"Delete file '{file}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes and os.path.exists(file_path):
            os.remove(file_path)
            self.update_files()

class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager by OceanJester")
        self.setWindowIcon(QIcon(os.path.join(ICONS_FOLDER, "vault.png")))
        self.resize(950, 630)
        self.master_password = None
        self.key = None
        self.salt = None

        self.setStyleSheet(QSS)
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(22)
        headline = QLabel("Password Manager by OceanJester")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        headline.setProperty("headline", True)
        main_layout.addWidget(headline)
        content = QHBoxLayout()
        main_layout.addLayout(content)

        # Left: Folder/File + Passwords
        left_panel = QVBoxLayout()
        left_panel.setSpacing(18)
        content.addLayout(left_panel, 2)
        left_panel.addWidget(QLabel("Folder:", alignment=Qt.AlignmentFlag.AlignLeft))
        self.folder_combo = QComboBox()
        self.folder_combo.currentIndexChanged.connect(self.update_file_combo)
        left_panel.addWidget(self.folder_combo)
        left_panel.addWidget(QLabel("File:", alignment=Qt.AlignmentFlag.AlignLeft))
        self.file_combo = QComboBox()
        self.file_combo.currentIndexChanged.connect(self.update_history)
        left_panel.addWidget(self.file_combo)
        left_panel.addWidget(QLabel("Password History:", alignment=Qt.AlignmentFlag.AlignLeft))
        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(180)
        left_panel.addWidget(self.history_list)
        # Search box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search passwords...")
        self.search_input.textChanged.connect(self.search_passwords)
        left_panel.addWidget(self.search_input)
        self.copy_history_btn = QPushButton("Copy selected password")
        self.copy_history_btn.setIcon(QIcon(os.path.join(ICONS_FOLDER, "file.png")))
        self.copy_history_btn.clicked.connect(self.copy_history_password)
        left_panel.addWidget(self.copy_history_btn)
        self.export_btn = QPushButton("Export passwords")
        self.export_btn.clicked.connect(self.export_passwords)
        left_panel.addWidget(self.export_btn)
        self.import_btn = QPushButton("Import passwords")
        self.import_btn.clicked.connect(self.import_passwords)
        left_panel.addWidget(self.import_btn)
        self.backup_btn = QPushButton("Backup file")
        self.backup_btn.clicked.connect(self.backup_file)
        left_panel.addWidget(self.backup_btn)

        # Right: Generator and Save
        right_panel = QVBoxLayout()
        right_panel.setSpacing(16)
        content.addLayout(right_panel, 4)
        right_panel.addWidget(QLabel("Generate a Password", alignment=Qt.AlignmentFlag.AlignLeft))
        gen_box = QHBoxLayout()
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 1000000)  # Practically no upper limit
        self.length_spin.setValue(16)
        gen_box.addWidget(QLabel("Length:"))
        gen_box.addWidget(self.length_spin)
        self.upper_cb = QCheckBox("Uppercase")
        self.upper_cb.setChecked(True)
        self.lower_cb = QCheckBox("Lowercase")
        self.lower_cb.setChecked(True)
        self.digit_cb = QCheckBox("Digits")
        self.digit_cb.setChecked(True)
        self.symbol_cb = QCheckBox("Symbols")
        self.symbol_cb.setChecked(True)
        for cb in [self.upper_cb, self.lower_cb, self.digit_cb, self.symbol_cb]:
            gen_box.addWidget(cb)
        right_panel.addLayout(gen_box)
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.clicked.connect(self.generate_password)
        right_panel.addWidget(self.generate_btn)
        self.password_output = QLineEdit()
        self.password_output.setReadOnly(True)
        right_panel.addWidget(self.password_output)
        self.suggestion_btn = QPushButton("Suggest Strong Password")
        self.suggestion_btn.clicked.connect(self.suggest_password)
        right_panel.addWidget(self.suggestion_btn)
        self.strength_label = QLabel("Password Strength: -")
        right_panel.addWidget(self.strength_label)
        right_panel.addWidget(QLabel("Save Password", alignment=Qt.AlignmentFlag.AlignLeft))
        save_form = QFormLayout()
        save_form.setFormAlignment(Qt.AlignmentFlag.AlignLeft)
        self.label_input = QLineEdit()
        self.username_input = QLineEdit()
        self.url_input = QLineEdit()
        self.notes_input = QLineEdit()
        save_form.addRow("Label:", self.label_input)
        save_form.addRow("Username:", self.username_input)
        save_form.addRow("URL:", self.url_input)
        save_form.addRow("Notes:", self.notes_input)
        right_panel.addLayout(save_form)
        self.save_btn = QPushButton("Save Password")
        self.save_btn.setIcon(QIcon(os.path.join(ICONS_FOLDER, "folder.png")))
        self.save_btn.clicked.connect(self.save_password)
        right_panel.addWidget(self.save_btn)
        self.last_added_label = QLabel("")
        right_panel.addWidget(self.last_added_label)
        self.editpanel_btn = QPushButton("Edit Folders / Files")
        self.editpanel_btn.setObjectName("editpanel")
        self.editpanel_btn.setMaximumWidth(170)
        self.editpanel_btn.clicked.connect(self.show_editpanel)
        main_layout.addWidget(self.editpanel_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        # Neon shadow for ALL buttons:
        all_btns = [
            self.copy_history_btn, self.export_btn, self.import_btn, self.backup_btn,
            self.generate_btn, self.suggestion_btn, self.save_btn, self.editpanel_btn
        ]
        for btn in all_btns:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(22)
            shadow.setColor(QColor(NEON_RED))
            shadow.setOffset(0, 0)
            btn.setGraphicsEffect(shadow)
        self.password_output.textChanged.connect(self.update_strength_label)
        self.check_master_password()
        self.refresh_folders_files()

    def show_editpanel(self):
        panel = EditPanel(self, self.key)
        panel.exec()
        self.refresh_folders_files()

    def check_master_password(self):
        if not os.path.exists(CONFIG_FILE):
            salt = generate_salt()
            pw, ok = QInputDialog.getText(self, "Set Master Password", "Create a strong master password:", QLineEdit.EchoMode.Password)
            if ok and pw:
                hashed_pw = hash_master_password(pw, salt)
                with open(CONFIG_FILE, "wb") as f:
                    f.write(salt + hashed_pw)
                self.master_password = pw
                self.salt = salt
                self.key = derive_key(pw, salt)
                return
            else:
                QMessageBox.warning(self, "Required", "You must set a master password to use this application.")
                sys.exit()
        with open(CONFIG_FILE, "rb") as f:
            data = f.read()
            salt = data[:16]
            stored_hash = data[16:]
        self.salt = salt
        while True:
            pw, ok = QInputDialog.getText(self, "Authentication Required", "Enter your master password:", QLineEdit.EchoMode.Password)
            if not ok:
                sys.exit()
            hashed_pw = hash_master_password(pw, salt)
            if secrets.compare_digest(hashed_pw, stored_hash):
                self.master_password = pw
                self.key = derive_key(pw, salt)
                return
            else:
                QMessageBox.warning(self, "Incorrect Password", "Wrong password, try again.")

    def refresh_folders_files(self):
        self.folder_combo.clear()
        folders = sorted([f for f in os.listdir(DATA_FOLDER) if os.path.isdir(os.path.join(DATA_FOLDER, f))])
        self.folder_combo.addItems(folders)
        self.update_file_combo()

    def update_file_combo(self):
        self.file_combo.clear()
        folder = self.folder_combo.currentText()
        if not folder:
            return
        folder_path = os.path.join(DATA_FOLDER, folder)
        files = sorted([f for f in os.listdir(folder_path) if f.endswith(".txt")])
        self.file_combo.addItems(files)
        self.update_history()

    def update_history(self):
        self.history_list.clear()
        folder = self.folder_combo.currentText()
        file = self.file_combo.currentText()
        if not folder or not file:
            return
        file_path = os.path.join(DATA_FOLDER, folder, file)
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_json = decrypt(encrypted_data, self.key)
                passwords = json.loads(decrypted_json)
                for entry in passwords[::-1]:
                    details = f"{entry['name']} | {entry.get('username','')} | {entry.get('url','')} | {entry.get('notes','')} ({entry['timestamp']}): {entry['password']}"
                    self.history_list.addItem(details)
                if passwords:
                    last = passwords[-1]
                    self.last_added_label.setText(f"Last added: {last['name']} ({last['timestamp']})")
                else:
                    self.last_added_label.setText("")
            except Exception:
                self.last_added_label.setText("")
        else:
            self.last_added_label.setText("")

    def generate_password(self):
        length = self.length_spin.value()
        characters = ""
        if self.upper_cb.isChecked():
            characters += string.ascii_uppercase
        if self.lower_cb.isChecked():
            characters += string.ascii_lowercase
        if self.digit_cb.isChecked():
            characters += string.digits
        if self.symbol_cb.isChecked():
            characters += string.punctuation
        if not characters:
            QMessageBox.warning(self, "Configuration Error", "Please select at least one character type.")
            return
        pw = ''.join(secrets.choice(characters) for _ in range(length))
        self.password_output.setText(pw)

    def suggest_password(self):
        # Example: 24-char strong password, all types
        chars = string.ascii_letters + string.digits + string.punctuation
        pw = ''.join(secrets.choice(chars) for _ in range(24))
        self.password_output.setText(pw)

    def update_strength_label(self):
        pw = self.password_output.text()
        strength = password_strength(pw)
        self.strength_label.setText(f"Password Strength: {strength}")

    def save_password(self):
        folder = self.folder_combo.currentText()
        file = self.file_combo.currentText()
        if not folder or not file:
            QMessageBox.warning(self, "Select a file", "Please select a folder and file to save password.")
            return
        pw = self.password_output.text()
        name = self.label_input.text()
        username = self.username_input.text()
        url = self.url_input.text()
        notes = self.notes_input.text()
        if not pw:
            QMessageBox.warning(self, "No Password", "Please generate a password first.")
            return
        if not name:
            QMessageBox.warning(self, "No Label", "Please enter a label/name for this password.")
            return
        file_path = os.path.join(DATA_FOLDER, folder, file)
        passwords = []
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_json = decrypt(encrypted_data, self.key)
                passwords = json.loads(decrypted_json)
            except Exception:
                passwords = []
        passwords.append({
            "name": name,
            "username": username,
            "url": url,
            "notes": notes,
            "password": pw,
            "timestamp": QDateTime.currentDateTime().toString(Qt.DateFormat.ISODate)
        })
        encrypted_data = encrypt(json.dumps(passwords), self.key)
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        QMessageBox.information(self, "Success", "Password successfully saved!")
        self.update_history()
        self.label_input.clear()
        self.username_input.clear()
        self.url_input.clear()
        self.notes_input.clear()

    def copy_history_password(self):
        item = self.history_list.currentItem()
        if item:
            text = item.text()
            try:
                pw = text.split(": ")[-1]
                clipboard = QApplication.clipboard()
                clipboard.setText(pw)
                QMessageBox.information(self, "Copied", "Password has been copied to your clipboard.")
            except IndexError:
                pass

    def search_passwords(self):
        query = self.search_input.text().lower()
        for i in range(self.history_list.count()):
            item = self.history_list.item(i)
            item.setHidden(query not in item.text().lower())

    def export_passwords(self):
        folder = self.folder_combo.currentText()
        file = self.file_combo.currentText()
        if not folder or not file:
            QMessageBox.warning(self, "Export Error", "Please select a folder and file to export.")
            return
        file_path = os.path.join(DATA_FOLDER, folder, file)
        if os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_json = decrypt(encrypted_data, self.key)
                passwords = json.loads(decrypted_json)
                save_path, _ = QFileDialog.getSaveFileName(self, "Export Passwords", f"{file}.json", "JSON Files (*.json)")
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as outf:
                        json.dump(passwords, outf, indent=2)
                    QMessageBox.information(self, "Exported", "Passwords exported as JSON.")
            except Exception as e:
                QMessageBox.warning(self, "Export Error", str(e))

    def import_passwords(self):
        folder = self.folder_combo.currentText()
        file = self.file_combo.currentText()
        if not folder or not file:
            QMessageBox.warning(self, "Import Error", "Please select a folder and file to import into.")
            return
        file_path = os.path.join(DATA_FOLDER, folder, file)
        open_path, _ = QFileDialog.getOpenFileName(self, "Import Passwords", "", "JSON Files (*.json)")
        if open_path:
            try:
                with open(open_path, "r", encoding="utf-8") as inf:
                    data = json.load(inf)
                if not isinstance(data, list):
                    raise Exception("Invalid JSON format")
                # Merge with current passwords
                curr = []
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()
                    decrypted_json = decrypt(encrypted_data, self.key)
                    curr = json.loads(decrypted_json)
                curr.extend(data)
                encrypted_data = encrypt(json.dumps(curr), self.key)
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)
                QMessageBox.information(self, "Imported", "Passwords imported and merged.")
                self.update_history()
            except Exception as e:
                QMessageBox.warning(self, "Import Error", str(e))

    def backup_file(self):
        folder = self.folder_combo.currentText()
        file = self.file_combo.currentText()
        if not folder or not file:
            QMessageBox.warning(self, "Backup Error", "Please select a folder and file to backup.")
            return
        file_path = os.path.join(DATA_FOLDER, folder, file)
        save_path, _ = QFileDialog.getSaveFileName(self, "Backup File", f"{file}.bak", "All Files (*)")
        if save_path:
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                with open(save_path, "wb") as outf:
                    outf.write(data)
                QMessageBox.information(self, "Backup", "Backup completed.")
            except Exception as e:
                QMessageBox.warning(self, "Backup Error", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Create default icons if they don't exist
    default_icons = {
        "vault.png": "🔒",
        "folder.png": "📂",
        "file.png": "📝"
    }
    for icon_name, emoji in default_icons.items():
        icon_path = os.path.join(ICONS_FOLDER, icon_name)
        if not os.path.exists(icon_path):
            with open(icon_path, "w", encoding="utf-8") as f:
                f.write(emoji)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
