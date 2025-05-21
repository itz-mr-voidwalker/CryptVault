import tkinter as tk
from tkinter import ttk, messagebox,PhotoImage
import random
import os
import json
import keyring
from cryptography.fernet import Fernet
from app.searchwindow import SearchWindow
from dotenv import load_dotenv
import string

class PasswordManager(tk.Tk):
    """Main application class for the Password Manager."""
    
    def __init__(self, logger):
        """Initialize the Password Manager application."""
        self.logger = logger
        try:
            load_dotenv()
            super().__init__()

            self.title(os.getenv('PROGRAM_APP_NAME'))
            self.geometry("480x420")
            self.resizable(False, False)
            
            icon = PhotoImage(file='assets/icon.png')        
            self.iconphoto(False, icon)     

            self.user_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs", "CryptVault")
            os.makedirs(self.user_path, exist_ok=True)
            self.data_file = os.path.join(self.user_path, os.getenv('PROGRAM_DATA_FILE'))

            self.colors = {
                "background": "#E0E0E0",
                "foreground": "#37474F",
                "entry_bg": "#F5F5F5",
                "entry_fg": "#263238",
                "button_bg": "#00BFA5",
                "button_fg": "#FFFFFF",
                "accent": "#00BFA5"
            }

            self.configure(bg=self.colors["background"])
            self.style = ttk.Style(self)
            self._set_style()
            self.setup_cipher()
            self.password_data = self.load_entries()
            self._create_widgets()
            
        except Exception as e:
            self.logger.error(e)

    def _set_style(self):
        """
        Configure the ttk style for the widgets with custom colors and fonts.
        """
        
        self.style.theme_use("clam")
        self.style.configure("TFrame", background=self.colors["background"])
        self.style.configure("TLabel", background=self.colors["background"], foreground=self.colors["foreground"], font=("Segoe UI", 11))
        # ttk.Entry doesn't support bg colors well across platforms, so entries are tk.Entry below
        self.style.configure("TButton", background=self.colors["button_bg"], foreground=self.colors["button_fg"], font=("Segoe UI Semibold", 11), padding=8)
        self.style.map("TButton", background=[('active', '#00897B'), ('!active', self.colors["button_bg"])])

    def load_entries(self) -> dict:
        """
        Load password entries from the data file.

        Returns:
            dict: Dictionary containing all password entries.
        """
        
        
        try:
            tmp_dct = {}
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as file:
                    for line in file:
                        data = json.loads(line.strip())
                        tmp_dct.update(data)
                return tmp_dct
            else:
                return tmp_dct
        except Exception as e:
            print(e)

    def _create_widgets(self):
        """
        Create and arrange all the GUI widgets in the main window.
        """        
        
        container = ttk.Frame(self, padding=(20, 20, 20, 20))
        container.pack(expand=True, fill=tk.BOTH)

        title_label = ttk.Label(container, text=os.getenv('PROGRAM_APP_NAME'), font=("Segoe UI Semibold", 20, "bold"))
        title_label.pack(pady=(0, 20))

        # Website
        website_label = ttk.Label(container, text="Website:")
        website_label.pack(anchor=tk.W, pady=(0, 5), padx=(10, 10))
        self.website_var = tk.StringVar()
        self.website_entry = tk.Entry(container, textvariable=self.website_var,
                                      bg=self.colors["entry_bg"], fg=self.colors["entry_fg"],
                                      insertbackground=self.colors["entry_fg"],
                                      font=("Segoe UI", 11), relief="flat", highlightthickness=2,
                                      highlightcolor=self.colors["accent"], highlightbackground=self.colors["accent"])
        self.website_entry.pack(fill=tk.X, pady=(0, 15), padx=(10, 10))

        # Username/Email
        username_label = ttk.Label(container, text="Username/Email:")
        username_label.pack(anchor=tk.W, pady=(0, 5), padx=(10, 10))
        self.username_var = tk.StringVar()
        self.username_entry = tk.Entry(container, textvariable=self.username_var,
                                       bg=self.colors["entry_bg"], fg=self.colors["entry_fg"],
                                       insertbackground=self.colors["entry_fg"],
                                       font=("Segoe UI", 11), relief="flat", highlightthickness=2,
                                       highlightcolor=self.colors["accent"], highlightbackground=self.colors["accent"])
        self.username_entry.pack(fill=tk.X, pady=(0, 15), padx=(10, 10))

        # Password
        password_label = ttk.Label(container, text="Password:")
        password_label.pack(anchor=tk.W, pady=(0, 5), padx=(10, 10))
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(container, textvariable=self.password_var, show="•",
                                       bg=self.colors["entry_bg"], fg=self.colors["entry_fg"],
                                       insertbackground=self.colors["entry_fg"],
                                       font=("Segoe UI", 11), relief="flat", highlightthickness=2,
                                       highlightcolor=self.colors["accent"], highlightbackground=self.colors["accent"])
        self.password_entry.pack(fill=tk.X, pady=(0, 15), padx=(10, 10))

        # Button frame
        button_frame = ttk.Frame(container)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        save_button = ttk.Button(button_frame, text="Save Password", command=self.save_password)
        save_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(10, 5))

        search_button = ttk.Button(button_frame, text="Search Password", command=self.open_search_window)
        search_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 10))

        footer = tk.Label(self, text="© 2025 CryptVault", font=("Segoe UI", 9),
                          fg="#777777", bg=self.colors["background"])
        footer.pack(side="bottom", pady=8)

    def generate_password(self):
        """Generate a strong random password and update the password entry."""
        try:
            length = 16
            all_chars = string.ascii_letters + string.digits + string.punctuation
            while True:
                password = ''.join(random.choice(all_chars) for _ in range(length))
                if (any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and any(c.isdigit() for c in password)
                    and any(c in string.punctuation for c in password)):
                    break
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Password Generated", "Strong password generated and copied to clipboard!")
            self.logger.info("Password Generated!")
        except Exception as e:
            self.logger.error("Can't Generate Password")

    def setup_cipher(self):
        """
        Setup the Fernet encryption cipher using a key stored in the keyring.
        Generates and stores a new key if one does not exist.
        """
        
        try:
            self.key = keyring.get_password('password_manager', 'admin')
            if self.key is None:
                self.key = Fernet.generate_key()
                keyring.set_password('password_manager', 'admin', self.key.decode())
            self.cipher_child = Fernet(self.key)
            
            key = keyring.get_password('password_manager', 'admin')
            if key is None:
                key = Fernet.generate_key()
                keyring.set_password('password_manager', 'admin', key.decode())
            self.cipher_parent = Fernet(key)
            
        except Exception as e:
            print(f"Exception While Cipher Setup - {e}")

    def save_to_file(self) -> bool:
        """
        Save the current password data to the file in JSON format.

        Returns:
            bool: True if saving succeeded, False otherwise.
        """
        
        try:
            with open(self.data_file, 'w') as file:
                file.write(json.dumps(self.password_data) + "\n")
                return True
            return False
        except Exception as e:
            self.logger.error(e)

    def save_password(self) -> None:
        """
        Validate inputs and save a new password entry encrypted to the data structure
        and persist it to file. Handles duplicate usernames per website.
        """
        try:
            website = self.website_var.get().strip()
            username = self.username_var.get().strip()
            password = self.password_var.get().strip()

            if not website or not username or not password:
                messagebox.showwarning("Input Error", "Please fill in all fields before saving.")
                self.logger.error("Please fill in all fields before saving.")
                return
            
            encrypted_pass_child = self.cipher_child.encrypt(password.encode())
            encrypted_pass = self.cipher_parent.encrypt(encrypted_pass_child)
            new_entry = {
                'username': username,
                'password': encrypted_pass.decode()
            }
            
            if website not in self.password_data:
                self.password_data[website] = []
                
            for entry in self.password_data[website]:
                if entry["username"] == username:
                    messagebox.showerror("Error", f"⚠️ Username '{username}' already exists under service '{website}'.")
                    self.logger.error(f"⚠️ Username '{username}' already exists under service '{website}'.")
                    return

            self.password_data[website].append(new_entry)
            if self.save_to_file():
                self.clear_entries()
                messagebox.showinfo("Saved", f"Password saved for {website}.")
                self.logger.info(f"Password saved for {website}.")
                
        except Exception as e:
            self.logger.error(e)

    def open_search_window(self) -> None:
        """
        Open the search window for finding saved passwords. If already opened,
        brings the window to the front.
        """
        
        if hasattr(self, "search_window") and self.search_window.winfo_exists():
            self.search_window.lift()
            return
        self.search_window = SearchWindow(self)

    def clear_entries(self):
        """Clear all input fields."""
        self.website_var.set("")
        self.username_var.set("")
        self.password_var.set("")

