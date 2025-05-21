import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage
import re
from auth.SecureLayer import SecureLayer
from app.main import main
from auth.session_control import SessionManager
from auth.auth_logging import setup_logging
from auth.forgot_pass import ForgotPasswordApp

class Login(tk.Tk):
    """
    Login window with pastel theme and session control.
    Handles user authentication and session creation.
    """
    
    def __init__(self):
        super().__init__()

        self.enc = SecureLayer()
        self.sm = SessionManager(3600)
        self.logger = setup_logging()
        self.title("Login")
        icon = PhotoImage(file='assets/icon.png')        
        self.iconphoto(False, icon)        
        self.geometry("400x380")
        self.resizable(False, False)

        # Set pleasant pastel color theme
        self.colors = {
            "background": "#E0E0E0",  # Light grey background
            "foreground": "#37474F",  # Blue-grey text
            "entry_bg": "#F5F5F5",    # Light entry background
            "entry_fg": "#263238",    # Darker text
            "button_bg": "#00BFA5",   # Teal Mint
            "button_fg": "#FFFFFF",   # White button text
            "error_fg": "#FF5252",    # Soft red
            "accent": "#00BFA5"        # Accent teal
        }

        self.bind_all('<Return>', self._submit)
        self.configure(bg=self.colors["background"])

        self.style = ttk.Style(self)
        self._set_pastel_style()
        self._create_widgets()

    def _set_pastel_style(self):
         # Apply custom styles to widgets for pastel look
         
        self.style.theme_use("clam")

        self.style.configure("TFrame", background=self.colors["background"])
        self.style.configure("TLabel", background=self.colors["background"], foreground=self.colors["foreground"], font=("Segoe UI", 11))
        self.style.configure("TEntry", fieldbackground=self.colors["entry_bg"], foreground=self.colors["entry_fg"], bordercolor=self.colors["accent"], borderwidth=2, padding=6, font=("Segoe UI", 11))
        self.style.configure("TButton", background=self.colors["button_bg"], foreground=self.colors["button_fg"], font=("Segoe UI Semibold", 11), padding=8)
        self.style.map("TButton", background=[('active', '#00897B'), ('!active', self.colors["button_bg"])])
        self.style.configure("Forgot.TLabel", foreground=self.colors["accent"], background=self.colors["background"], font=("Segoe UI", 10, "underline"))

    def _create_widgets(self):
        # Layout of login screen widgets - neat and spaced well
        
        container = ttk.Frame(self, padding=(20, 20, 20, 20))
        container.pack(expand=True, fill=tk.BOTH)

        title_label = ttk.Label(container, text="Login to your Account", font=("Segoe UI Semibold", 20, "bold"))
        title_label.pack(pady=(0, 25))

        self.username_var = tk.StringVar()
        username_label = ttk.Label(container, text="Username:")
        username_label.pack(anchor=tk.W, pady=(0,5), padx=(10,10))
        self.username_entry = ttk.Entry(container, textvariable=self.username_var)
        self.username_entry.pack(fill=tk.X, pady=(0, 15), padx=(10,10))
        self.username_entry.focus()

        self.password_var = tk.StringVar()
        password_label = ttk.Label(container, text="Password:")
        password_label.pack(anchor=tk.W, pady=(0,5), padx=(10,10))
        self.password_entry = ttk.Entry(container, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill=tk.X, pady=(0, 10), padx=(10,10))

        self.forgot_password_label = ttk.Label(container, text="Forgot Password?", style="Forgot.TLabel", cursor="hand2")
        self.forgot_password_label.pack(anchor=tk.E, pady=(0, 20), padx=(10,10))
        self.forgot_password_label.bind("<Button-1>", self._forgot_password_clicked)

        submit_button = ttk.Button(container, text="Login", command=self._submit)
        submit_button.pack(fill=tk.X, padx=(10,10))

    def _forgot_password_clicked(self, event=None):
        # Launch forgot password window — help for those who forget the magic word!
        
        _forgot = ForgotPasswordApp()
        _forgot.mainloop()

    def _submit(self, event=None):
        # Called on login submit, validates inputs and authenticates user
        
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username:
            self._show_error("Username cannot be empty.")
            self.username_entry.focus()
            return

        if len(password) < 6:
            self._show_error("Password must be at least 6 characters long.")
            self.password_entry.focus()
            return

        try:
            if self.enc.validate_user(username, password):
                self._show_success(f"Login successful!\nWelcome, {username}.")
                self.logger.info("Login Successful")                
                session = self.sm.create_session(username)
                self.logger.info("Session Created")
                self.destroy()
                main(session, self.logger)
                return
            else:
                self.logger.error("Invalid Credentials")
                self._show_error("Invalid Credentials")
        except Exception as e:
            self.logger.error("Error While Validating User")
            return

        self._clear_fields()

    def _show_error(self, message):
         # Show error popup
        messagebox.showerror("Error", message)

    def _show_success(self, message):
         # Show success popup
        messagebox.showinfo("Success", message)

    def _clear_fields(self):
        # Clear inputs and reset focus
        self.username_var.set("")
        self.password_var.set("")
        self.username_entry.focus()
