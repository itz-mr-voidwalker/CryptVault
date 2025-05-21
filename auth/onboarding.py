import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage
import re
from auth.login import Login
import time
import socket
import random
from auth.email_sender import EmailVerification
from auth.SecureLayer import SecureLayer
from auth.auth_logging import setup_logging


class Setup(tk.Tk):
    """
    Onboarding Setup window class for the Password Manager application.

    Responsibilities:
    - Collect username, email, and password from user.
    - Validate input fields including email format and password length.
    - Verify email via a 5-digit code sent to the user's email address.
    - Encrypt and save user data securely using SecureLayer.
    - Transition to Login window upon successful setup.

    Attributes:
        logger (logging.Logger): Logger instance for app events.
        enc (SecureLayer): Encryption handler for storing credentials.
        colors (dict): Color palette for UI styling.
        username_var (tk.StringVar): Bound to username input field.
        email_var (tk.StringVar): Bound to email input field.
        password_var (tk.StringVar): Bound to password input field.
    """
    
    def __init__(self):
        """
        Initializes the Setup window, UI components, styles,
        and event bindings.
        """
        
        self.logger = setup_logging()
        super().__init__()

        self.title("Onboarding - Setup")
        self.geometry("400x420")
        self.resizable(False, False)

        icon = PhotoImage(file='assets/icon.png')        
        self.iconphoto(False, icon)     

        self.enc = SecureLayer()

        self.colors = {
            "background": "#E0E0E0",
            "foreground": "#37474F",
            "entry_bg": "#F5F5F5",
            "entry_fg": "#263238",
            "button_bg": "#00BFA5",
            "button_fg": "#FFFFFF",
            "error_fg": "#FF5252",
            "accent": "#00BFA5"
        }

        self.configure(bg=self.colors["background"])


        self.style = ttk.Style(self)
        self._set_style()
        self._create_widgets()
        self.bind_all('<Return>', self._submit)

    def _set_style(self):
        """
        Configures the ttk styles for the UI widgets
        according to the pastel color theme.
        """
        
        self.style.theme_use("clam")
        self.style.configure("TFrame", background=self.colors["background"])
        self.style.configure("TLabel", background=self.colors["background"], foreground=self.colors["foreground"], font=("Segoe UI", 11))
        self.style.configure("TEntry", fieldbackground=self.colors["entry_bg"], foreground=self.colors["entry_fg"], bordercolor=self.colors["accent"], borderwidth=2, padding=6, font=("Segoe UI", 11))
        self.style.configure("TButton", background=self.colors["button_bg"], foreground=self.colors["button_fg"], font=("Segoe UI Semibold", 11), padding=8)
        self.style.map("TButton", background=[('active', '#00897B'), ('!active', self.colors["button_bg"])])

    def _create_widgets(self):
        """
        Creates and places all widgets on the Setup window,
        including labels, entry fields, and the submit button.
        """
        
        container = ttk.Frame(self, padding=(20, 20, 20, 20))
        container.pack(expand=True, fill=tk.BOTH)

        title_label = ttk.Label(container, text="Create your Account", font=("Segoe UI Semibold", 20, "bold"))
        title_label.pack(pady=(0, 20))

        self.username_var = tk.StringVar()
        username_label = ttk.Label(container, text="Username:")
        username_label.pack(anchor=tk.W, pady=(0, 5), padx=(10, 10))
        self.username_entry = ttk.Entry(container, textvariable=self.username_var)
        self.username_entry.pack(fill=tk.X, pady=(0, 15), padx=(10, 10))
        self.username_entry.focus()

        self.email_var = tk.StringVar()
        email_label = ttk.Label(container, text="Email:")
        email_label.pack(anchor=tk.W, pady=(0, 5), padx=(10, 10))
        self.email_entry = ttk.Entry(container, textvariable=self.email_var)
        self.email_entry.pack(fill=tk.X, pady=(0, 15), padx=(10, 10))

        self.password_var = tk.StringVar()
        password_label = ttk.Label(container, text="Password:")
        password_label.pack(anchor=tk.W, pady=(0, 5), padx=(10, 10))
        self.password_entry = ttk.Entry(container, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill=tk.X, pady=(0, 25), padx=(10, 10))

        submit_button = ttk.Button(container, text="Submit", command=self._submit)
        submit_button.pack(fill=tk.X, padx=(10, 10))

    def _submit(self, event= None):
        """
        Handles form submission when user presses Submit button or Enter key.

        Workflow:
        1. Validate username, email, and password inputs.
        2. Verify email by sending a verification code and prompting user.
        3. Encrypt and save user data if verification succeeds.
        4. Log events and display messages accordingly.
        5. On success, destroy setup window and open Login window.

        Args:
            event (tk.Event, optional): Event object from key binding.
        """
        
        
        try:
            username = self.username_var.get().strip()
            email = self.email_var.get().strip()
            password = self.password_var.get()

            if not username:
                self._show_error("Username cannot be empty.")
                self.username_entry.focus()
                return

            if not self._is_valid_email(email):
                self._show_error("Please enter a valid email address.")
                self.email_entry.focus()
                return

            if len(password) < 6:
                self._show_error("Password must be at least 6 characters long.")
                self.password_entry.focus()
                return

            if self._is_email_verified(email):
                try:
                    if self.enc.encrypt_data(username, email, password):
                        self.logger.info("Setup Completed Successfully")
                        self._show_success(f"Account created successfully!\nUsername: {username}\nEmail: {email}")
                        self.destroy()
                        Login().mainloop()
                    self.logger.error("Encryption Error")
                except Exception as e:
                    self.logger.error(e)
            self._clear_fields()
        except Exception as e:
            self.logger.error(f"Error While Validating in Onboarding.py {e}")

    def is_connected(self, host="8.8.8.8", port=53, timeout=3):
        """
        Checks if the machine has an active internet connection by attempting
        to connect to a reliable host (Google DNS by default).

        Args:
            host (str): Host to connect to. Defaults to "8.8.8.8".
            port (int): Port number. Defaults to 53.
            timeout (int): Connection timeout in seconds. Defaults to 3.

        Returns:
            bool: True if connected, False otherwise.
        """
        
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except socket.error as ex:
            print(f"Connection failed: {ex}")
            return False

    def _is_email_verified(self, email):
        """
        Verifies user's email by sending a 5-digit code via EmailVerification
        and displaying a modal prompt to enter the code.

        Args:
            email (str): The email address to verify.

        Returns:
            bool: True if verification succeeds, False otherwise.

        Side Effects:
            - Displays a Toplevel window for code input.
            - Shows info/error messages during verification.
            - Logs verification steps and errors.
        """
        
        if not self.is_connected():
            messagebox.showwarning("No Internet !", "Internet Connection Required for Authentication!\nReattempt the setup after connecting to internet")
            self.logger.error("No Internet")
            return

        try:
            generated_code = random.randrange(10000, 99999)
            created_at = int(time.time())
            EmailVerification().send_email('Email Verification - Password Manager', generated_code, email)
            self.logger.info("Email Code Sent !")
        except:
            self.logger.error("Can't Send Email Verification Code")
            return

        verified = False
        sub_window = tk.Toplevel(self)
        sub_window.grab_set()
        sub_window.title("Email Verification")
        sub_window.geometry("360x250")
        sub_window.configure(bg=self.colors["background"])
        sub_window.resizable(False, False)

        frame = ttk.Frame(sub_window, padding=20, style="TFrame")
        frame.pack(expand=True, fill=tk.BOTH)

        title_label = ttk.Label(frame, text="Email Verification", font=("Segoe UI Semibold", 16))
        title_label.pack(pady=(0, 10))

        desc_label = ttk.Label(frame, text="Enter the 5-digit code sent to your email:", font=("Segoe UI", 11))
        desc_label.pack(pady=(0, 10))

        code_entry = ttk.Entry(frame, font=("Segoe UI", 12), justify="center", width=15)
        code_entry.pack(pady=(0, 15))
        code_entry.focus()

        error_label = ttk.Label(frame, text="", foreground=self.colors["error_fg"], font=("Segoe UI", 10))
        error_label.pack()

        def _on_submit():
            nonlocal verified
            try:
                entered_code = int(code_entry.get())
                current_time = int(time.time())

                if current_time - created_at > 600:
                    error_label.config(text="Code expired. Please try again.")
                    self.logger.error("Code Expired, Retry")
                elif entered_code == generated_code:
                    self.logger.info("Code Verification Successful")
                    verified = True
                    self._show_success("Email Verified Successfully!")
                    sub_window.destroy()
                else:
                    error_label.config(text="Incorrect code. Retry!")
                    self.logger.error("Wrong Code")
            except:
                error_label.config(text="Invalid input. Enter numbers only.")
                self.logger.error("Can't Validate Code")

        submit_btn = ttk.Button(frame, text="Verify", command=_on_submit)
        submit_btn.pack(pady=(10, 0))

        self.wait_window(sub_window)
        return verified
    
    def _is_valid_email(self, email):
        """
        Validates email format using a regex pattern.

        Args:
            email (str): Email address to validate.

        Returns:
            bool: True if email matches the regex pattern, False otherwise.
        """
        
        EMAIL_REGEX = re.compile(
                r"""(?xi)                                     # Enable verbose and case-insensitive modes
                ^                                             # Start of string
                [a-z0-9!#$%&'*+/=?^_{|}~-]+                  # Local part
                    (?:\.[a-z0-9!#$%&'*+/=?^_{|}~-]+)*       # Dots in local part
                @                                             # @ symbol
                (?:
                    [a-z0-9]                                  # Domain start
                    (?:[a-z0-9-]{0,61}[a-z0-9])?              # Domain middle
                    \.                                        # Dot before TLD
                )+                                            # Repeatable domain parts
                [a-z]{2,63}                                   # TLD (e.g., com, io, co.uk)
                $                                             # End of string
                """
            )
        return bool(EMAIL_REGEX.match(email))

    def _show_error(self, message):
        """
        Displays an error message dialog with the specified message.

        Args:
            message (str): Error message to show.
        """
        messagebox.showerror("Error", message)

    def _show_success(self, message):
        """
        Displays an informational success message dialog with the specified message.

        Args:
            message (str): Success message to show.
        """
        
        messagebox.showinfo("Success", message)

    def _clear_fields(self):
        """
        Resets the input fields to empty strings and sets focus
        back to the username entry field.
        """
        self.username_var.set("")
        self.email_var.set("")
        self.password_var.set("")
        self.username_entry.focus()