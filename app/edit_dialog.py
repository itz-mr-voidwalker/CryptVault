import tkinter as tk
from tkinter import messagebox,ttk, PhotoImage

class EditDialog(tk.Toplevel):
    """Dialog window to edit username and password for a selected service."""

    def __init__(self, parent, service, username, password):
        """
        Initialize the Edit dialog.

        Args:
            parent (tk.Widget): Parent widget.
            service (str): The service name being edited.
            username (str): Current username/email.
            password (str): Current password.
        """
        super().__init__(parent)
        self.parent = parent
        self.service = service
        self.updated_data = None  # To hold updated username and password on submit

        icon = PhotoImage(file='assets/icon.png')        
        self.iconphoto(False, icon)     
        
        # Dark theme colors/fonts
        self.color_bg = "#E0E0E0"
        self.color_fg = "#37474F"
        self.color_entry_bg = "#FFFFFF"
        self.color_border = "#00BFA5"
        self.color_select_bg = "#00BFA5"
        self.color_select_fg = "#FFFFFF"
        self.color_btn_bg = "#00BFA5"
        self.color_btn_hover = "#24A392"
        self.font_label = ("Segoe UI", 11)
        self.font_entry = ("Segoe UI", 12)
        self.font_btn = ("Segoe UI", 11, "bold")

        self.configure(bg=self.color_bg)
        self.title(f"Edit '{service}'")

        self.geometry("400x320")
        self.resizable(True, True)

        self.username_var = tk.StringVar(value=username)
        self.password_var = tk.StringVar(value=password)

        self._setup_widgets()
        self.transient(parent)  # Set to be modal
        self.grab_set()
        self.focus_force()

    def _setup_widgets(self):
        """Setup UI widgets inside the edit dialog."""
        padding_x = 20
        padding_y = 15

        lbl_service = tk.Label(self, text=f"Editing service: {self.service}", font=("Segoe UI", 13, "bold"),
                               fg=self.color_fg, bg=self.color_bg)
        lbl_service.pack(pady=(padding_y, 10))

        # Username
        user_frame = tk.Frame(self, bg=self.color_bg)
        user_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))

        user_label = tk.Label(user_frame, text="Username/Email:", font=self.font_label,
                              fg=self.color_fg, bg=self.color_bg)
        user_label.pack(anchor="w")

        user_entry = tk.Entry(user_frame, font=self.font_entry, bg=self.color_entry_bg,
                              fg=self.color_fg, insertbackground=self.color_fg,
                              borderwidth=2, relief="groove",
                              textvariable=self.username_var)
        user_entry.pack(fill="x", pady=(4, 0))

        # Password
        pass_frame = tk.Frame(self, bg=self.color_bg)
        pass_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))

        pass_label = tk.Label(pass_frame, text="Password:", font=self.font_label,
                              fg=self.color_fg, bg=self.color_bg)
        pass_label.pack(anchor="w")

        pass_entry = tk.Entry(pass_frame, font=self.font_entry, bg=self.color_entry_bg,
                              fg=self.color_fg, insertbackground=self.color_fg,
                              borderwidth=2, relief="groove",
                              textvariable=self.password_var,
                              show="*")
        pass_entry.pack(fill="x", pady=(4, 0))

        # Buttons frame
        btn_frame = tk.Frame(self, bg=self.color_bg)
        btn_frame.pack(pady=(10, padding_y))

        submit_btn = tk.Button(btn_frame, text="Submit", font=self.font_btn,
                               bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                               cursor="hand2", borderwidth=0, padx=20, pady=8,
                               command=self.on_submit)
        submit_btn.pack(side="left", padx=8)

        cancel_btn = tk.Button(btn_frame, text="Cancel", font=self.font_btn,
                               bg="#555555", fg="white", activebackground="#777777",
                               cursor="hand2", borderwidth=0, padx=20, pady=8,
                               command=self.destroy)
        cancel_btn.pack(side="left", padx=8)

    def on_submit(self):
        """Validate inputs and submit updated data."""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty.", parent=self)
            return

        self.updated_data = {"username": username, "password": password}
        self.destroy()


