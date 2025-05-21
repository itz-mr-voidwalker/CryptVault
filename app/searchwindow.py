import tkinter as tk
from tkinter import messagebox, ttk, PhotoImage
import threading
import time
from typing import Tuple
from app.edit_dialog import EditDialog

class SearchWindow(tk.Toplevel):
    """Window for searching, editing, deleting, and copying saved passwords."""

    def __init__(self, parent):
        """Initialize the Search Window."""
        try:
            super().__init__(parent)
            self.parent = parent
            self.title("🔍 Search Passwords")
            self.geometry("600x520")
            self.configure(bg="#E0E0E0")
            self.resizable(False, False)

            icon = PhotoImage(file='assets/icon.png')        
            self.iconphoto(False, icon)     

            # Fonts and colors consistent with parent
            self.font_label = ("Segoe UI", 11)
            self.font_entry = ("Segoe UI", 12)
            self.font_tree = ("Segoe UI", 10)
            self.color_bg = "#E0E0E0"
            self.color_fg = "#37474F"
            self.color_entry_bg = "#FFFFFF"
            self.color_border = "#00BFA5"
            self.color_select_bg = "#00BFA5"
            self.color_select_fg = "#FFFFFF"
            self.color_btn_bg = "#00BFA5"
            self.color_btn_hover = "#24A392"

            self._setup_widgets()
            self.refresh_table()
        except Exception as e:
            self.parent.logger.error(e)

    def _setup_widgets(self):
        """Setup widgets for the search window."""
        try:
            padding_x = 20
            padding_y = 15

            # Search Label and Entry frame
            search_frame = tk.Frame(self, bg=self.color_bg)
            search_frame.pack(fill="x", padx=padding_x, pady=(padding_y, 8))

            search_label = tk.Label(search_frame, text="Search Service:", font=self.font_label, fg=self.color_fg, bg=self.color_bg)
            search_label.pack(anchor="w")

            self.search_var = tk.StringVar()
            self.search_var.trace_add("write", self.on_search_change)

            search_entry = tk.Entry(search_frame, font=self.font_entry,
                        bg=self.color_entry_bg,
                        fg=self.color_fg, insertbackground=self.color_fg,
                        borderwidth=2, relief="groove",
                        textvariable=self.search_var)

            search_entry.pack(fill="x", pady=(6, 0), ipady=3) 

            # Treeview frame with scrollbar
            tree_frame = tk.Frame(self, bg=self.color_bg)
            tree_frame.pack(fill="both", expand=True, padx=padding_x, pady=(10, 8))

            columns = ("service", "username", "password")
            self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
            self.tree.pack(side="left", fill="both", expand=True)

            # Scrollbar
            scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
            scrollbar.pack(side="right", fill="y")
            self.tree.configure(yscroll=scrollbar.set)

            # Treeview columns configuration
            self.tree.heading("service", text="Service")
            self.tree.heading("username", text="Username")
            self.tree.heading("password", text="Password")

            self.tree.column("service", width=200, anchor="w")
            self.tree.column("username", width=180, anchor="w")
            self.tree.column("password", width=180, anchor="w")

            # Style Treeview for dark theme
            style = ttk.Style(self)
            style.theme_use('clam')

            style.configure("Treeview",
                            background=self.color_entry_bg,
                            foreground=self.color_fg,
                            fieldbackground=self.color_entry_bg,
                            font=self.font_tree,
                            bordercolor=self.color_border,
                            borderwidth=0,
                            rowheight=28)

            style.map("Treeview",
                    background=[('selected', self.color_select_bg)],
                    foreground=[('selected', self.color_select_fg)])

            style.configure("Treeview.Heading",
                            background=self.color_border,
                            foreground=self.color_fg,
                            font=("Segoe UI", 11, "bold"))

            # Buttons frame for Edit, Delete, and Copy Password
            btn_frame = tk.Frame(self, bg=self.color_bg)
            btn_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))

            edit_btn = tk.Button(btn_frame, text="Edit Selected", font=("Segoe UI", 11, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                cursor="hand2", borderwidth=0, padx=15, pady=6,
                                command=self.edit_selected)
            edit_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))

            delete_btn = tk.Button(btn_frame, text="Delete Selected", font=("Segoe UI", 11, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                cursor="hand2", borderwidth=0, padx=15, pady=6,
                                command=self.delete_selected)
            delete_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))

            copy_btn = tk.Button(btn_frame, text="Copy Password", font=("Segoe UI", 11, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                cursor="hand2", borderwidth=0, padx=15, pady=6,
                                command=self.copy_password)
            copy_btn.pack(side="left", expand=True, fill="x")
        
        except Exception as e:
            self.parent.logger.error(e)

    def on_search_change(self, *args):
        """Called when search input changes to refresh the table."""
        try:
            self.refresh_table()
        except Exception as e:
            self.parent.logger.error(e)

    def refresh_table(self, *args):
        """
        Refreshes the password table in the search window.
        Filters entries based on the search query and populates the Treeview.
        """
        try:
            query = self.search_var.get().lower()

            # Clear the current contents of the Treeview
            for row in self.tree.get_children():
                self.tree.delete(row)
            

            # Filter and add rows to the Treeview
            for service,entries in self.parent.password_data.items():
                for entry in entries:
                    username = entry['username']
                    hidden_password = "*" * len(entry['password'])
                    
                    if not query or query in service.lower() or query in username.lower():
                        self.tree.insert("",tk.END,values=(service, username, hidden_password))
        except Exception as e:
            self.parent.logger.error(e)
    
    def get_selected_service(self) -> Tuple[str, str, str]:
        """
        Retrieve the currently selected service from the treeview.

        Returns:
            str or None: The selected service name or None if no selection.
        """
        try:
            selected = self.tree.selection()
            if not selected:
                messagebox.showinfo("Selection Required", "Please select a service entry.")
                return None
            item = self.tree.item(selected[0])
            service = item['values'][0]
            username = item['values'][1]
            password =  item['values'][2]
            return service,username,password

        except Exception as e:
            self.parent.logger.error(e)
    
    def edit_selected(self):
        """Open the edit dialog for the selected entry."""
        try:
            service, username, password = self.get_selected_service()
            if not service:
                return        
            

            # Open custom modern edit dialog
            dialog = EditDialog(self, service, username, password)
            self.wait_window(dialog)
            # After dialog closes, check if updates were made
            if dialog.updated_data:           
                uname  = dialog.updated_data['username']
                encryp_password = self.parent.cipher.encrypt(dialog.updated_data['password'].encode()).decode()
                
                entries = self.parent.password_data.get(service, [])
                for entry in entries:
                    if entry['username']==username:
                        entry['username']=uname
                        entry['password']=encryp_password                   
                        if self.parent.save_to_file():
                            messagebox.showinfo("Success", "Edit Successful")
                            self.parent.logger.info(f"Edit Successful for {username}")
                            self.refresh_table()
                            return
                        else:
                            messagebox.showerror("Error while saving edits to file")
                            self.parent.logger.error("Error while saving edits to file")
                            return      
                        
        except Exception as e:
            self.parent.logger.error(e)         
            
    def delete_selected(self):
        """Delete the selected password entry after confirmation."""
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showwarning("No Selection", "Please select an entry to delete.")
                self.parent.logger.error("Please select an entry to delete.")
                return

            service, username, _ = self.get_selected_service()

            confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the entry for '{username}' under '{service}'?")
            if not confirm:
                return

            # Remove the entry from the parent's data dictionary
            entries = self.parent.password_data.get(service, [])
            self.parent.password_data[service] = [entry for entry in entries if entry["username"] != username]

            # If no more entries under the service, remove the service key entirely
            if not self.parent.password_data[service]:
                del self.parent.password_data[service]

            # Save to file and refresh UI
            if self.parent.save_to_file():
                self.refresh_table()
                messagebox.showinfo("Deleted", f"The password entry for '{username}' under '{service}' was successfully deleted.")
                self.parent.logger.info(f"The password entry for '{username}' under '{service}' was successfully deleted.")
            else:
                messagebox.showerror("Error", "Failed to save changes to file.")
                self.parent.logger.error("Failed to save changes to file.")
                
        except Exception as e:
            self.parent.logger.error(e)
    
    def copy_password(self):
        """Copy the password of the selected service to clipboard."""
        try:
            service,username, _ = self.get_selected_service()
            if not service:
                return
            found=False
            for Service, entries in self.parent.password_data.items():
                if Service==service:
                    for entry in entries:
                        if entry['username']==username:
                            try:
                                found=True                            
                                encrypted_password = entry['password']
                                password_parent = self.parent.cipher_parent.decrypt(encrypted_password.encode())
                                password = self.parent.cipher_child.decrypt(password_parent).decode()
                                self.clipboard_clear()
                                self.clipboard_append(password)
                                self.update()
                                
                                messagebox.showinfo("Success",'Password Copied to Clipboard, It will last only for 10secs')
                                self.parent.logger.info('Password Copied to Clipboard, It will last only for 10secs')
                                break
                            except Exception as e:
                                self.parent.logger.error(e)    
             
            if not found:
                print("There was an error while parsing the password")
                self.parent.logger.info("There was an error while parsing the password")         

            
            if not password:
                messagebox.showerror("Error", f"No password found for {service}.")
                self.parent.logger.info(f"No password found for {service}.")
                return
        except Exception as e:
            self.parent.logger.error(e)
        
    

