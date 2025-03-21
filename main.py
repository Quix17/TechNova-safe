# Copyright (c) 2025 TechNova / Sven Kunz
# Nutzung erlaubt, aber Weiterverbreitung und Verkauf nur mit Erlaubnis.
# Siehe LICENSE-Datei für weitere Details.

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import secrets
import string
import pyperclip
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from datetime import datetime
import customtkinter as ctk
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw
import keyboard
import webbrowser


class TechNovasafe:
    def __init__(self):
        self.db_file = "technovasafe.db"
        self.master_key = None
        self.cipher_suite = None
        self.init_db()

        # Set up the customtkinter theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Create main window
        self.root = ctk.CTk()
        self.root.title("TechNovasafe")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)

        # Create styles and colors
        self.colors = {
            "bg": "#121212",
            "card": "#1E1E1E",
            "primary": "#9C27B0",  # Purple
            "secondary": "#6A1B9A",  # Dark Purple
            "text": "#FFFFFF",
            "text_secondary": "#BBBBBB"
        }

        self.tray_icon = None
        self.quiet_mode_var = tk.BooleanVar(value=False)  # Variable for Quiet Mode checkbox
        self.setup_tray_icon()
        self.bind_shortcuts()

        self.setup_ui()

    def init_db(self):
        """Initialize the database and create tables if they don't exist"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Create master password table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY,
            salt BLOB NOT NULL,
            password_hash TEXT NOT NULL,
            hint TEXT
        )
        ''')

        # Create passwords table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            category TEXT,
            date_added TEXT,
            date_modified TEXT
        )
        ''')

        # Create categories table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        )
        ''')

        # Insert default categories
        default_categories = ["Banking", "Email", "Social", "Shopping", "Work", "Entertainment", "Other"]
        for category in default_categories:
            try:
                cursor.execute("INSERT INTO categories (name) VALUES (?)", (category,))
            except sqlite3.IntegrityError:
                pass  # Category already exists

        conn.commit()
        conn.close()

    def setup_ui(self):
        """Set up the user interface"""
        # Check if master password exists
        if self.check_master_exists():
            self.show_login_screen()
        else:
            self.show_create_master_screen()

    def check_master_exists(self):
        """Check if a master password has been set up"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def show_login_screen(self):
        """Display the login screen"""
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create login frame
        login_frame = ctk.CTkFrame(self.root, fg_color=self.colors["bg"])
        login_frame.pack(fill=tk.BOTH, expand=True)

        # Add logo/title
        title_label = ctk.CTkLabel(login_frame, text="TechNovasafe",
                                   font=ctk.CTkFont(size=32, weight="bold"),
                                   text_color=self.colors["primary"])
        title_label.pack(pady=(100, 20))

        subtitle_label = ctk.CTkLabel(login_frame, text="Your Secure Password Vault",
                                      font=ctk.CTkFont(size=14),
                                      text_color=self.colors["text_secondary"])
        subtitle_label.pack(pady=(0, 40))

        # Create login form
        form_frame = ctk.CTkFrame(login_frame, fg_color=self.colors["card"], corner_radius=10)
        form_frame.pack(padx=20, pady=20, ipadx=30, ipady=30)

        password_label = ctk.CTkLabel(form_frame, text="Master Password",
                                      font=ctk.CTkFont(size=14),
                                      text_color=self.colors["text"])
        password_label.pack(anchor="w", padx=20, pady=(20, 5))

        self.password_entry = ctk.CTkEntry(form_frame, width=300, show="•",
                                           fg_color=self.colors["bg"],
                                           border_color=self.colors["primary"],
                                           text_color=self.colors["text"])
        self.password_entry.pack(padx=20, pady=(0, 20))
        self.password_entry.focus()

        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=10)

        login_button = ctk.CTkButton(button_frame, text="Login",
                                     fg_color=self.colors["primary"],
                                     hover_color=self.colors["secondary"],
                                     height=36,
                                     command=self.verify_master_password)
        login_button.pack(side="left", fill="x", expand=True, padx=(0, 5))

        hint_button = ctk.CTkButton(button_frame, text="Hint",
                                    fg_color="transparent",
                                    hover_color=self.colors["card"],
                                    border_width=1,
                                    border_color=self.colors["primary"],
                                    height=36,
                                    command=self.show_password_hint)
        hint_button.pack(side="right", fill="x", expand=True, padx=(5, 0))

        # Bind Enter key to login button
        self.password_entry.bind("<Return>", lambda event: self.verify_master_password())

        # Version info at the bottom
        version_label = ctk.CTkLabel(login_frame, text="v1.0(beta)",
                                     font=ctk.CTkFont(size=10),
                                     text_color=self.colors["text_secondary"])
        version_label.pack(side="bottom", pady=10)

    def show_create_master_screen(self):
        """Display the screen to create a new master password"""
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create setup frame
        setup_frame = ctk.CTkFrame(self.root, fg_color=self.colors["bg"])
        setup_frame.pack(fill=tk.BOTH, expand=True)

        # Add logo/title
        title_label = ctk.CTkLabel(setup_frame, text="TechNovasafe",
                                   font=ctk.CTkFont(size=32, weight="bold"),
                                   text_color=self.colors["primary"])
        title_label.pack(pady=(80, 20))

        subtitle_label = ctk.CTkLabel(setup_frame, text="Create Your Master Password",
                                      font=ctk.CTkFont(size=14),
                                      text_color=self.colors["text_secondary"])
        subtitle_label.pack(pady=(0, 30))

        # Create setup form
        form_frame = ctk.CTkFrame(setup_frame, fg_color=self.colors["card"], corner_radius=10)
        form_frame.pack(padx=20, pady=20, ipadx=30, ipady=30)

        info_label = ctk.CTkLabel(form_frame,
                                  text="Your master password is the key to all your passwords.\nMake it strong and don't forget it!",
                                  font=ctk.CTkFont(size=12),
                                  text_color=self.colors["text_secondary"])
        info_label.pack(pady=(20, 25))

        password_label = ctk.CTkLabel(form_frame, text="Master Password",
                                      font=ctk.CTkFont(size=14),
                                      text_color=self.colors["text"])
        password_label.pack(anchor="w", padx=20, pady=(0, 5))

        self.new_password_entry = ctk.CTkEntry(form_frame, width=300, show="•",
                                               fg_color=self.colors["bg"],
                                               border_color=self.colors["primary"],
                                               text_color=self.colors["text"])
        self.new_password_entry.pack(padx=20, pady=(0, 15))

        confirm_label = ctk.CTkLabel(form_frame, text="Confirm Password",
                                     font=ctk.CTkFont(size=14),
                                     text_color=self.colors["text"])
        confirm_label.pack(anchor="w", padx=20, pady=(0, 5))

        self.confirm_password_entry = ctk.CTkEntry(form_frame, width=300, show="•",
                                                   fg_color=self.colors["bg"],
                                                   border_color=self.colors["primary"],
                                                   text_color=self.colors["text"])
        self.confirm_password_entry.pack(padx=20, pady=(0, 15))

        hint_label = ctk.CTkLabel(form_frame, text="Password Hint (Optional)",
                                  font=ctk.CTkFont(size=14),
                                  text_color=self.colors["text"])
        hint_label.pack(anchor="w", padx=20, pady=(0, 5))

        self.hint_entry = ctk.CTkEntry(form_frame, width=300,
                                       fg_color=self.colors["bg"],
                                       border_color=self.colors["primary"],
                                       text_color=self.colors["text"])
        self.hint_entry.pack(padx=20, pady=(0, 20))

        create_button = ctk.CTkButton(form_frame, text="Create Password",
                                      fg_color=self.colors["primary"],
                                      hover_color=self.colors["secondary"],
                                      height=36,
                                      command=self.create_master_password)
        create_button.pack(pady=10)

        # Focus on first entry
        self.new_password_entry.focus()

    def create_master_password(self):
        """Create a new master password"""
        password = self.new_password_entry.get()
        confirm = self.confirm_password_entry.get()
        hint = self.hint_entry.get()

        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # Check password strength
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return

        # Generate salt
        salt = os.urandom(16)

        # Hash the password
        password_hash = hashlib.sha256(password.encode() + salt).hexdigest()

        # Store in database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO master (salt, password_hash, hint) VALUES (?, ?, ?)",
                       (salt, password_hash, hint))
        conn.commit()
        conn.close()

        # Set up encryption
        self.master_key = password
        self.setup_encryption(salt, password)

        messagebox.showinfo("Success", "Master password created successfully")
        self.show_main_screen()

    def verify_master_password(self):
        """Verify the entered master password"""
        password = self.password_entry.get()

        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return

        # Get salt and hash from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT salt, password_hash FROM master")
        result = cursor.fetchone()
        conn.close()

        if not result:
            messagebox.showerror("Error", "Master password not found")
            return

        salt, stored_hash = result

        # Hash the entered password
        password_hash = hashlib.sha256(password.encode() + salt).hexdigest()

        # Compare hashes
        if password_hash == stored_hash:
            self.master_key = password
            self.setup_encryption(salt, password)
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Incorrect master password")

    def setup_encryption(self, salt, password):
        """Set up encryption with the master password"""
        # Generate a key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

    def show_password_hint(self):
        """Show the password hint if available"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT hint FROM master")
        hint = cursor.fetchone()[0]
        conn.close()

        if hint:
            messagebox.showinfo("Password Hint", hint)
        else:
            messagebox.showinfo("Password Hint", "No hint available")

    def show_main_screen(self):
        """Display the main application screen"""
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create main frame
        self.main_frame = ctk.CTkFrame(self.root, fg_color=self.colors["bg"])
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create header
        header_frame = ctk.CTkFrame(self.main_frame, fg_color=self.colors["primary"], height=60)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)

        title_label = ctk.CTkLabel(header_frame, text="TechNovasafe",
                                   font=ctk.CTkFont(size=18, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(side="left", padx=20)

        # Create logout button
        logout_button = ctk.CTkButton(header_frame, text="Logout",
                                      fg_color=self.colors["secondary"],
                                      hover_color="#4A148C",
                                      width=100,
                                      command=self.logout)
        logout_button.pack(side="right", padx=20)

        # Create main content frame with sidebar and content
        content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Create sidebar
        sidebar_frame = ctk.CTkFrame(content_frame, fg_color=self.colors["card"], width=200)
        sidebar_frame.pack(side="left", fill="y", padx=0, pady=0)
        sidebar_frame.pack_propagate(False)

        # Add sidebar buttons
        self.create_sidebar(sidebar_frame)

        # Create main content area
        self.password_frame = ctk.CTkFrame(content_frame, fg_color=self.colors["bg"])
        self.password_frame.pack(side="right", fill="both", expand=True, padx=0, pady=0)

        # Show the password list by default
        self.show_password_list()

    def logout(self):
        """Logs the user out and returns to the login screen"""
        confirm = messagebox.askyesno("Logout", "Are you sure you want to log out?")
        if confirm:
            self.master_key = None
            self.cipher_suite = None
            self.show_login_screen()

    def create_sidebar(self, sidebar_frame):
        """Create the sidebar with navigation buttons"""
        # Add some padding at the top
        padding = ctk.CTkFrame(sidebar_frame, fg_color="transparent", height=20)
        padding.pack()

        # Add buttons
        buttons = [
            ("All Passwords", self.show_password_list),
            ("Add New Password", self.show_add_password),
            ("Categories", self.show_categories),
            ("Password Generator", self.show_password_generator),
            ("Settings", self.show_settings)
        ]

        for text, command in buttons:
            btn = ctk.CTkButton(sidebar_frame, text=text,
                                fg_color="transparent",
                                hover_color=self.colors["primary"],
                                anchor="w",
                                height=40,
                                command=command)
            btn.pack(fill="x", padx=5, pady=2)

    def clear_password_frame(self):
        """Clear the main content area"""
        for widget in self.password_frame.winfo_children():
            widget.destroy()

    def show_password_list(self):
        """Display the list of saved passwords"""
        self.clear_password_frame()

        # Create toolbar
        toolbar = ctk.CTkFrame(self.password_frame, fg_color=self.colors["bg"])
        toolbar.pack(fill="x", padx=20, pady=20)

        title_label = ctk.CTkLabel(toolbar, text="All Passwords",
                                   font=ctk.CTkFont(size=20, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(side="left")

        add_button = ctk.CTkButton(toolbar, text="+ Add New",
                                   fg_color=self.colors["primary"],
                                   hover_color=self.colors["secondary"],
                                   command=self.show_add_password)
        add_button.pack(side="right")

        search_entry = ctk.CTkEntry(toolbar, width=200,
                                    placeholder_text="Search...",
                                    fg_color=self.colors["card"],
                                    text_color=self.colors["text"])
        search_entry.pack(side="right", padx=10)
        search_entry.bind("<KeyRelease>", self.search_passwords)

        # Create scrollable frame for passwords
        container = ctk.CTkFrame(self.password_frame, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.passwords_canvas = tk.Canvas(container, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.passwords_canvas.yview)
        self.passwords_list_frame = ctk.CTkFrame(self.passwords_canvas, fg_color="transparent")

        self.passwords_list_frame.bind(
            "<Configure>",
            lambda e: self.passwords_canvas.configure(scrollregion=self.passwords_canvas.bbox("all"))
        )

        self.passwords_canvas.create_window((0, 0), window=self.passwords_list_frame, anchor="nw")
        self.passwords_canvas.configure(yscrollcommand=scrollbar.set)

        self.passwords_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Load passwords
        self.load_passwords()

    def load_passwords(self, search_term=None):
        """Load passwords from the database"""
        # Clear the passwords list frame
        for widget in self.passwords_list_frame.winfo_children():
            widget.destroy()

        # Connect to database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Query passwords
        if search_term:
            cursor.execute("""
                SELECT id, title, username, password, url, category 
                FROM passwords 
                WHERE title LIKE ? OR username LIKE ? OR url LIKE ? OR category LIKE ?
                ORDER BY title
            """, (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        else:
            cursor.execute("""
                SELECT id, title, username, password, url, category 
                FROM passwords 
                ORDER BY title
            """)

        passwords = cursor.fetchall()
        conn.close()

        if not passwords:
            no_passwords_label = ctk.CTkLabel(self.passwords_list_frame,
                                              text="No passwords found",
                                              font=ctk.CTkFont(size=14),
                                              text_color=self.colors["text_secondary"])
            no_passwords_label.pack(pady=50)
            return

        # Display passwords
        for idx, (id, title, username, password, url, category) in enumerate(passwords):
            # Decrypt password
            try:
                decrypted_password = self.cipher_suite.decrypt(password.encode()).decode()
            except:
                decrypted_password = "**Error: Could not decrypt**"

            card = ctk.CTkFrame(self.passwords_list_frame, fg_color=self.colors["card"], corner_radius=8)
            card.pack(fill="x", pady=5, ipady=10, ipadx=10)

            title_frame = ctk.CTkFrame(card, fg_color="transparent")
            title_frame.pack(fill="x", padx=15, pady=(10, 5))

            title_label = ctk.CTkLabel(title_frame, text=title,
                                       font=ctk.CTkFont(size=14, weight="bold"),
                                       text_color=self.colors["text"])
            title_label.pack(side="left")

            if category:
                category_label = ctk.CTkLabel(title_frame, text=category,
                                              font=ctk.CTkFont(size=10),
                                              text_color=self.colors["primary"])
                category_label.pack(side="right")

            if username:
                username_label = ctk.CTkLabel(card, text=f"Username: {username}",
                                              font=ctk.CTkFont(size=12),
                                              text_color=self.colors["text_secondary"])
                username_label.pack(anchor="w", padx=15, pady=2)

            password_frame = ctk.CTkFrame(card, fg_color="transparent")
            password_frame.pack(fill="x", padx=15, pady=2)

            password_label = ctk.CTkLabel(password_frame, text="Password: ••••••••",
                                          font=ctk.CTkFont(size=12),
                                          text_color=self.colors["text_secondary"])
            password_label.pack(side="left")

            copy_button = ctk.CTkButton(password_frame, text="Copy",
                                        fg_color="transparent",
                                        hover_color=self.colors["secondary"],
                                        text_color=self.colors["primary"],
                                        width=60, height=24,
                                        command=lambda p=decrypted_password: self.copy_to_clipboard(p))
            copy_button.pack(side="right")

            show_button = ctk.CTkButton(password_frame, text="Show",
                                        fg_color="transparent",
                                        hover_color=self.colors["secondary"],
                                        text_color=self.colors["primary"],
                                        width=60, height=24,
                                        command=lambda l=password_label, p=decrypted_password:
                                        self.toggle_password_visibility(l, p))
            show_button.pack(side="right", padx=5)

            if url:
                url_label = ctk.CTkLabel(card, text=f"URL: {url}",
                                         font=ctk.CTkFont(size=12),
                                         text_color=self.colors["text_secondary"])
                url_label.pack(anchor="w", padx=15, pady=2)

            button_frame = ctk.CTkFrame(card, fg_color="transparent")
            button_frame.pack(fill="x", padx=15, pady=(10, 5))

            edit_button = ctk.CTkButton(button_frame, text="Edit",
                                        fg_color="transparent",
                                        hover_color=self.colors["secondary"],
                                        text_color=self.colors["primary"],
                                        border_width=1,
                                        border_color=self.colors["primary"],
                                        width=80, height=30,
                                        command=lambda id=id: self.edit_password(id))
            edit_button.pack(side="left")

            delete_button = ctk.CTkButton(button_frame, text="Delete",
                                          fg_color="transparent",
                                          hover_color="#D32F2F",
                                          text_color="#F44336",
                                          border_width=1,
                                          border_color="#F44336",
                                          width=80, height=30,
                                          command=lambda id=id, t=title: self.delete_password(id, t))
            delete_button.pack(side="right")

    def search_passwords(self, event):
        """Search passwords based on the search term"""
        search_term = event.widget.get()
        self.load_passwords(search_term)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        pyperclip.copy(text)
        messagebox.showinfo("Copied", "Password copied to clipboard")

    def toggle_password_visibility(self, label, password):
        """Toggle password visibility"""
        if label.cget("text") == "Password: ••••••••":
            label.configure(text=f"Password: {password}")
        else:
            label.configure(text="Password: ••••••••")

    def show_add_password(self):
        """Show form to add a new password"""
        self.clear_password_frame()

        # Create form
        form_frame = ctk.CTkFrame(self.password_frame, fg_color=self.colors["bg"])
        form_frame.pack(fill="both", expand=True, padx=40, pady=40)

        title_label = ctk.CTkLabel(form_frame, text="Add New Password",
                                   font=ctk.CTkFont(size=24, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(anchor="w", pady=(0, 20))

        # Create input fields
        fields = [
            ("Title", "title_entry"),
            ("Username", "username_entry"),
            ("Password", "password_entry"),
            ("URL", "url_entry"),
            ("Notes", "notes_entry")
        ]

        for label_text, attr_name in fields:
            label = ctk.CTkLabel(form_frame, text=label_text,
                                 font=ctk.CTkFont(size=14),
                                 text_color=self.colors["text"])
            label.pack(anchor="w", pady=(10, 5))

            if label_text == "Notes":
                entry = ctk.CTkTextbox(form_frame, height=100,
                                       fg_color=self.colors["card"],
                                       text_color=self.colors["text"])
                entry.pack(fill="x", pady=(0, 10))
            elif label_text == "Password":
                password_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
                password_frame.pack(fill="x", pady=(0, 10))

                entry = ctk.CTkEntry(password_frame,
                                     fg_color=self.colors["card"],
                                     text_color=self.colors["text"],
                                     show="•")
                entry.pack(side="left", fill="x", expand=True)

                generate_button = ctk.CTkButton(password_frame, text="Generate",
                                                fg_color=self.colors["primary"],
                                                hover_color=self.colors["secondary"],
                                                command=lambda: self.generate_and_insert_password(entry))
                generate_button.pack(side="right", padx=(10, 0))
            else:
                entry = ctk.CTkEntry(form_frame,
                                     fg_color=self.colors["card"],
                                     text_color=self.colors["text"])
                entry.pack(fill="x", pady=(0, 10))

            setattr(self, attr_name, entry)

        # Category dropdown
        category_label = ctk.CTkLabel(form_frame, text="Category",
                                      font=ctk.CTkFont(size=14),
                                      text_color=self.colors["text"])
        category_label.pack(anchor="w", pady=(10, 5))

        # Get categories from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM categories ORDER BY name")
        categories = [cat[0] for cat in cursor.fetchall()]
        conn.close()

        self.category_var = tk.StringVar(value=categories[0] if categories else "")
        category_menu = ctk.CTkOptionMenu(form_frame, values=categories,
                                          variable=self.category_var,
                                          fg_color=self.colors["card"],
                                          button_color=self.colors["primary"],
                                          button_hover_color=self.colors["secondary"],
                                          dropdown_fg_color=self.colors["card"])
        category_menu.pack(fill="x", pady=(0, 20))

        # Create buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=20)

        cancel_button = ctk.CTkButton(button_frame, text="Cancel",
                                      fg_color="transparent",
                                      hover_color=self.colors["card"],
                                      border_width=1,
                                      border_color=self.colors["primary"],
                                      command=self.show_password_list)
        cancel_button.pack(side="left", padx=(0, 10))

        save_button = ctk.CTkButton(button_frame, text="Save",
                                    fg_color=self.colors["primary"],
                                    hover_color=self.colors["secondary"],
                                    command=self.save_password)
        save_button.pack(side="right")

    def generate_and_insert_password(self, entry):
        """Generate a secure password and insert it into the entry field"""
        password = self.generate_password()

        # Prüfen, ob entry eine CTkTextbox ist
        if isinstance(entry, ctk.CTkTextbox):
            entry.delete("1.0", tk.END)
            entry.insert("1.0", password)
        else:
            entry.delete(0, tk.END)
            entry.insert(0, password)

    def save_password(self):
        """Save a new password to the database"""
        title = self.title_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        notes = self.notes_entry.get("1.0", tk.END).strip()
        category = self.category_var.get()

        # Validate input
        if not title:
            messagebox.showerror("Error", "Title is required")
            return

        if not password:
            messagebox.showerror("Error", "Password is required")
            return

        # Encrypt password
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

        # Get current datetime
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save to database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
                                                INSERT INTO passwords (title, username, password, url, notes, category, date_added, date_modified)
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                            """,
                       (title, username, encrypted_password, url, notes, category, current_datetime, current_datetime))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password saved successfully")
        self.show_password_list()

    def edit_password(self, password_id):
        """Edit an existing password"""
        # Get password details
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
                                                SELECT title, username, password, url, notes, category
                                                FROM passwords
                                                WHERE id = ?
                                            """, (password_id,))
        password_data = cursor.fetchone()
        conn.close()

        if not password_data:
            messagebox.showerror("Error", "Password not found")
            return

        title, username, encrypted_password, url, notes, category = password_data

        # Decrypt password
        try:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
        except:
            decrypted_password = ""

        # Show edit form
        self.show_add_password()

        # Set values
        self.title_entry.insert(0, title)
        if username:
            self.username_entry.insert(0, username)
        self.password_entry.insert(0, decrypted_password)
        if url:
            self.url_entry.insert(0, url)
        if notes:
            self.notes_entry.insert("1.0", notes)
        if category:
            self.category_var.set(category)

        # Update save button to update instead of create
        for widget in self.password_frame.winfo_children():
            if isinstance(widget, ctk.CTkFrame):
                for child in widget.winfo_children():
                    if isinstance(child, ctk.CTkFrame):
                        for btn in child.winfo_children():
                            if isinstance(btn, ctk.CTkButton) and btn.cget("text") == "Save":
                                btn.configure(command=lambda id=password_id: self.update_password(id))

    def update_password(self, password_id):
        """Update an existing password"""
        title = self.title_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        notes = self.notes_entry.get("1.0", tk.END).strip()
        category = self.category_var.get()

        # Validate input
        if not title:
            messagebox.showerror("Error", "Title is required")
            return

        if not password:
            messagebox.showerror("Error", "Password is required")
            return

        # Encrypt password
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

        # Get current datetime
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Update database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
                                                UPDATE passwords
                                                SET title = ?, username = ?, password = ?, url = ?, notes = ?, category = ?, date_modified = ?
                                                WHERE id = ?
                                            """,
                       (title, username, encrypted_password, url, notes, category, current_datetime, password_id))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password updated successfully")
        self.show_password_list()

    def delete_password(self, password_id, title):
        """Delete a password after confirmation"""
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete '{title}'?"
        )

        if confirm:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            conn.commit()
            conn.close()

            messagebox.showinfo("Success", "Password deleted successfully")
            self.show_password_list()

    def show_categories(self):
        """Show categories management screen"""
        self.clear_password_frame()

        # Create categories frame
        categories_frame = ctk.CTkFrame(self.password_frame, fg_color=self.colors["bg"])
        categories_frame.pack(fill="both", expand=True, padx=40, pady=40)

        title_label = ctk.CTkLabel(categories_frame, text="Manage Categories",
                                   font=ctk.CTkFont(size=24, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(anchor="w", pady=(0, 20))

        # Create form to add new category
        form_frame = ctk.CTkFrame(categories_frame, fg_color=self.colors["card"], corner_radius=10)
        form_frame.pack(fill="x", pady=10, ipady=15)

        form_title = ctk.CTkLabel(form_frame, text="Add New Category",
                                  font=ctk.CTkFont(size=16, weight="bold"),
                                  text_color=self.colors["text"])
        form_title.pack(anchor="w", padx=20, pady=(15, 10))

        input_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=20, pady=10)

        self.new_category_entry = ctk.CTkEntry(input_frame,
                                               placeholder_text="Category Name",
                                               fg_color=self.colors["bg"],
                                               text_color=self.colors["text"])
        self.new_category_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        add_button = ctk.CTkButton(input_frame, text="Add",
                                   fg_color=self.colors["primary"],
                                   hover_color=self.colors["secondary"],
                                   command=self.add_category)
        add_button.pack(side="right")

        # Display existing categories
        categories_list_frame = ctk.CTkFrame(categories_frame, fg_color=self.colors["card"], corner_radius=10)
        categories_list_frame.pack(fill="both", expand=True, pady=20)

        list_title = ctk.CTkLabel(categories_list_frame, text="Current Categories",
                                  font=ctk.CTkFont(size=16, weight="bold"),
                                  text_color=self.colors["text"])
        list_title.pack(anchor="w", padx=20, pady=(15, 10))

        # Get categories from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
                                                SELECT c.id, c.name, COUNT(p.id) as count
                                                FROM categories c
                                                LEFT JOIN passwords p ON c.name = p.category
                                                GROUP BY c.id, c.name
                                                ORDER BY c.name
                                            """)
        categories = cursor.fetchall()
        conn.close()

        if not categories:
            no_categories_label = ctk.CTkLabel(categories_list_frame,
                                               text="No categories found",
                                               font=ctk.CTkFont(size=14),
                                               text_color=self.colors["text_secondary"])
            no_categories_label.pack(pady=20)
        else:
            for category_id, name, count in categories:
                category_frame = ctk.CTkFrame(categories_list_frame, fg_color="transparent")
                category_frame.pack(fill="x", padx=20, pady=5)

                category_label = ctk.CTkLabel(category_frame, text=name,
                                              font=ctk.CTkFont(size=14),
                                              text_color=self.colors["text"])
                category_label.pack(side="left")

                count_label = ctk.CTkLabel(category_frame, text=f"{count} passwords",
                                           font=ctk.CTkFont(size=12),
                                           text_color=self.colors["text_secondary"])
                count_label.pack(side="left", padx=10)

                if count == 0:
                    delete_button = ctk.CTkButton(category_frame, text="Delete",
                                                  fg_color="transparent",
                                                  hover_color="#D32F2F",
                                                  text_color="#F44336",
                                                  border_width=1,
                                                  border_color="#F44336",
                                                  width=80, height=25,
                                                  command=lambda id=category_id, n=name: self.delete_category(id, n))
                    delete_button.pack(side="right")

                edit_button = ctk.CTkButton(category_frame, text="Edit",
                                            fg_color="transparent",
                                            hover_color=self.colors["secondary"],
                                            text_color=self.colors["primary"],
                                            border_width=1,
                                            border_color=self.colors["primary"],
                                            width=80, height=25,
                                            command=lambda id=category_id, n=name: self.edit_category(id, n))
                edit_button.pack(side="right", padx=5)

        # Add back button
        back_button = ctk.CTkButton(categories_frame, text="Back",
                                    fg_color="transparent",
                                    hover_color=self.colors["card"],
                                    border_width=1,
                                    border_color=self.colors["primary"],
                                    command=self.show_password_list)
        back_button.pack(anchor="w", pady=20)

    def add_category(self):
        """Add a new category"""
        category_name = self.new_category_entry.get()

        if not category_name:
            messagebox.showerror("Error", "Category name is required")
            return

        # Save to database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO categories (name) VALUES (?)", (category_name,))
            conn.commit()
            messagebox.showinfo("Success", "Category added successfully")
            self.new_category_entry.delete(0, tk.END)
            self.show_categories()  # Refresh the list
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", f"Category '{category_name}' already exists")
        finally:
            conn.close()

    def edit_category(self, category_id, current_name):
        """Edit a category name"""
        new_name = simpledialog.askstring("Edit Category", "Enter new category name:", initialvalue=current_name)

        if not new_name:
            return

        if new_name == current_name:
            return

        # Update database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            # Update category name
            cursor.execute("UPDATE categories SET name = ? WHERE id = ?", (new_name, category_id))

            # Update passwords with this category
            cursor.execute("UPDATE passwords SET category = ? WHERE category = ?", (new_name, current_name))

            conn.commit()
            messagebox.showinfo("Success", "Category updated successfully")
            self.show_categories()  # Refresh the list
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", f"Category '{new_name}' already exists")
        finally:
            conn.close()

    def delete_category(self, category_id, name):
        """Delete a category after confirmation"""
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the category '{name}'?"
        )

        if confirm:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
            conn.commit()
            conn.close()

            messagebox.showinfo("Success", "Category deleted successfully")
            self.show_categories()  # Refresh the list

    def show_password_generator(self):
        """Show password generator screen"""
        self.clear_password_frame()

        generator_frame = ctk.CTkFrame(self.password_frame, fg_color=self.colors["bg"])
        generator_frame.pack(fill="both", expand=True, padx=40, pady=40)

        title_label = ctk.CTkLabel(generator_frame, text="Password Generator",
                                   font=ctk.CTkFont(size=24, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(anchor="w", pady=(0, 20))

        # Create generator card
        card = ctk.CTkFrame(generator_frame, fg_color=self.colors["card"], corner_radius=10)
        card.pack(fill="x", pady=10, ipady=15)

        # Password display
        password_frame = ctk.CTkFrame(card, fg_color="transparent")
        password_frame.pack(fill="x", padx=20, pady=15)

        self.generated_password = ctk.CTkEntry(password_frame,
                                               fg_color=self.colors["bg"],
                                               text_color=self.colors["text"],
                                               font=ctk.CTkFont(size=16))
        self.generated_password.pack(side="left", fill="x", expand=True, padx=(0, 10))

        copy_button = ctk.CTkButton(password_frame, text="Copy",
                                    fg_color=self.colors["primary"],
                                    hover_color=self.colors["secondary"],
                                    command=lambda: self.copy_to_clipboard(self.generated_password.get()))
        copy_button.pack(side="right")

        # Options
        options_frame = ctk.CTkFrame(card, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=10)

        left_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        left_frame.pack(side="left", fill="y")

        right_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        right_frame.pack(side="right", fill="y", expand=True)

        # Length slider
        length_label = ctk.CTkLabel(left_frame, text="Password Length:",
                                    font=ctk.CTkFont(size=14),
                                    text_color=self.colors["text"])
        length_label.pack(anchor="w", pady=(0, 5))

        self.length_var = tk.IntVar(value=16)
        self.length_display = ctk.CTkLabel(left_frame, text="16 characters",
                                           font=ctk.CTkFont(size=12),
                                           text_color=self.colors["text_secondary"])
        self.length_display.pack(anchor="w", pady=(0, 10))

        length_slider = ctk.CTkSlider(left_frame, from_=8, to=64,
                                      number_of_steps=56,
                                      variable=self.length_var,
                                      command=self.update_length_display,
                                      progress_color=self.colors["primary"],
                                      button_color=self.colors["primary"],
                                      button_hover_color=self.colors["secondary"])
        length_slider.pack(fill="x", pady=(0, 20))

        # Checkboxes for character types
        self.use_uppercase_var = tk.BooleanVar(value=True)
        uppercase_check = ctk.CTkCheckBox(left_frame, text="Uppercase Letters (A-Z)",
                                          variable=self.use_uppercase_var,
                                          checkbox_width=20, checkbox_height=20,
                                          fg_color=self.colors["primary"],
                                          hover_color=self.colors["secondary"],
                                          text_color=self.colors["text"])
        uppercase_check.pack(anchor="w", pady=5)

        self.use_lowercase_var = tk.BooleanVar(value=True)
        lowercase_check = ctk.CTkCheckBox(left_frame, text="Lowercase Letters (a-z)",
                                          variable=self.use_lowercase_var,
                                          checkbox_width=20, checkbox_height=20,
                                          fg_color=self.colors["primary"],
                                          hover_color=self.colors["secondary"],
                                          text_color=self.colors["text"])
        lowercase_check.pack(anchor="w", pady=5)

        self.use_numbers_var = tk.BooleanVar(value=True)
        numbers_check = ctk.CTkCheckBox(left_frame, text="Numbers (0-9)",
                                        variable=self.use_numbers_var,
                                        checkbox_width=20, checkbox_height=20,
                                        fg_color=self.colors["primary"],
                                        hover_color=self.colors["secondary"],
                                        text_color=self.colors["text"])
        numbers_check.pack(anchor="w", pady=5)

        self.use_symbols_var = tk.BooleanVar(value=True)
        symbols_check = ctk.CTkCheckBox(left_frame, text="Special Characters (!@#$...)",
                                        variable=self.use_symbols_var,
                                        checkbox_width=20, checkbox_height=20,
                                        fg_color=self.colors["primary"],
                                        hover_color=self.colors["secondary"],
                                        text_color=self.colors["text"])
        symbols_check.pack(anchor="w", pady=5)

        # Generate button
        generate_button = ctk.CTkButton(options_frame, text="Generate Password",
                                        fg_color=self.colors["primary"],
                                        hover_color=self.colors["secondary"],
                                        height=40,
                                        command=self.regenerate_password)
        generate_button.pack(side="bottom", fill="x", pady=(20, 0))

        # Password strength meter
        strength_frame = ctk.CTkFrame(card, fg_color="transparent")
        strength_frame.pack(fill="x", padx=20, pady=(15, 10))

        strength_label = ctk.CTkLabel(strength_frame, text="Password Strength:",
                                      font=ctk.CTkFont(size=14),
                                      text_color=self.colors["text"])
        strength_label.pack(side="left")

        self.strength_meter = ctk.CTkLabel(strength_frame, text="Strong",
                                           font=ctk.CTkFont(size=14, weight="bold"),
                                           text_color="#4CAF50")
        self.strength_meter.pack(side="right")

        # Generate initial password
        self.regenerate_password()

        # Add back button
        back_button = ctk.CTkButton(generator_frame, text="Back",
                                    fg_color="transparent",
                                    hover_color=self.colors["card"],
                                    border_width=1,
                                    border_color=self.colors["primary"],
                                    command=self.show_password_list)
        back_button.pack(anchor="w", pady=20)

    def update_length_display(self, value):
        """Update the length display when slider moves"""
        length = int(value)
        self.length_display.configure(text=f"{length} characters")

    def regenerate_password(self):
        """Generate a new password based on the selected options"""
        length = self.length_var.get()
        use_upper = self.use_uppercase_var.get()
        use_lower = self.use_lowercase_var.get()
        use_numbers = self.use_numbers_var.get()
        use_symbols = self.use_symbols_var.get()

        # Ensure at least one option is selected
        if not any([use_upper, use_lower, use_numbers, use_symbols]):
            messagebox.showerror("Error", "Please select at least one character type")
            return

        password = self.generate_password(length, use_upper, use_lower, use_numbers, use_symbols)
        self.generated_password.delete(0, tk.END)
        self.generated_password.insert(0, password)

        # Update strength meter
        strength = self.check_password_strength(password)
        if strength == "strong":
            self.strength_meter.configure(text="Strong", text_color="#4CAF50")
        elif strength == "medium":
            self.strength_meter.configure(text="Medium", text_color="#FF9800")
        else:
            self.strength_meter.configure(text="Weak", text_color="#F44336")

    def generate_password(self, length=64, use_upper=True, use_lower=True, use_numbers=True, use_symbols=True):
        """Generate a secure random password"""
        # Define character sets
        uppercase = string.ascii_uppercase if use_upper else ""
        lowercase = string.ascii_lowercase if use_lower else ""
        numbers = string.digits if use_numbers else ""
        symbols = string.punctuation if use_symbols else ""

        # Combine all allowed characters
        all_chars = uppercase + lowercase + numbers + symbols

        if not all_chars:
            return ""

        # Ensure at least one character from each selected type
        password = []
        if use_upper:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_lower:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_numbers:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice(string.punctuation))

        # Fill the rest with random characters
        remaining_length = length - len(password)
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))

        # Shuffle the password
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def update_password_hint(self):
        """Update the master password hint"""
        new_hint = simpledialog.askstring("Update Hint", "Enter new password hint:")

        if new_hint is None:  # Falls der Benutzer abbricht
            return

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE master SET hint = ?", (new_hint,))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password hint updated successfully")

    def check_password_strength(self, password):
        """Check the strength of a password"""
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        variety = sum([has_upper, has_lower, has_digit, has_symbol])

        if length >= 12 and variety >= 3:
            return "strong"
        elif length >= 8 and variety >= 2:
            return "medium"
        else:
            return "weak"

    def show_settings(self):
        """Show settings screen"""
        self.clear_password_frame()

        settings_frame = ctk.CTkFrame(self.password_frame, fg_color=self.colors["bg"])
        settings_frame.pack(fill="both", expand=True, padx=40, pady=40)

        title_label = ctk.CTkLabel(settings_frame, text="Settings",
                                   font=ctk.CTkFont(size=24, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(anchor="w", pady=(0, 20))

        # Create settings cards
        password_card = ctk.CTkFrame(settings_frame, fg_color=self.colors["card"], corner_radius=10)
        password_card.pack(fill="x", pady=10, ipady=15)

        card_title = ctk.CTkLabel(password_card, text="Master Password",
                                  font=ctk.CTkFont(size=16, weight="bold"),
                                  text_color=self.colors["text"])
        card_title.pack(anchor="w", padx=20, pady=(15, 10))

        change_button = ctk.CTkButton(password_card, text="Change Master Password",
                                      fg_color=self.colors["primary"],
                                      hover_color=self.colors["secondary"],
                                      command=self.show_change_master_password)
        change_button.pack(padx=20, pady=10)

        hint_button = ctk.CTkButton(password_card, text="Update Password Hint",
                                    fg_color="transparent",
                                    hover_color=self.colors["secondary"],
                                    border_width=1,
                                    border_color=self.colors["primary"],
                                    command=self.update_password_hint)
        hint_button.pack(padx=20, pady=10)

        # Quiet Mode card
        quiet_mode_card = ctk.CTkFrame(settings_frame, fg_color=self.colors["card"], corner_radius=10)
        quiet_mode_card.pack(fill="x", pady=10, ipady=15)

        quiet_mode_title = ctk.CTkLabel(quiet_mode_card, text="Quiet Mode",
                                        font=ctk.CTkFont(size=16, weight="bold"),
                                        text_color=self.colors["text"])
        quiet_mode_title.pack(anchor="w", padx=20, pady=(15, 10))

        quiet_mode_frame = ctk.CTkFrame(quiet_mode_card, fg_color="transparent")
        quiet_mode_frame.pack(fill="x", padx=20, pady=10)

        quiet_mode_checkbox = ctk.CTkCheckBox(quiet_mode_frame, text="Enable Quiet Mode",
                                              variable=self.quiet_mode_var,
                                              checkbox_width=20, checkbox_height=20,
                                              fg_color=self.colors["primary"],
                                              hover_color=self.colors["secondary"],
                                              text_color=self.colors["text"],
                                              command=self.toggle_quiet_mode)
        quiet_mode_checkbox.pack(side="left")

        help_button = ctk.CTkButton(quiet_mode_frame, text="?",
                                    fg_color="transparent",
                                    hover_color=self.colors["secondary"],
                                    text_color=self.colors["primary"],
                                    width=30, height=30,
                                    command=self.show_quiet_mode_help)
        help_button.pack(side="left", padx=(10, 0))

        # About card
        about_card = ctk.CTkFrame(settings_frame, fg_color=self.colors["card"], corner_radius=10)
        about_card.pack(fill="x", pady=10, ipady=15)

        about_title = ctk.CTkLabel(about_card, text="About",
                                   font=ctk.CTkFont(size=16, weight="bold"),
                                   text_color=self.colors["text"])
        about_title.pack(anchor="w", padx=20, pady=(15, 5))

        # App name and version in prominent style
        app_name = ctk.CTkLabel(about_card,
                                text="TechNovasafe Password Manager",
                                font=ctk.CTkFont(size=14, weight="bold"),
                                text_color=self.colors["text"])
        app_name.pack(anchor="w", padx=20, pady=(5, 0))

        version = ctk.CTkLabel(about_card,
                               text="Version 1.0 (Beta)",
                               font=ctk.CTkFont(size=12),
                               text_color=self.colors["text_secondary"])
        version.pack(anchor="w", padx=20, pady=(0, 10))

        # Info section
        info_frame = ctk.CTkFrame(about_card, fg_color="transparent")
        info_frame.pack(fill="x", padx=20, pady=5)

        # Create two columns for information
        left_col = ctk.CTkFrame(info_frame, fg_color="transparent")
        left_col.pack(side="left", fill="y", padx=(0, 10))

        creator_label = ctk.CTkLabel(left_col, text="Creator:",
                                     font=ctk.CTkFont(size=12, weight="bold"),
                                     text_color=self.colors["text"])
        creator_label.pack(anchor="w", pady=2)

        lang_label = ctk.CTkLabel(left_col, text="Language:",
                                  font=ctk.CTkFont(size=12, weight="bold"),
                                  text_color=self.colors["text"])
        lang_label.pack(anchor="w", pady=2)

        license_label = ctk.CTkLabel(left_col, text="License:",
                                     font=ctk.CTkFont(size=12, weight="bold"),
                                     text_color=self.colors["text"])
        license_label.pack(anchor="w", pady=2)

        right_col = ctk.CTkFrame(info_frame, fg_color="transparent")
        right_col.pack(side="left", fill="y")

        creator_value = ctk.CTkLabel(right_col, text="TechNova Team / Sven Kunz",
                                     font=ctk.CTkFont(size=12),
                                     text_color=self.colors["text_secondary"])
        creator_value.pack(anchor="w", pady=2)

        lang_value = ctk.CTkLabel(right_col, text="Python",
                                  font=ctk.CTkFont(size=12),
                                  text_color=self.colors["text_secondary"])
        lang_value.pack(anchor="w", pady=2)

        license_value = ctk.CTkLabel(right_col, text="Quix17-Lizenz",
                                     font=ctk.CTkFont(size=12),
                                     text_color=self.colors["text_secondary"])
        license_value.pack(anchor="w", pady=2)

        # Contact section
        contact_frame = ctk.CTkFrame(about_card, fg_color="transparent")
        contact_frame.pack(fill="x", padx=20, pady=(10, 5))

        contact_title = ctk.CTkLabel(contact_frame, text="Contact",
                                     font=ctk.CTkFont(size=12, weight="bold"),
                                     text_color=self.colors["text"])
        contact_title.pack(anchor="w")

        contact_info = ctk.CTkLabel(contact_frame,
                                    text="support@technova.com • www.technova.com",
                                    font=ctk.CTkFont(size=12),
                                    text_color=self.colors["text_secondary"])
        contact_info.pack(anchor="w", pady=2)

        # Funktion zum Öffnen der GitHub-Seite
        def open_github():
            webbrowser.open("https://github.com/Quix17/Password-Manager")

        # Funktion zum Anzeigen des Lizenz-Fensters
        def show_license():
            license_window = ctk.CTkToplevel()
            license_window.title("License Agreement")
            license_window.geometry("600x400")
            license_window.resizable(True, True)

            # Stelle sicher, dass das Fenster im Vordergrund bleibt
            license_window.transient(about_card.winfo_toplevel())
            license_window.grab_set()

            # Lizenztext
            license_text = """
        **Quix17-Lizenz**

        Copyright (c) [2025] [TechNova / Sven Kunz]

        **Erlaubt:**
        ✅ Nutzung des Codes für private und kommerzielle Zwecke
        ✅ Änderung und Anpassung für eigene Projekte
        ✅ Integration in andere Software für persönlichen Gebrauch
        ✅ Verwendung zu Bildungszwecken

        **Nicht erlaubt ohne schriftliche Erlaubnis:**
        🚫 Weiterverbreitung des Codes (auch verändert)
        🚫 Verkauf oder kommerzielle Nutzung durch Dritte
        🚫 Entfernung von Copyright-Hinweisen
        🚫 Verwendung des Namens "TechNova" oder "Quix17" für abgeleitete Werke

        **Bedingungen:**
        1. Bei Verwendung des Codes muss ein Verweis auf den ursprünglichen Autor (Sven Kunz / Quix17) erhalten bleiben.
        2. Änderungen müssen dokumentiert werden.
        3. Bei Integration in eigene Projekte muss diese Lizenz beigefügt werden.

        **Haftungsausschluss:**
        DIESER CODE WIRD OHNE JEGLICHE GARANTIE BEREITGESTELLT. DER AUTOR IST NICHT HAFTBAR FÜR SCHÄDEN, DIE DURCH DIE NUTZUNG ENTSTEHEN. DER NUTZER TRÄGT DAS VOLLE RISIKO FÜR DIE VERWENDUNG DIESER SOFTWARE.

        **Kündigung:**
        Diese Lizenz erlischt automatisch, wenn eine der oben genannten Bedingungen nicht eingehalten wird.

        **Kontakt für Genehmigungen:**
        Anfragen zur kommerziellen Nutzung oder Weiterverbreitung richten Sie bitte an: support@technova.com
        """

            # Scrollbarer Textbereich für die Lizenz
            license_frame = ctk.CTkFrame(license_window)
            license_frame.pack(fill="both", expand=True, padx=20, pady=20)

            license_textbox = ctk.CTkTextbox(license_frame, wrap="word")
            license_textbox.pack(fill="both", expand=True)
            license_textbox.insert("1.0", license_text)
            license_textbox.configure(state="disabled")  # Schreibgeschützt machen

            # OK-Button zum Schließen
            ok_button = ctk.CTkButton(license_window, text="I Understand",
                                      command=license_window.destroy)
            ok_button.pack(pady=(0, 20))

        # Buttons frame für zwei Buttons nebeneinander
        buttons_frame = ctk.CTkFrame(about_card, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=20, pady=(10, 5))

        github_button = ctk.CTkButton(buttons_frame,
                                      text="View on GitHub",
                                      font=ctk.CTkFont(size=12),
                                      height=28,
                                      width=150,
                                      command=open_github)
        github_button.pack(side="left", padx=(0, 10))

        license_button = ctk.CTkButton(buttons_frame,
                                       text="View License",
                                       font=ctk.CTkFont(size=12),
                                       height=28,
                                       width=150,
                                       command=show_license)
        license_button.pack(side="left")

        # Copyright at bottom
        copyright = ctk.CTkLabel(about_card,
                                 text="© 2025 TechNova",
                                 font=ctk.CTkFont(size=11),
                                 text_color=self.colors["text_secondary"])
        copyright.pack(padx=20, pady=(5, 10))

        # Add back button
        back_button = ctk.CTkButton(settings_frame, text="Back",
                                    fg_color="transparent",
                                    hover_color=self.colors["card"],
                                    border_width=1,
                                    border_color=self.colors["primary"],
                                    command=self.show_password_list)
        back_button.pack(anchor="w", pady=20)

    def toggle_quiet_mode(self):
        """Enable or disable Quiet Mode."""
        if self.quiet_mode_var.get():
            self.hide_window()
        else:
            self.restore_window()

    def show_quiet_mode_help(self):
        """Show an explanation of Quiet Mode."""
        messagebox.showinfo("Quiet Mode",
                            "Quiet Mode minimizes the application to the system tray.\n"
                            "Use the shortcut Ctrl + Shift + Q to restore the window.")

    def show_change_master_password(self):
        """Show form to change master password"""
        self.clear_password_frame()

        form_frame = ctk.CTkFrame(self.password_frame, fg_color=self.colors["bg"])
        form_frame.pack(fill="both", expand=True, padx=40, pady=40)

        title_label = ctk.CTkLabel(form_frame, text="Change Master Password",
                                   font=ctk.CTkFont(size=24, weight="bold"),
                                   text_color=self.colors["text"])
        title_label.pack(anchor="w", pady=(0, 20))

        # Create form
        card = ctk.CTkFrame(form_frame, fg_color=self.colors["card"], corner_radius=10)
        card.pack(fill="x", pady=10, ipady=15)

        # Current password
        current_label = ctk.CTkLabel(card, text="Current Password",
                                     font=ctk.CTkFont(size=14),
                                     text_color=self.colors["text"])
        current_label.pack(anchor="w", padx=20, pady=(15, 5))

        self.current_password_entry = ctk.CTkEntry(card,
                                                   fg_color=self.colors["bg"],
                                                   text_color=self.colors["text"],
                                                   show="•")
        self.current_password_entry.pack(fill="x", padx=20, pady=(0, 15))

        # New password
        new_label = ctk.CTkLabel(card, text="New Password",
                                 font=ctk.CTkFont(size=14),
                                 text_color=self.colors["text"])
        new_label.pack(anchor="w", padx=20, pady=(0, 5))

        self.new_master_entry = ctk.CTkEntry(card,
                                             fg_color=self.colors["bg"],
                                             text_color=self.colors["text"],
                                             show="•")
        self.new_master_entry.pack(fill="x", padx=20, pady=(0, 15))

        # Confirm new password
        confirm_label = ctk.CTkLabel(card, text="Confirm New Password",
                                     font=ctk.CTkFont(size=14),
                                     text_color=self.colors["text"])
        confirm_label.pack(anchor="w", padx=20, pady=(0, 5))

        self.confirm_master_entry = ctk.CTkEntry(card,
                                                 fg_color=self.colors["bg"],
                                                 text_color=self.colors["text"],
                                                 show="•")
        self.confirm_master_entry.pack(fill="x", padx=20, pady=(0, 15))

        # New hint
        hint_label = ctk.CTkLabel(card, text="New Password Hint (Optional)",
                                  font=ctk.CTkFont(size=14),
                                  text_color=self.colors["text"])
        hint_label.pack(anchor="w", padx=20, pady=(0, 5))

        self.new_hint_entry = ctk.CTkEntry(card,
                                           fg_color=self.colors["bg"],
                                           text_color=self.colors["text"])
        self.new_hint_entry.pack(fill="x", padx=20, pady=(0, 15))

        # Save button
        save_button = ctk.CTkButton(card, text="Save Changes",
                                    fg_color=self.colors["primary"],
                                    hover_color=self.colors["secondary"],
                                    command=self.change_master_password)
        save_button.pack(padx=20, pady=20)

        # Back button
        back_button = ctk.CTkButton(card, text="Back",
                                    fg_color="transparent",
                                    hover_color=self.colors["card"],
                                    border_width=1,
                                    border_color=self.colors["primary"],
                                    command=self.show_password_list)
        back_button.pack(pady=10)

    def change_master_password(self):
        """Change the master password"""
        current_password = self.current_password_entry.get()
        new_password = self.new_master_entry.get()
        confirm_password = self.confirm_master_entry.get()
        new_hint = self.new_hint_entry.get()

        if not current_password or not new_password or not confirm_password:
            messagebox.showerror("Error", "All fields are required")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match")
            return

        if len(new_password) < 8:
            messagebox.showerror("Error", "New password must be at least 8 characters long")
            return

        # Fetch current master password hash and salt
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT salt, password_hash FROM master")
        result = cursor.fetchone()
        conn.close()

        if not result:
            messagebox.showerror("Error", "Master password not found")
            return

        salt, stored_hash = result
        current_password_hash = hashlib.sha256(current_password.encode() + salt).hexdigest()

        if current_password_hash != stored_hash:
            messagebox.showerror("Error", "Incorrect current password")
            return

        # Generate new salt and hash
        new_salt = os.urandom(16)
        new_password_hash = hashlib.sha256(new_password.encode() + new_salt).hexdigest()

        # Update the database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE master SET salt = ?, password_hash = ?, hint = ?",
                       (new_salt, new_password_hash, new_hint))
        conn.commit()
        conn.close()

        # Reset encryption
        self.master_key = new_password
        self.setup_encryption(new_salt, new_password)

        messagebox.showinfo("Success", "Master password changed successfully")
        self.show_password_list()

    def setup_tray_icon(self):
        """Set up the system tray icon."""
        # Create an icon image
        icon_image = Image.new("RGB", (64, 64), color=(0, 0, 0))
        draw = ImageDraw.Draw(icon_image)
        draw.rectangle([16, 16, 48, 48], fill=(156, 39, 176))  # Purple square

        # Define tray menu
        menu = (
            item("Show TechNovasafe", self.restore_window),
            item("Exit", self.exit_application),
        )

        # Create the tray icon
        self.tray_icon = pystray.Icon("TechNovasafe", icon_image, "TechNovasafe", menu)

    def bind_shortcuts(self):
        """Bind global keyboard shortcuts."""
        keyboard.add_hotkey("ctrl+shift+q", self.restore_window)

    def hide_window(self):
        """Hide the main window and minimize to tray."""
        self.root.withdraw()  # Hide the window
        if not self.tray_icon.visible:
            self.tray_icon.run_detached()  # Show the tray icon

    def restore_window(self):
        """Restore the main window from the tray."""
        if self.tray_icon.visible:
            self.tray_icon.stop()  # Hide the tray icon
        self.root.deiconify()  # Show the window

    def exit_application(self):
        """Exit the application."""
        if self.tray_icon.visible:
            self.tray_icon.stop()
        self.root.quit()


if __name__ == "__main__":
    app = TechNovasafe()
    app.root.protocol("WM_DELETE_WINDOW", app.hide_window)  # Override close button behavior
    app.root.mainloop()
