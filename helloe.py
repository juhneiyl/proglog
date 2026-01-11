import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import sqlite3
import hashlib
import secrets
import csv
import json
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import re

DB_FILE = "tpop_favorites.db"

# limit window size
# segment the classes

class DatabaseManager:
    
    @staticmethod
    def create_connection():
        return sqlite3.connect(DB_FILE)
    
    @staticmethod
    def initialize_database():
        with DatabaseManager.create_connection() as conn:
            cur = conn.cursor()
          
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS artists (
                    artist_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artist_name TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS favorites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    artist_id INTEGER,
                    fav_group TEXT NOT NULL,
                    bias TEXT NOT NULL,
                    bias_wrecker TEXT NOT NULL,
                    song_count INTEGER NOT NULL,
                    fav_song TEXT NOT NULL,
                    fav_album TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    FOREIGN KEY (artist_id) REFERENCES artists(artist_id)
                )
            """)
            conn.commit()
            
            cur.execute("CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_favorites_artist ON favorites(artist_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id)")
            
            conn.commit()
    
    @staticmethod
    def log_activity(user_id, action, details=""):
        """Log user activity"""
        try:
            with DatabaseManager.create_connection() as conn:
                conn.execute(
                    "INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
                    (user_id, action, details)
                )
                conn.commit()
        except Exception as e:
            print(f"Error logging activity: {e}")



class AuthManager:
    """Handles user authentication and session management"""
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return pwd_hash.hex(), salt
    
    @staticmethod
    def verify_password(password, stored_hash, salt):
        """Verify password against stored hash"""
        pwd_hash, _ = AuthManager.hash_password(password, salt)
        return pwd_hash == stored_hash
    
    @staticmethod
    def create_user(username, password, role='user'):
        """Create a new user"""
        try:
            pwd_hash, salt = AuthManager.hash_password(password)
            with DatabaseManager.create_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                    (username, pwd_hash, salt, role)
                )
                conn.commit()
            return True, "User created successfully"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, f"Error creating user: {e}"
    
    @staticmethod
    def authenticate(username, password):
        """Authenticate user credentials"""
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT user_id, password_hash, salt, role, is_active FROM users WHERE username = ?",
                    (username,)
                )
                result = cur.fetchone()
                
                if not result:
                    return None, "Invalid username or password"
                
                user_id, pwd_hash, salt, role, is_active = result
                
                if not is_active:
                    return None, "Account is deactivated"
                
                if AuthManager.verify_password(password, pwd_hash, salt):
                 
                    conn.execute(
                        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?",
                        (user_id,)
                    )
                    conn.commit()
                    return {'user_id': user_id, 'username': username, 'role': role}, None
                else:
                    return None, "Invalid username or password"
        except Exception as e:
            return None, f"Authentication error: {e}"

class LoginWindow:
    """Login and registration interface"""
    
    def __init__(self, root, on_login_success):
        self.root = root
        self.on_login_success = on_login_success
        self.root.title("T-pop Favorites - Login")
        self.root.geometry("450x550")
        self.root.resizable(False, False)
        
        
        self.center_window()
        
        self.create_widgets()
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create login interface"""
        # Header
        header = tk.Frame(self.root, bg='#465187', height=80)
        header.pack(fill='x')
        
        tk.Label(
            header,
            text="T-pop Favorites System",
            font=('Arial', 22, 'bold'),
            bg='#465187',
            fg='white'
        ).pack(pady=20)
        
        
        main_frame = tk.Frame(self.root, bg='#a37dc2')
        main_frame.pack(fill='both', expand=True, padx=40, pady=30)
        
        
        login_frame = tk.LabelFrame(
            main_frame,
            text="Login",
            font=('Arial', 14, 'bold'),
            bg='#a37dc2',
            fg='white',
            padx=20,
            pady=20
        )
        login_frame.pack(fill='both', expand=True)
        
        
        tk.Label(login_frame, text="Username:", bg='#a37dc2', fg='white', font=('Arial', 11)).grid(row=0, column=0, sticky='w', pady=10)
        self.username_var = tk.StringVar()
        username_entry = tk.Entry(login_frame, textvariable=self.username_var, font=('Arial', 11), width=25)
        username_entry.grid(row=0, column=1, pady=10, padx=10)
        username_entry.focus()
        
        
        tk.Label(login_frame, text="Password:", bg='#a37dc2', fg='white', font=('Arial', 11)).grid(row=1, column=0, sticky='w', pady=10)
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(login_frame, textvariable=self.password_var, show='●', font=('Arial', 11), width=25)
        password_entry.grid(row=1, column=1, pady=10, padx=10)
        
        
        password_entry.bind('<Return>', lambda e: self.login())
        username_entry.bind('<Return>', lambda e: password_entry.focus())
        
        
        btn_frame = tk.Frame(login_frame, bg='#a37dc2')
        btn_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        tk.Button(
            btn_frame,
            text="Login",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            fg='black',
            width=12,
            command=self.login
        ).pack(side='left', padx=5)
        
        tk.Button(
            btn_frame,
            text="Register",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            fg='black',
            width=12,
            command=self.show_register
        ).pack(side='left', padx=5)
        
        
        self.info_label = tk.Label(
            main_frame,
            text="",
            bg='#a37dc2',
            fg='white',
            font=('Arial', 9)
        )
        self.info_label.pack(pady=10)
    
    def login(self):
        """Handle login"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter username and password")
            return
        
        user, error = AuthManager.authenticate(username, password)
        
        if user:
            DatabaseManager.log_activity(user['user_id'], "LOGIN", f"User {username} logged in")
            self.on_login_success(user)
        else:
            messagebox.showerror("Login Failed", error)
            self.password_var.set("")
    
    def show_register(self):
        """Show registration dialog"""
        RegisterDialog(self.root)
        
class RegisterDialog:
    """User registration dialog"""
    
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Register New User")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
        

        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Create registration form"""
        frame = tk.Frame(self.dialog, bg='#a37dc2', padx=30, pady=20)
        frame.pack(fill='both', expand=True)
        
        tk.Label(frame, text="Create New Account", font=('Arial', 14, 'bold'), bg='#a37dc2', fg='white').grid(row=0, column=0, columnspan=2, pady=15)
        
        
        tk.Label(frame, text="Username:", bg='#a37dc2', fg='white', font=('Arial', 10)).grid(row=1, column=0, sticky='w', pady=8)
        self.username_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.username_var, font=('Arial', 10), width=20).grid(row=1, column=1, pady=8, padx=5)
        
        
        tk.Label(frame, text="Password:", bg='#a37dc2', fg='white', font=('Arial', 10)).grid(row=2, column=0, sticky='w', pady=8)
        self.password_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.password_var, show='●', font=('Arial', 10), width=20).grid(row=2, column=1, pady=8, padx=5)
        
        
        tk.Label(frame, text="Confirm:", bg='#a37dc2', fg='white', font=('Arial', 10)).grid(row=3, column=0, sticky='w', pady=8)
        self.confirm_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.confirm_var, show='●', font=('Arial', 10), width=20).grid(row=3, column=1, pady=8, padx=5)
        
        
        btn_frame = tk.Frame(frame, bg='#a37dc2')
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        tk.Button(
            btn_frame,
            text="Register",
            font=('Arial', 10, 'bold'),
            bg='#c2a3db',
            width=10,
            command=self.register
        ).pack(side='left', padx=5)
        
        tk.Button(
            btn_frame,
            text="Cancel",
            font=('Arial', 10, 'bold'),
            bg='#c2a3db',
            width=10,
            command=self.dialog.destroy
        ).pack(side='left', padx=5)
    
    def register(self):
        """Handle user registration"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        confirm = self.confirm_var.get()
        
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please fill all fields")
            return
        
        if len(username) < 3:
            messagebox.showwarning("Invalid Username", "Username must be at least 3 characters")
            return
        
        if len(password) < 6:
            messagebox.showwarning("Weak Password", "Password must be at least 6 characters")
            return
        
        if password != confirm:
            messagebox.showwarning("Password Mismatch", "Passwords do not match")
            return
        
        
        success, message = AuthManager.create_user(username, password)
        
        if success:
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
            self.dialog.destroy()
        else:
            messagebox.showerror("Registration Failed", message)


class TPopFavoritesSystem:
    """Main application window with all features"""
    
    def __init__(self, root, user):
        self.root = root
        self.user = user
        self.root.title(f"T-pop Favorites Record System - Welcome {user['username']}")
        self.root.geometry("1400x800")
        self.root.resizable(True, True)
        
        self.colors = {
            'header': '#465187',
            'bg_white': '#a37dc2',
            'btn': '#c2a3db',
            'status_bg': '#465187',
            'status_fg': 'white'
        }
        
        self.selected_id = None
        self.create_menu()
        self.create_widgets()
        self.refresh_table()
        
  
        self.root.bind('<Control-n>', lambda e: self.add_entry())
        self.root.bind('<Control-s>', lambda e: self.update_entry())
        self.root.bind('<Delete>', lambda e: self.delete_entry())
        self.root.bind('<F5>', lambda e: self.refresh_table())
        self.root.bind('<Control-f>', lambda e: self.focus_search())
        self.root.bind('<Control-e>', lambda e: self.export_data())
        
        
        DatabaseManager.log_activity(self.user['user_id'], "APP_START", "Application opened")
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Entry (Ctrl+N)", command=self.add_entry)
        file_menu.add_separator()
        # file_menu.add_command(label="Import CSV", command=self.import_csv)
        file_menu.add_command(label="Export CSV (Ctrl+E)", command=self.export_data)
        #file_menu.add_command(label="Export JSON", command=self.export_json)
        file_menu.add_separator()
        #file_menu.add_command(label="Backup Database", command=self.backup_database)
        file_menu.add_separator()
        # file_menu.add_command(label="Logout", command=self.logout)
        # file_menu.add_command(label="Exit", command=self.root.quit)
        
        
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh (F5)", command=self.refresh_table)
        # view_menu.add_command(label="Analytics Dashboard", command=self.show_analytics)
        # view_menu.add_command(label="Activity Log", command=self.show_activity_log)
        
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Advanced Search", command=self.advanced_search)
        # tools_menu.add_command(label="Generate Report", command=self.generate_report)
        # tools_menu.add_command(label="Statistics", command=self.show_statistics)
        
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        # help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        # help_menu.add_command(label="About", command=self.show_about)

    
    def create_widgets(self):
        """Create main interface"""
        
        header_frame = tk.Frame(self.root, bg=self.colors['header'], height=60)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="T-pop Favorites Record System",
            font=('Arial', 20, 'bold'),
            bg=self.colors['header'],
            fg='white'
        ).pack(side='left', padx=20, pady=15)
        
        tk.Label(
            header_frame,
            text=f"{self.user['username']} ({self.user['role'].upper()})",
            font=('Arial', 11),
            bg=self.colors['header'],
            fg='white'
        ).pack(side='right', padx=20)
        
        
        input_frame = tk.LabelFrame(
            self.root,
            text=" Entry Details ",
            font=('Arial', 12, 'bold'),
            bg=self.colors['bg_white'],
            fg='white',
            pady=15,
            padx=10
        )
        input_frame.pack(fill='x', padx=20, pady=15)
        
        for i in range(6):
            input_frame.columnconfigure(i, weight=1)
        
       
        self.name_var = tk.StringVar()
        self.group_var = tk.StringVar()
        self.bias_var = tk.StringVar()
        self.wrecker_var = tk.StringVar()
        self.song_count_var = tk.StringVar()
        self.song_var = tk.StringVar()
        self.album_var = tk.StringVar()
        
        
        self.create_input_field(input_frame, "Your name:", self.name_var, 0, 0, "Enter your name")
        self.create_input_field(input_frame, "Favorite Group/Artist:", self.group_var, 0, 2, "Your favorite T-pop group")
        self.create_input_field(input_frame, "Your bias:", self.bias_var, 1, 0, "Your favorite member")
        self.create_input_field(input_frame, "Bias wrecker:", self.wrecker_var, 1, 2, "Member who challenges your bias")
        self.create_input_field(input_frame, "Song count:", self.song_count_var, 2, 0, "Number of songs you know")
        self.create_input_field(input_frame, "Favorite song:", self.song_var, 2, 2, "Your favorite song")
        self.create_input_field(input_frame, "Favorite album:", self.album_var, 3, 0, "Your favorite album")
        
       
        button_frame = tk.Frame(self.root, bg='#465187', pady=10)
        button_frame.pack(fill='x', padx=20)
        
        buttons = [
            ("Add Entry", self.add_entry, "Ctrl+N"),
            ("Update Entry", self.update_entry, "Ctrl+S"),
            ("Delete Entry", self.delete_entry, "Del"),
            ("View All", self.refresh_table, "F5"),
            ("Clear Fields", self.clear_fields, "Esc")
        ]
        
        for i, (text, cmd, shortcut) in enumerate(buttons):
            btn = tk.Button(
                button_frame,
                text=text,
                font=('Arial', 10, 'bold'),
                bg=self.colors['btn'],
                fg='black',
                width=15,
                command=cmd,
                cursor='hand2'
            )
            btn.grid(row=0, column=i, padx=5)
            self.create_tooltip(btn, shortcut)
        
       
        search_frame = tk.Frame(self.root, bg=self.colors['bg_white'], pady=8)
        search_frame.pack(fill='x', padx=20)
        
        tk.Label(search_frame, text="Search:", bg=self.colors['bg_white'], fg='white', font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.filter_table())
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, font=('Arial', 10), width=40)
        search_entry.pack(side='left', padx=5)
        
        tk.Label(search_frame, text="Filter by:", bg=self.colors['bg_white'], fg='white', font=('Arial', 10)).pack(side='left', padx=10)
        
        self.filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(
            search_frame,
            textvariable=self.filter_var,
            values=["All", "Name", "Group", "Bias", "Song"],
            state='readonly',
            width=10,
            font=('Arial', 9)
        )
        filter_combo.pack(side='left', padx=5)
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_table())
        
        tk.Button(
            search_frame,
            text="Advanced Search",
            font=('Arial', 9, 'bold'),
            bg=self.colors['btn'],
            command=self.advanced_search
        ).pack(side='left', padx=10)
        
       
        table_container = tk.Frame(self.root, bg=self.colors['bg_white'])
        table_container.pack(fill='both', expand=True, padx=20, pady=(5, 10))
        
       
        vsb = ttk.Scrollbar(table_container, orient="vertical")
        hsb = ttk.Scrollbar(table_container, orient="horizontal")
        
        
        self.tree = ttk.Treeview(
            table_container,
            columns=("ID", "Name", "Group", "Bias", "Wrecker", "Songs", "Songs count", "Song", "Album"),
            show='headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        
        columns_config = {
            "ID": 50,
            "Name": 120,
            "Group": 150,
            "Bias": 120,
            "Wrecker": 120,
            "Songs": 80,
            "Songs count": 100,
            "Song": 150,
            "Album": 150
        }
        
        for col, width in columns_config.items():
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=width, anchor='center' if col in ["ID", "Songs", "Songs count"] else 'w')
        
      
        vsb.pack(side='right', fill='y')
        hsb.pack(side='bottom', fill='x')
        self.tree.pack(fill='both', expand=True)
        
        
        self.tree.bind("<<TreeviewSelect>>", self.select_row)
        self.tree.bind("<Double-1>", lambda e: self.update_entry())
        
        
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Edit", command=self.update_entry)
        self.context_menu.add_command(label="Delete", command=self.delete_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="View Details", command=self.view_details)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        
        status_frame = tk.Frame(self.root, bg=self.colors['status_bg'], height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            status_frame,
            text=f"Ready | Database: {DB_FILE} | Total Records: 0",
            bg=self.colors['status_bg'],
            fg=self.colors['status_fg'],
            font=('Arial', 9)
        )
        self.status_label.pack(side='left', padx=10)
        
        self.time_label = tk.Label(
            status_frame,
            text="",
            bg=self.colors['status_bg'],
            fg=self.colors['status_fg'],
            font=('Arial', 9)
        )
        self.time_label.pack(side='right', padx=10)
        self.update_time()
        
        
        self.root.bind('<Escape>', lambda e: self.clear_fields())
    
    def create_input_field(self, parent, label, var, r, c, tooltip=""):
        """Create labeled input field with tooltip"""
        lbl = tk.Label(parent, text=label, bg='#a37dc2', fg='white', font=('Arial', 10, 'bold'))
        lbl.grid(row=r, column=c, sticky='w', padx=5, pady=5)
        
        entry = tk.Entry(parent, textvariable=var, font=('Arial', 10), width=22)
        entry.grid(row=r, column=c + 1, sticky='ew', padx=5, pady=5)
        
        if tooltip:
            self.create_tooltip(entry, tooltip)
        
        return entry
    
    def create_tooltip(self, widget, text):
        """Create tooltip for widget"""
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            label = tk.Label(tooltip, text=text, background="lightyellow", relief='solid', borderwidth=1, font=('Arial', 8))
            label.pack()
            widget.tooltip = tooltip
        
        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                del widget.tooltip
        
        widget.bind('<Enter>', on_enter)
        widget.bind('<Leave>', on_leave)
    
    def update_time(self):
        """Update status bar time"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=now)
        self.root.after(1000, self.update_time)
    
    def refresh_table(self, query=None):
        """Refresh table with current data"""
        self.tree.delete(*self.tree.get_children())
        
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                
                if query:
                    cur.execute(query)
                else:
                    cur.execute("""
                        SELECT id, name, fav_group, bias, bias_wrecker, 
                               song_count, fav_song, fav_album
                        FROM favorites 
                        WHERE user_id = ?
                        ORDER BY id DESC
                    """, (self.user['user_id'],))
                
                rows = cur.fetchall()
                
                for row in rows:
                    # Add Songs column with emoji
                    display_row = list(row)
                    display_row.insert(5, "🎵" * min(int(row[5]), 10))  # Visual song count
                    self.tree.insert("", "end", values=display_row)
                
                # Update status
                self.status_label.config(text=f"Ready | Database: {DB_FILE} | Total Records: {len(rows)}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load data: {e}")
    
    def filter_table(self):
        """Filter table based on search input"""
        search_text = self.search_var.get().strip().lower()
        filter_by = self.filter_var.get()
        
        if not search_text:
            self.refresh_table()
            return
        
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                
                if filter_by == "All":
                    query = """
                        SELECT id, name, fav_group, bias, bias_wrecker, 
                               song_count, fav_song, fav_album
                        FROM favorites 
                        WHERE user_id = ? AND (
                            LOWER(name) LIKE ? OR
                            LOWER(fav_group) LIKE ? OR
                            LOWER(bias) LIKE ? OR
                            LOWER(fav_song) LIKE ?
                        )
                        ORDER BY id DESC
                    """
                    params = (self.user['user_id'], f'%{search_text}%', f'%{search_text}%', 
                             f'%{search_text}%', f'%{search_text}%')
                elif filter_by == "Name":
                    query = """
                        SELECT id, name, fav_group, bias, bias_wrecker, 
                               song_count, fav_song, fav_album
                        FROM favorites 
                        WHERE user_id = ? AND LOWER(name) LIKE ?
                        ORDER BY id DESC
                    """
                    params = (self.user['user_id'], f'%{search_text}%')
                elif filter_by == "Group":
                    query = """
                        SELECT id, name, fav_group, bias, bias_wrecker, 
                               song_count, fav_song, fav_album
                        FROM favorites 
                        WHERE user_id = ? AND LOWER(fav_group) LIKE ?
                        ORDER BY id DESC
                    """
                    params = (self.user['user_id'], f'%{search_text}%')
                elif filter_by == "Bias":
                    query = """
                        SELECT id, name, fav_group, bias, bias_wrecker, 
                               song_count, fav_song, fav_album
                        FROM favorites 
                        WHERE user_id = ? AND LOWER(bias) LIKE ?
                        ORDER BY id DESC
                    """
                    params = (self.user['user_id'], f'%{search_text}%')
                else: 
                    query = """
                        SELECT id, name, fav_group, bias, bias_wrecker, 
                               song_count, fav_song, fav_album
                        FROM favorites 
                        WHERE user_id = ? AND LOWER(fav_song) LIKE ?
                        ORDER BY id DESC
                    """
                    params = (self.user['user_id'], f'%{search_text}%')
                
                cur.execute(query, params)
                self.tree.delete(*self.tree.get_children())
                
                rows = cur.fetchall()
                for row in rows:
                    display_row = list(row)
                    display_row.insert(5, "🎵" * min(int(row[5]), 10))
                    self.tree.insert("", "end", values=display_row)
                
                self.status_label.config(text=f"Search Results: {len(rows)} found")
        
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {e}")
    
    def sort_column(self, col):
        """Sort table by column"""
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
        
        try:
            items.sort(key=lambda x: int(x[0]) if x[0].isdigit() else x[0].lower())
        except:
            items.sort(key=lambda x: x[0].lower() if isinstance(x[0], str) else x[0])
        
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
    
    def clear_fields(self):
        """Clear all input fields"""
        self.selected_id = None
        for var in (self.name_var, self.group_var, self.bias_var,
                    self.wrecker_var, self.song_count_var,
                    self.song_var, self.album_var):
            var.set("")
        self.status_label.config(text="Fields cleared")
    
    def select_row(self, event):
        """Handle row selection"""
        sel = self.tree.selection()
        if not sel:
            return
        
        vals = self.tree.item(sel[0], "values")
        self.selected_id = vals[0]
        self.name_var.set(vals[1])
        self.group_var.set(vals[2])
        self.bias_var.set(vals[3])
        self.wrecker_var.set(vals[4])
        self.song_count_var.set(vals[6])  # Skip visual column
        self.song_var.set(vals[7])
        self.album_var.set(vals[8])
    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def validate_inputs(self):
        """Validate all input fields"""
        errors = []
        
        if not self.name_var.get().strip():
            errors.append("Name is required")
        
        if not self.group_var.get().strip():
            errors.append("Favorite Group/Artist is required")
        
        if not self.bias_var.get().strip():
            errors.append("Bias is required")
        
        if not self.wrecker_var.get().strip():
            errors.append("Bias wrecker is required")
        
        try:
            count = int(self.song_count_var.get())
            if count < 0:
                errors.append("Song count must be positive")
        except ValueError:
            errors.append("Song count must be a valid number")
        
        if not self.song_var.get().strip():
            errors.append("Favorite song is required")
        
        if not self.album_var.get().strip():
            errors.append("Favorite album is required")
        
        return errors
    
    def add_entry(self):
        """Add new entry with validation"""
        errors = self.validate_inputs()
        
        if errors:
            messagebox.showwarning("Validation Error", "\n".join(errors))
            return
        
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                
                
                artist_name = self.group_var.get().strip()
                cur.execute("INSERT OR IGNORE INTO artists (artist_name) VALUES (?)", (artist_name,))
                cur.execute("SELECT artist_id FROM artists WHERE artist_name = ?", (artist_name,))
                artist_id = cur.fetchone()[0]
                
                
                cur.execute("""
                    INSERT INTO favorites
                    (user_id, name, artist_id, fav_group, bias, bias_wrecker, 
                     song_count, fav_song, fav_album)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.user['user_id'],
                    self.name_var.get().strip(),
                    artist_id,
                    self.group_var.get().strip(),
                    self.bias_var.get().strip(),
                    self.wrecker_var.get().strip(),
                    int(self.song_count_var.get()),
                    self.song_var.get().strip(),
                    self.album_var.get().strip()
                ))
                
                conn.commit()
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "ADD_ENTRY",
                f"Added entry for {self.group_var.get()}"
            )
            
            messagebox.showinfo("Success", "Entry added successfully!")
            self.clear_fields()
            self.refresh_table()
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add entry: {e}")
    
    def update_entry(self):
        """Update existing entry"""
        if not self.selected_id:
            messagebox.showwarning("Selection Required", "Please select a record to update")
            return
        
        errors = self.validate_inputs()
        if errors:
            messagebox.showwarning("Validation Error", "\n".join(errors))
            return
        
        confirm = messagebox.askyesno(
            "Confirm Update",
            "Are you sure you want to update this entry?"
        )
        
        if not confirm:
            return
        
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                
                
                artist_name = self.group_var.get().strip()
                cur.execute("INSERT OR IGNORE INTO artists (artist_name) VALUES (?)", (artist_name,))
                cur.execute("SELECT artist_id FROM artists WHERE artist_name = ?", (artist_name,))
                artist_id = cur.fetchone()[0]
                
                
                cur.execute("""
                    UPDATE favorites SET
                        name=?, artist_id=?, fav_group=?, bias=?, bias_wrecker=?,
                        song_count=?, fav_song=?, fav_album=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id=? AND user_id=?
                """, (
                    self.name_var.get().strip(),
                    artist_id,
                    self.group_var.get().strip(),
                    self.bias_var.get().strip(),
                    self.wrecker_var.get().strip(),
                    int(self.song_count_var.get()),
                    self.song_var.get().strip(),
                    self.album_var.get().strip(),
                    self.selected_id,
                    self.user['user_id']
                ))
                
                conn.commit()
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "UPDATE_ENTRY",
                f"Updated entry ID {self.selected_id}"
            )
            
            messagebox.showinfo("Success", "Entry updated successfully!")
            self.clear_fields()
            self.refresh_table()
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update entry: {e}")
    
    def delete_entry(self):
        """Delete selected entry"""
        if not self.selected_id:
            messagebox.showwarning("Selection Required", "Please select a record to delete")
            return
        
        confirm = messagebox.askyesno(
            "Confirm Delete",
            "Are you sure you want to delete this entry?\n\nThis action cannot be undone."
        )
        
        if not confirm:
            return
        
        try:
            with DatabaseManager.create_connection() as conn:
                conn.execute(
                    "DELETE FROM favorites WHERE id=? AND user_id=?",
                    (self.selected_id, self.user['user_id'])
                )
                conn.commit()
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "DELETE_ENTRY",
                f"Deleted entry ID {self.selected_id}"
            )
            
            messagebox.showinfo("Success", "Entry deleted successfully!")
            self.clear_fields()
            self.refresh_table()
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {e}")
    
    def focus_search(self):
        """Focus on search box"""
        self.search_var.set("")

        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Entry) and child.cget('textvariable') == str(self.search_var):
                        child.focus()
                        return
    
    def view_details(self):
        """Show detailed view of selected entry"""
        if not self.selected_id:
            messagebox.showwarning("Selection Required", "Please select a record first")
            return
        
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT f.*, a.artist_name,
                           datetime(f.created_at) as created,
                           datetime(f.updated_at) as updated
                    FROM favorites f
                    LEFT JOIN artists a ON f.artist_id = a.artist_id
                    WHERE f.id = ? AND f.user_id = ?
                """, (self.selected_id, self.user['user_id']))
                
                row = cur.fetchone()
                
                if row:
                    details = f"""
 Entry Details
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ID: {row[0]}
Name: {row[2]}
Favorite Group/Artist: {row[4]}
Bias: {row[5]}
Bias Wrecker: {row[6]}
Song Count: {row[7]}
Favorite Song: {row[8]}
Favorite Album: {row[9]}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Created: {row[11]}
Last Updated: {row[12]}
                    """
                    
                    messagebox.showinfo("Entry Details", details)
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load details: {e}")
    
    def advanced_search(self):
        """Show advanced search dialog"""
        AdvancedSearchDialog(self.root, self.user, self)
    
    def export_data(self):
        """Export data to CSV"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"tpop_favorites_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            if not filename:
                return
            
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, name, fav_group, bias, bias_wrecker,
                           song_count, fav_song, fav_album,
                           datetime(created_at), datetime(updated_at)
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY id
                """, (self.user['user_id'],))
                
                rows = cur.fetchall()
                
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Name', 'Group', 'Bias', 'Wrecker', 
                                   'Song Count', 'Favorite Song', 'Favorite Album',
                                   'Created', 'Updated'])
                    writer.writerows(rows)
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "EXPORT_CSV",
                f"Exported {len(rows)} records to CSV"
            )
            
            messagebox.showinfo("Success", f"Exported {len(rows)} records to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")



class StatisticsWindow:
    """Detailed statistics and calculations"""
    
    def __init__(self, parent, user):
        self.user = user
        
        self.window = tk.Toplevel(parent)
        self.window.title("Statistics & Analytics")
        self.window.geometry("700x600")
        self.window.resizable(False, False)
        
        self.create_widgets()
        self.calculate_statistics()
    
    def create_widgets(self):
        """Create statistics interface"""

        header = tk.Frame(self.window, bg='#465187', height=60)
        header.pack(fill='x')
        
        tk.Label(
            header,
            text= "Detailed Statistics",
            font=('Arial', 18, 'bold'),
            bg='#465187',
            fg='white'
        ).pack(pady=15)
        

        self.stats_text = tk.Text(
            self.window,
            font=('Courier', 10),
            bg='#f5f5f5',
            wrap='word',
            padx=20,
            pady=20
        )
        self.stats_text.pack(fill='both', expand=True, padx=10, pady=10)
    
    def calculate_statistics(self):
        """Calculate and display statistics"""
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                
                # Basic stats
                cur.execute("""
                    SELECT 
                        COUNT(*) as total,
                        COUNT(DISTINCT fav_group) as groups,
                        COUNT(DISTINCT bias) as biases,
                        SUM(song_count) as total_songs,
                        AVG(song_count) as avg_songs,
                        MAX(song_count) as max_songs,
                        MIN(song_count) as min_songs
                    FROM favorites
                    WHERE user_id = ?
                """, (self.user['user_id'],))
                
                basic = cur.fetchone()
                

                cur.execute("""
                    SELECT fav_group, COUNT(*) as cnt
                    FROM favorites
                    WHERE user_id = ?
                    GROUP BY fav_group
                    ORDER BY cnt DESC
                    LIMIT 1
                """, (self.user['user_id'],))
                
                top_group = cur.fetchone()
                

                cur.execute("""
                    SELECT bias, COUNT(*) as cnt
                    FROM favorites
                    WHERE user_id = ?
                    GROUP BY bias
                    ORDER BY cnt DESC
                    LIMIT 1
                """, (self.user['user_id'],))
                
                top_bias = cur.fetchone()
                

                cur.execute("""
                    SELECT bias_wrecker, COUNT(*) as cnt
                    FROM favorites
                    WHERE user_id = ?
                    GROUP BY bias_wrecker
                    ORDER BY cnt DESC
                    LIMIT 1
                """, (self.user['user_id'],))
                
                top_wrecker = cur.fetchone()
                

                cur.execute("""
                    SELECT name, fav_group, song_count
                    FROM favorites
                    WHERE user_id = ? AND song_count = ?
                    LIMIT 1
                """, (self.user['user_id'], basic[5]))
                
                max_entry = cur.fetchone()
                
                stats_content = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    COMPREHENSIVE STATISTICS                      ║
╠══════════════════════════════════════════════════════════════════╣

 GENERAL STATISTICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Total Entries:                    {basic[0]:>10}
  Unique Groups/Artists:            {basic[1]:>10}
  Unique Bias Members:              {basic[2]:>10}
  
 SONG STATISTICS  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Total Songs Known:                {basic[3]:>10}
  Average Songs per Entry:          {basic[4]:>10.2f}
  Maximum Songs (Single Entry):     {basic[5]:>10}
  Minimum Songs (Single Entry):     {basic[6]:>10}
  
 TOP FAVORITES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Most Frequent Group:
    » {top_group[0] if top_group else 'N/A'}
    ({top_group[1] if top_group else 0} entries)
  
  Most Frequent Bias:
    » {top_bias[0] if top_bias else 'N/A'}
    ({top_bias[1] if top_bias else 0} times)
  
  Most Frequent Bias Wrecker:
    » {top_wrecker[0] if top_wrecker else 'N/A'}
    ({top_wrecker[1] if top_wrecker else 0} times)
  
 HIGHLIGHTED ENTRY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Entry with Most Songs Known:
    Name: {max_entry[0] if max_entry else 'N/A'}
    Group: {max_entry[1] if max_entry else 'N/A'}
    Songs: {max_entry[2] if max_entry else 0}
  
╚══════════════════════════════════════════════════════════════════╝

 Analysis Summary:
You're tracking favorites across {basic[1]} different groups/artists with
a total knowledge of {basic[3]} songs. Your collection shows strong
preference for {top_group[0] if top_group else 'various groups'}, and
{top_bias[0] if top_bias else 'your bias'} appears most frequently in your
favorites. Keep building your T-pop collection.
                """
                
                self.stats_text.insert('1.0', stats_content)
                self.stats_text.config(state='disabled')
        
        except Exception as e:
            self.stats_text.insert('1.0', f"Error calculating statistics: {e}")
            self.stats_text.config(state='disabled')



class ReportGenerator:
    """Generate comprehensive reports"""
    
    def __init__(self, parent, user):
        self.user = user
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Report Generator")
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create report generator interface"""
        frame = tk.Frame(self.dialog, bg='#a37dc2', padx=30, pady=30)
        frame.pack(fill='both', expand=True)
        
        tk.Label(
            frame,
            text="📄 Generate Report",
            font=('Arial', 16, 'bold'),
            bg='#a37dc2',
            fg='white'
        ).pack(pady=15)
        
        tk.Label(
            frame,
            text="Select report type:",
            font=('Arial', 11),
            bg='#a37dc2',
            fg='white'
        ).pack(pady=10)
        
        self.report_type = tk.StringVar(value="summary")
        
        reports = [
            ("summary", "Summary Report - Overview of all favorites"),
            ("detailed", "Detailed Report - Complete listing with all fields"),
            ("groups", "Groups Report - Organized by artist/group"),
            ("statistics", "Statistics Report - Analytics and insights")
        ]
        
        for value, text in reports:
            tk.Radiobutton(
                frame,
                text=text,
                variable=self.report_type,
                value=value,
                font=('Arial', 10),
                bg='#a37dc2',
                fg='white',
                selectcolor='#465187',
                activebackground='#a37dc2',
                activeforeground='white'
            ).pack(anchor='w', pady=5, padx=20)
        
        tk.Label(
            frame,
            text="Report format:",
            font=('Arial', 11),
            bg='#a37dc2',
            fg='white'
        ).pack(pady=10)
        
        self.format_var = tk.StringVar(value="txt")
        
        format_frame = tk.Frame(frame, bg='#a37dc2')
        format_frame.pack()
        
        tk.Radiobutton(
            format_frame,
            text="Text File (.txt)",
            variable=self.format_var,
            value="txt",
            font=('Arial', 10),
            bg='#a37dc2',
            fg='white',
            selectcolor='#465187'
        ).pack(side='left', padx=10)
        
        tk.Radiobutton(
            format_frame,
            text="HTML (.html)",
            variable=self.format_var,
            value="html",
            font=('Arial', 10),
            bg='#a37dc2',
            fg='white',
            selectcolor='#465187'
        ).pack(side='left', padx=10)
        

        btn_frame = tk.Frame(frame, bg='#a37dc2')
        btn_frame.pack(pady=20)
        
        tk.Button(
            btn_frame,
            text="Generate",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            width=12,
            command=self.generate_report
        ).pack(side='left', padx=5)
        
        tk.Button(
            btn_frame,
            text="Cancel",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            width=12,
            command=self.dialog.destroy
        ).pack(side='left', padx=5)
    
    def generate_report(self):
        """Generate selected report"""
        report_type = self.report_type.get()
        format_type = self.format_var.get()
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=[(f"{format_type.upper()} files", f"*.{format_type}")],
            initialfile=f"tpop_report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type}"
        )
        
        if not filename:
            return
        
        try:
            if format_type == "txt":
                content = self.generate_text_report(report_type)
            else:
                content = self.generate_html_report(report_type)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "GENERATE_REPORT",
                f"Generated {report_type} report in {format_type} format"
            )
            
            messagebox.showinfo("Success", f"Report generated successfully!\n\n{filename}")
            self.dialog.destroy()
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")
    
    def generate_text_report(self, report_type):
        """Generate text format report"""
        with DatabaseManager.create_connection() as conn:
            cur = conn.cursor()
            
            header = f"""
╔═══════════════════════════════════════════════════════════════════╗
║              T-POP FAVORITES REPORT                               ║
║              {report_type.upper()} REPORT                                        ║
╠═══════════════════════════════════════════════════════════════════╣
║  User: {self.user['username']:<56} ║
║  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<48} ║
╚═══════════════════════════════════════════════════════════════════╝

"""
            
            if report_type == "summary":
                cur.execute("""
                    SELECT COUNT(*), COUNT(DISTINCT fav_group), SUM(song_count)
                    FROM favorites
                    WHERE user_id = ?
                """, (self.user['user_id'],))
                
                total, groups, songs = cur.fetchone()
                
                content = header + f"""
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Entries: {total}
Unique Groups/Artists: {groups}
Total Songs Known: {songs}

TOP GROUPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
                
                cur.execute("""
                    SELECT fav_group, COUNT(*) as cnt
                    FROM favorites
                    WHERE user_id = ?
                    GROUP BY fav_group
                    ORDER BY cnt DESC
                    LIMIT 10
                """, (self.user['user_id'],))
                
                for i, (group, count) in enumerate(cur.fetchall(), 1):
                    content += f"\n{i}. {group} ({count} entries)"
            
            elif report_type == "detailed":
                cur.execute("""
                    SELECT name, fav_group, bias, bias_wrecker, song_count, fav_song, fav_album
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY fav_group, name
                """, (self.user['user_id'],))
                
                content = header + "DETAILED LISTING\n" + "═" * 70 + "\n\n"
                
                for i, row in enumerate(cur.fetchall(), 1):
                    content += f"""
Entry #{i}
{'─' * 70}
Name:           {row[0]}
Group/Artist:   {row[1]}
Bias:           {row[2]}
Bias Wrecker:   {row[3]}
Song Count:     {row[4]}
Favorite Song:  {row[5]}
Favorite Album: {row[6]}

"""
            
            elif report_type == "groups":
                cur.execute("""
                    SELECT DISTINCT fav_group
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY fav_group
                """, (self.user['user_id'],))
                
                content = header + "ORGANIZED BY GROUP/ARTIST\n" + "═" * 70 + "\n\n"
                
                for (group,) in cur.fetchall():
                    content += f"\n{'═' * 70}\n{group}\n{'═' * 70}\n\n"
                    
                    cur.execute("""
                        SELECT name, bias, song_count, fav_song
                        FROM favorites
                        WHERE user_id = ? AND fav_group = ?
                        ORDER BY name
                    """, (self.user['user_id'], group))
                    
                    for name, bias, count, song in cur.fetchall():
                        content += f"  • {name}\n"
                        content += f"    Bias: {bias} | Songs: {count} | Fav: {song}\n\n"
            
            else:  
                cur.execute("""
                    SELECT 
                        COUNT(*),
                        COUNT(DISTINCT fav_group),
                        AVG(song_count),
                        MAX(song_count),
                        MIN(song_count)
                    FROM favorites
                    WHERE user_id = ?
                """, (self.user['user_id'],))
                
                stats = cur.fetchone()
                
                content = header + f"""
STATISTICS & ANALYTICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Entries:          {stats[0]}
Unique Groups:          {stats[1]}
Average Song Count:     {stats[2]:.2f}
Maximum Song Count:     {stats[3]}
Minimum Song Count:     {stats[4]}

DISTRIBUTION ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
                
                cur.execute("""
                    SELECT fav_group, COUNT(*) as cnt
                    FROM favorites
                    WHERE user_id = ?
                    GROUP BY fav_group
                    ORDER BY cnt DESC
                """, (self.user['user_id'],))
                
                for group, count in cur.fetchall():
                    percentage = (count / stats[0]) * 100
                    bar = "█" * int(percentage / 2)
                    content += f"\n{group:<30} {bar} {percentage:.1f}%"
            
            return content
    
    def generate_html_report(self, report_type):
        """Generate HTML format report"""
        with DatabaseManager.create_connection() as conn:
            cur = conn.cursor()
            
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>T-pop Favorites Report - {report_type.upper()}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{
            color: #465187;
            text-align: center;
            border-bottom: 3px solid #a37dc2;
            padding-bottom: 15px;
        }}
        .info {{
            background: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background: #465187;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .entry {{
            background: #f9f9f9;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #a37dc2;
            border-radius: 5px;
        }}
        .group-header {{
            background: #465187;
            color: white;
            padding: 10px;
            margin: 20px 0 10px 0;
            border-radius: 5px;
        }}
        .stat-box {{
            display: inline-block;
            background: #c2a3db;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: #465187;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1> T-pop Favorites Report</h1>
        <div class="info">
            <strong>Report Type:</strong> {report_type.upper()}<br>
            <strong>User:</strong> {self.user['username']}<br>
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
"""
            
            if report_type == "summary":
                cur.execute("""
                    SELECT COUNT(*), COUNT(DISTINCT fav_group), SUM(song_count)
                    FROM favorites
                    WHERE user_id = ?
                """, (self.user['user_id'],))
                
                total, groups, songs = cur.fetchone()
                
                html += f"""
        <h2>Summary Statistics</h2>
        <div style="text-align: center;">
            <div class="stat-box">
                <div class="stat-number">{total}</div>
                <div class="stat-label">Total Entries</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{groups}</div>
                <div class="stat-label">Unique Groups</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{songs}</div>
                <div class="stat-label">Total Songs</div>
            </div>
        </div>
        
        <h2>Top Groups/Artists</h2>
        <table>
            <tr>
                <th>Rank</th>
                <th>Group/Artist</th>
                <th>Entries</th>
            </tr>
"""
                
                cur.execute("""
                    SELECT fav_group, COUNT(*) as cnt
                    FROM favorites
                    WHERE user_id = ?
                    GROUP BY fav_group
                    ORDER BY cnt DESC
                    LIMIT 10
                """, (self.user['user_id'],))
                
                for i, (group, count) in enumerate(cur.fetchall(), 1):
                    html += f"""
            <tr>
                <td>{i}</td>
                <td>{group}</td>
                <td>{count}</td>
            </tr>
"""
                
                html += "        </table>"
            
            elif report_type == "detailed":
                cur.execute("""
                    SELECT name, fav_group, bias, bias_wrecker, song_count, fav_song, fav_album
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY fav_group, name
                """, (self.user['user_id'],))
                
                html += "<h2>Detailed Listing</h2>"
                
                for i, row in enumerate(cur.fetchall(), 1):
                    html += f"""
        <div class="entry">
            <h3>Entry #{i}: {row[0]}</h3>
            <strong>Group/Artist:</strong> {row[1]}<br>
            <strong>Bias:</strong> {row[2]}<br>
            <strong>Bias Wrecker:</strong> {row[3]}<br>
            <strong>Song Count:</strong> {row[4]}<br>
            <strong>Favorite Song:</strong> {row[5]}<br>
            <strong>Favorite Album:</strong> {row[6]}
        </div>
"""
            
            elif report_type == "groups":
                cur.execute("""
                    SELECT DISTINCT fav_group
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY fav_group
                """, (self.user['user_id'],))
                
                html += "<h2>Organized by Group/Artist</h2>"
                
                for (group,) in cur.fetchall():
                    html += f'<div class="group-header"><h3>{group}</h3></div>'
                    
                    cur.execute("""
                        SELECT name, bias, song_count, fav_song
                        FROM favorites
                        WHERE user_id = ? AND fav_group = ?
                        ORDER BY name
                    """, (self.user['user_id'], group))
                    
                    html += "<table><tr><th>Name</th><th>Bias</th><th>Songs</th><th>Favorite Song</th></tr>"
                    
                    for name, bias, count, song in cur.fetchall():
                        html += f"<tr><td>{name}</td><td>{bias}</td><td>{count}</td><td>{song}</td></tr>"
                    
                    html += "</table>"
            
            html += """
    </div>
</body>
</html>
"""
            
            return html



def main():
    """Main application entry point"""

    DatabaseManager.initialize_database()
    

    try:
        with DatabaseManager.create_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] == 0:
                AuthManager.create_user("admin", "admin123", "admin")
                print("Default admin user created: admin/admin123")
    except Exception as e:
        print(f"Error checking users: {e}")
    

    root = tk.Tk()
    
    def on_login_success(user):
        """Handle successful login"""
        root.destroy()
        

        main_root = tk.Tk()
        app = TPopFavoritesSystem(main_root, user)
        

        def on_closing():
            if messagebox.askokcancel("Quit", "Do you want to quit?"):
                DatabaseManager.log_activity(
                    user['user_id'],
                    "APP_CLOSE",
                    "Application closed"
                )
                main_root.destroy()
        
        main_root.protocol("WM_DELETE_WINDOW", on_closing)
        main_root.mainloop()
    
    LoginWindow(root, on_login_success)
    root.mainloop()


if __name__ == "__main__":
    main()

    
    def export_json(self):
        """Export data to JSON"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=f"tpop_favorites_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            
            if not filename:
                return
            
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, name, fav_group, bias, bias_wrecker,
                           song_count, fav_song, fav_album,
                           datetime(created_at), datetime(updated_at)
                    FROM favorites
                    WHERE user_id = ?
                    ORDER BY id
                """, (self.user['user_id'],))
                
                columns = ['id', 'name', 'group', 'bias', 'wrecker',
                          'song_count', 'favorite_song', 'favorite_album',
                          'created_at', 'updated_at']
                
                rows = [dict(zip(columns, row)) for row in cur.fetchall()]
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'export_date': datetime.now().isoformat(),
                        'user': self.user['username'],
                        'total_records': len(rows),
                        'data': rows
                    }, f, indent=2, ensure_ascii=False)
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "EXPORT_JSON",
                f"Exported {len(rows)} records to JSON"
            )
            
            messagebox.showinfo("Success", f"Exported {len(rows)} records to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
    
    def import_csv(self):
        """Import data from CSV"""
        filename = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            imported = 0
            errors = []
            
            with open(filename, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                with DatabaseManager.create_connection() as conn:
                    for row_num, row in enumerate(reader, start=2):
                        try:

                            required = ['Name', 'Group', 'Bias', 'Wrecker', 'Song Count', 'Favorite Song', 'Favorite Album']
                            if not all(row.get(field) for field in required):
                                errors.append(f"Row {row_num}: Missing required fields")
                                continue
                            

                            cur = conn.cursor()
                            artist_name = row['Group'].strip()
                            cur.execute("INSERT OR IGNORE INTO artists (artist_name) VALUES (?)", (artist_name,))
                            cur.execute("SELECT artist_id FROM artists WHERE artist_name = ?", (artist_name,))
                            artist_id = cur.fetchone()[0]
                            

                            conn.execute("""
                                INSERT INTO favorites
                                (user_id, name, artist_id, fav_group, bias, bias_wrecker,
                                 song_count, fav_song, fav_album)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                self.user['user_id'],
                                row['Name'].strip(),
                                artist_id,
                                row['Group'].strip(),
                                row['Bias'].strip(),
                                row['Wrecker'].strip(),
                                int(row['Song Count']),
                                row['Favorite Song'].strip(),
                                row['Favorite Album'].strip()
                            ))
                            
                            imported += 1
                        
                        except Exception as e:
                            errors.append(f"Row {row_num}: {str(e)}")
                    
                    conn.commit()
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "IMPORT_CSV",
                f"Imported {imported} records from CSV"
            )
            
            msg = f"Successfully imported {imported} records"
            if errors:
                msg += f"\n\nErrors ({len(errors)}):\n" + "\n".join(errors[:5])
                if len(errors) > 5:
                    msg += f"\n... and {len(errors) - 5} more"
            
            messagebox.showinfo("Import Complete", msg)
            self.refresh_table()
        
        except Exception as e:
            messagebox.showerror("Error", f"Import failed: {e}")
    
    def backup_database(self):
        """Create database backup"""
        try:
            import shutil
            
            backup_file = filedialog.asksaveasfilename(
                defaultextension=".db",
                filetypes=[("Database files", "*.db"), ("All files", "*.*")],
                initialfile=f"tpop_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            )
            
            if not backup_file:
                return
            
            shutil.copy2(DB_FILE, backup_file)
            
            DatabaseManager.log_activity(
                self.user['user_id'],
                "DATABASE_BACKUP",
                f"Created backup: {backup_file}"
            )
            
            messagebox.showinfo("Success", f"Database backed up to:\n{backup_file}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {e}")
    
    def show_analytics(self):
        """Show analytics dashboard with charts"""
        AnalyticsDashboard(self.root, self.user)
    
    def show_activity_log(self):
        """Show user activity log"""
        ActivityLogWindow(self.root, self.user)
    
    def show_statistics(self):
        """Show statistics window"""
        StatisticsWindow(self.root, self.user)
    
    def generate_report(self):
        """Generate comprehensive report"""
        ReportGenerator(self.root, self.user)
    
    def show_shortcuts(self):
        """Show keyboard shortcuts help"""
        shortcuts = """
 Keyboard Shortcuts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ctrl+N     -  Add new entry
Ctrl+S     -  Update selected entry
Delete     -  Delete selected entry
F5         -  Refresh table
Ctrl+F     -  Focus search box
Ctrl+E     -  Export data to CSV
Esc        -  Clear all fields
Double-Click - Edit selected entry

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
 T-pop Favorites Record System
        """
        messagebox.showinfo("About", about_text)
    
    def logout(self):
        """Logout and return to login screen"""
        confirm = messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?")
        
        if confirm:
            DatabaseManager.log_activity(
                self.user['user_id'],
                "LOGOUT",
                f"User {self.user['username']} logged out"
            )
            self.root.destroy()



class AdvancedSearchDialog:
    """Advanced search with multiple criteria"""
    
    def __init__(self, parent, user, main_app):
        self.user = user
        self.main_app = main_app
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Advanced Search")
        self.dialog.geometry("600x500")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create search form"""
        frame = tk.Frame(self.dialog, bg='#a37dc2', padx=20, pady=20)
        frame.pack(fill='both', expand=True)
        
        tk.Label(
            frame,
            text=" Advanced Search",
            font=('Arial', 16, 'bold'),
            bg='#a37dc2',
            fg='white'
        ).pack(pady=10)
        

        criteria_frame = tk.LabelFrame(frame, text=" Search Criteria ", bg='#a37dc2', fg='white', font=('Arial', 11, 'bold'), padx=15, pady=15)
        criteria_frame.pack(fill='both', expand=True, pady=10)
        
        self.name_var = tk.StringVar()
        self.group_var = tk.StringVar()
        self.bias_var = tk.StringVar()
        self.song_var = tk.StringVar()
        self.min_count_var = tk.StringVar()
        self.max_count_var = tk.StringVar()
        
        fields = [
            ("Name contains:", self.name_var),
            ("Group contains:", self.group_var),
            ("Bias contains:", self.bias_var),
            ("Song contains:", self.song_var),
            ("Min song count:", self.min_count_var),
            ("Max song count:", self.max_count_var)
        ]
        
        for i, (label, var) in enumerate(fields):
            tk.Label(criteria_frame, text=label, bg='#a37dc2', fg='white', font=('Arial', 10)).grid(row=i, column=0, sticky='w', pady=8)
            tk.Entry(criteria_frame, textvariable=var, font=('Arial', 10), width=30).grid(row=i, column=1, pady=8, padx=10)
        

        btn_frame = tk.Frame(frame, bg='#a37dc2')
        btn_frame.pack(pady=15)
        
        tk.Button(
            btn_frame,
            text="Search",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            width=12,
            command=self.perform_search
        ).pack(side='left', padx=5)
        
        tk.Button(
            btn_frame,
            text="Clear",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            width=12,
            command=self.clear_search
        ).pack(side='left', padx=5)
        
        tk.Button(
            btn_frame,
            text="Close",
            font=('Arial', 11, 'bold'),
            bg='#c2a3db',
            width=12,
            command=self.dialog.destroy
        ).pack(side='left', padx=5)
    
    def perform_search(self):
        """Perform advanced search"""
        conditions = []
        params = [self.user['user_id']]
        
        if self.name_var.get().strip():
            conditions.append("LOWER(name) LIKE ?")
            params.append(f"%{self.name_var.get().strip().lower()}%")
        
        if self.group_var.get().strip():
            conditions.append("LOWER(fav_group) LIKE ?")
            params.append(f"%{self.group_var.get().strip().lower()}%")
        
        if self.bias_var.get().strip():
            conditions.append("LOWER(bias) LIKE ?")
            params.append(f"%{self.bias_var.get().strip().lower()}%")
        
        if self.song_var.get().strip():
            conditions.append("LOWER(fav_song) LIKE ?")
            params.append(f"%{self.song_var.get().strip().lower()}%")
        
        if self.min_count_var.get().strip():
            try:
                conditions.append("song_count >= ?")
                params.append(int(self.min_count_var.get()))
            except ValueError:
                pass
        
        if self.max_count_var.get().strip():
            try:
                conditions.append("song_count <= ?")
                params.append(int(self.max_count_var.get()))
            except ValueError:
                pass
        
        if not conditions:
            messagebox.showwarning("No Criteria", "Please enter at least one search criterion")
            return
        
        try:
            with DatabaseManager.create_connection() as conn:
                query = f"""
                    SELECT id, name, fav_group, bias, bias_wrecker,
                           song_count, fav_song, fav_album
                    FROM favorites
                    WHERE user_id = ? AND {' AND '.join(conditions)}
                    ORDER BY id DESC
                """
                
                cur = conn.cursor()
                cur.execute(query, params)
                
                self.main_app.tree.delete(*self.main_app.tree.get_children())
                
                rows = cur.fetchall()
                for row in rows:
                    display_row = list(row)
                    display_row.insert(5, "🎵" * min(int(row[5]), 10))
                    self.main_app.tree.insert("", "end", values=display_row)
                
                self.main_app.status_label.config(text=f"Advanced Search: {len(rows)} results found")
                
                DatabaseManager.log_activity(
                    self.user['user_id'],
                    "ADVANCED_SEARCH",
                    f"Searched with {len(conditions)} criteria, found {len(rows)} results"
                )
            
            messagebox.showinfo("Search Complete", f"Found {len(rows)} matching records")
            self.dialog.destroy()
        
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {e}")
    
    def clear_search(self):
        """Clear search fields"""
        for var in (self.name_var, self.group_var, self.bias_var,
                    self.song_var, self.min_count_var, self.max_count_var):
            var.set("")



class AnalyticsDashboard:
    """Analytics and data visualization"""
    
    def __init__(self, parent, user):
        self.user = user
        
        self.window = tk.Toplevel(parent)
        self.window.title("Analytics Dashboard")
        self.window.geometry("1000x700")
        self.window.resizable(True, True)
        
        self.create_widgets()
        self.load_analytics()
    
    def create_widgets(self):
        """Create dashboard interface"""
        # Header
        header = tk.Frame(self.window, bg='#465187', height=60)
        header.pack(fill='x')
        
        tk.Label(
            header,
            text=" Analytics Dashboard",
            font=('Arial', 18, 'bold'),
            bg='#465187',
            fg='white'
        ).pack(pady=15)
        

        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        

        overview_frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(overview_frame, text="Overview")
        

        charts_frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(charts_frame, text="Charts")
        

        top_frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(top_frame, text="Top Lists")
        
        self.overview_frame = overview_frame
        self.charts_frame = charts_frame
        self.top_frame = top_frame
    
    def load_analytics(self):
        """Load and display analytics data"""
        try:
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                

                cur.execute("""
                    SELECT 
                        COUNT(*) as total_entries,
                        COUNT(DISTINCT fav_group) as unique_groups,
                        AVG(song_count) as avg_songs,
                        MAX(song_count) as max_songs,
                        MIN(song_count) as min_songs,
                        SUM(song_count) as total_songs
                    FROM favorites
                    WHERE user_id = ?
                """, (self.user['user_id'],))
                
                stats = cur.fetchone()
                

                overview_text = tk.Text(self.overview_frame, font=('Courier', 11), bg='#f0f0f0', wrap='word')
                overview_text.pack(fill='both', expand=True, padx=20, pady=20)
                
                overview_content = f"""
╔════════════════════════════════════════════════════════╗
║           T-POP FAVORITES STATISTICS                   ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║  Total Entries:          {stats[0]:>28}  ║
║  Unique Groups/Artists:  {stats[1]:>28}  ║
║  Total Songs Known:      {stats[5]:>28}  ║
║  Average Songs/Entry:    {stats[2]:>27.1f}  ║
║  Max Songs (Entry):      {stats[3]:>28}  ║
║  Min Songs (Entry):      {stats[4]:>28}  ║
║                                                        ║
╚════════════════════════════════════════════════════════╝

Your T-pop Journey:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You've been tracking {stats[0]} favorite entries across {stats[1]} different
groups and artists. That's impressive dedication to T-pop.

You know a combined total of {stats[5]} songs, which averages to
about {stats[2]:.1f} songs per entry.
                """
                
                overview_text.insert('1.0', overview_content)
                overview_text.config(state='disabled')
                

                self.create_charts(cur)
                

                self.create_top_lists(cur)
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load analytics: {e}")
    
    def create_charts(self, cursor):
        """Create visualization charts"""
        try:

            cursor.execute("""
                SELECT fav_group, COUNT(*) as count
                FROM favorites
                WHERE user_id = ?
                GROUP BY fav_group
                ORDER BY count DESC
                LIMIT 10
            """, (self.user['user_id'],))
            
            group_data = cursor.fetchall()
            
            if not group_data:
                tk.Label(
                    self.charts_frame,
                    text="No data available for charts",
                    font=('Arial', 14),
                    bg='white'
                ).pack(expand=True)
                return
            

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))
            fig.patch.set_facecolor('#f0f0f0')
            
            groups = [row[0] for row in group_data]
            counts = [row[1] for row in group_data]
            

            colors = plt.cm.Paired(range(len(groups)))
            ax1.bar(range(len(groups)), counts, color=colors)
            ax1.set_xlabel('Groups/Artists', fontweight='bold')
            ax1.set_ylabel('Number of Entries', fontweight='bold')
            ax1.set_title('Top Groups/Artists', fontweight='bold', fontsize=12)
            ax1.set_xticks(range(len(groups)))
            ax1.set_xticklabels([g[:15] + '...' if len(g) > 15 else g for g in groups], rotation=45, ha='right')
            ax1.grid(axis='y', alpha=0.3)
            

            ax2.pie(counts, labels=[g[:15] + '...' if len(g) > 15 else g for g in groups], 
                   autopct='%1.1f%%', colors=colors, startangle=90)
            ax2.set_title('Distribution of Favorites', fontweight='bold', fontsize=12)
            
            plt.tight_layout()
            

            canvas = FigureCanvasTkAgg(fig, master=self.charts_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)
        
        except Exception as e:
            tk.Label(
                self.charts_frame,
                text=f"Error creating charts: {e}",
                font=('Arial', 12),
                bg='white',
                fg='red'
            ).pack(expand=True)
    
    def create_top_lists(self, cursor):
        """Create top lists"""
        list_frame = tk.Frame(self.top_frame, bg='white')
        list_frame.pack(fill='both', expand=True, padx=20, pady=20)
        

        tk.Label(
            list_frame,
            text=" Top 10 Groups/Artists",
            font=('Arial', 14, 'bold'),
            bg='white'
        ).pack(pady=10)
        
        cursor.execute("""
            SELECT fav_group, COUNT(*) as count
            FROM favorites
            WHERE user_id = ?
            GROUP BY fav_group
            ORDER BY count DESC
            LIMIT 10
        """, (self.user['user_id'],))
        
        top_groups = cursor.fetchall()
        
        top_text = tk.Text(list_frame, height=12, font=('Courier', 10), bg='#f9f9f9')
        top_text.pack(fill='x', pady=5)
        
        top_text.insert('1.0', f"{'Rank':<6} {'Group/Artist':<30} {'Entries':>10}\n")
        top_text.insert('end', "─" * 50 + "\n")
        
        for i, (group, count) in enumerate(top_groups, 1):
            medal = "First:" if i == 1 else "Second:" if i == 2 else "Third" if i == 3 else "  "
            top_text.insert('end', f"{medal} {i:<3} {group:<30} {count:>10}\n")
        
        top_text.config(state='disabled')
        

        tk.Label(
            list_frame,
            text="Most Popular Bias",
            font=('Arial', 14, 'bold'),
            bg='white'
        ).pack(pady=10)
        
        cursor.execute("""
            SELECT bias, COUNT(*) as count
            FROM favorites
            WHERE user_id = ?
            GROUP BY bias
            ORDER BY count DESC
            LIMIT 5
        """, (self.user['user_id'],))
        
        top_bias = cursor.fetchall()
        
        bias_text = tk.Text(list_frame, height=7, font=('Courier', 10), bg='#f9f9f9')
        bias_text.pack(fill='x', pady=5)
        
        bias_text.insert('1.0', f"{'Rank':<6} {'Bias':<30} {'Count':>10}\n")
        bias_text.insert('end', "─" * 50 + "\n")
        
        for i, (bias, count) in enumerate(top_bias, 1):
            bias_text.insert('end', f"  {i:<4} {bias:<30} {count:>10}\n")
        
        bias_text.config(state='disabled')



class ActivityLogWindow:
    """Display user activity log"""
    
    def __init__(self, parent, user):
        self.user = user
        
        self.window = tk.Toplevel(parent)
        self.window.title("Activity Log")
        self.window.geometry("900x600")
        self.window.resizable(True, True)
        
        self.create_widgets()
        self.load_log()
    
    def create_widgets(self):
        """Create log interface"""

        header = tk.Frame(self.window, bg='#465187', height=60)
        header.pack(fill='x')
        
        tk.Label(
            header,
            text=" Activity Log",
            font=('Arial', 18, 'bold'),
            bg='#465187',
            fg='white'
        ).pack(pady=15)
        

        toolbar = tk.Frame(self.window, bg='#a37dc2', pady=10)
        toolbar.pack(fill='x', padx=10)
        
        tk.Button(
            toolbar,
            text="Refresh",
            font=('Arial', 10, 'bold'),
            bg='#c2a3db',
            command=self.load_log
        ).pack(side='left', padx=5)
        
        tk.Button(
            toolbar,
            text="Export Log",
            font=('Arial', 10, 'bold'),
            bg='#c2a3db',
            command=self.export_log
        ).pack(side='left', padx=5)
        
        tk.Label(toolbar, text="Show:", bg='#a37dc2', fg='white', font=('Arial', 10)).pack(side='left', padx=10)
        
        self.limit_var = tk.StringVar(value="50")
        limit_combo = ttk.Combobox(
            toolbar,
            textvariable=self.limit_var,
            values=["10", "50", "100", "All"],
            state='readonly',
            width=8
        )
        limit_combo.pack(side='left')
        limit_combo.bind('<<ComboboxSelected>>', lambda e: self.load_log())
        

        tree_frame = tk.Frame(self.window)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("ID", "Action", "Details", "Timestamp"),
            show='headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("Action", text="Action")
        self.tree.heading("Details", text="Details")
        self.tree.heading("Timestamp", text="Timestamp")
        
        self.tree.column("ID", width=50, anchor='center')
        self.tree.column("Action", width=150)
        self.tree.column("Details", width=400)
        self.tree.column("Timestamp", width=180)
        
        vsb.pack(side='right', fill='y')
        hsb.pack(side='bottom', fill='x')
        self.tree.pack(fill='both', expand=True)
    
    def load_log(self):
        """Load activity log"""
        self.tree.delete(*self.tree.get_children())
        
        try:
            limit = self.limit_var.get()
            
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                
                if limit == "All":
                    cur.execute("""
                        SELECT log_id, action, details, datetime(timestamp)
                        FROM activity_log
                        WHERE user_id = ?
                        ORDER BY log_id DESC
                    """, (self.user['user_id'],))
                else:
                    cur.execute("""
                        SELECT log_id, action, details, datetime(timestamp)
                        FROM activity_log
                        WHERE user_id = ?
                        ORDER BY log_id DESC
                        LIMIT ?
                    """, (self.user['user_id'], int(limit)))
                
                for row in cur.fetchall():
                    self.tree.insert("", "end", values=row)
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log: {e}")
    
    def export_log(self):
        """Export activity log"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile=f"activity_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            if not filename:
                return
            
            with DatabaseManager.create_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT log_id, action, details, datetime(timestamp)
                    FROM activity_log
                    WHERE user_id = ?
                    ORDER BY log_id DESC
                """, (self.user['user_id'],))
                
                rows = cur.fetchall()
                
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Action', 'Details', 'Timestamp'])
                    writer.writerows(rows)
            
            messagebox.showinfo("Success", f"Exported {len(rows)} log entries")
        
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
