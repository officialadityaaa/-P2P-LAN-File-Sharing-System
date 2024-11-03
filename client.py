# client.py
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk  # Import ttk for progress bar
import os
import requests
import threading
import socket
import json
import sqlite3
import logging

import socketio  # Import SocketIO client

from werkzeug.utils import secure_filename  # Import for filename sanitization

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
DEFAULT_SERVER_URL = 'http://10.35.8.12:5000'  # Replace with your server's default IP
SHARED_DIR = os.path.abspath('shared_files')  # Use absolute path
DOWNLOAD_DIR = os.path.abspath('downloads')   # Use absolute path
DATABASE = 'client_database.db'
FILE_SERVER_PORT = 5001  # Default port for file server

# Initialize directories
os.makedirs(SHARED_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# Initialize client database
def init_client_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL
                )''')
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files (
                    file_id INTEGER PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    file_type TEXT,
                    shared_by TEXT,
                    ip_address TEXT,
                    port INTEGER
                )''')
    conn.commit()
    conn.close()

# Start a server socket to serve files
def start_file_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind(('', port))
    except socket.error as e:
        logging.error(f"Failed to bind to port {port}: {e}")
        return
    server_socket.listen(5)
    logging.info(f"File server started on port {port}")

    while True:
        try:
            client, addr = server_socket.accept()
            logging.info(f"Connection received from {addr}")
            threading.Thread(target=handle_file_request, args=(client, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Error accepting connections: {e}")

def handle_file_request(client_socket, addr):
    try:
        data = client_socket.recv(1024).decode()
        logging.info(f"Request Data from {addr}: {data}")
        request = json.loads(data)
        if request['action'] == 'download':
            file_name = request['file_name']
            # Sanitize the file name to prevent directory traversal
            file_name = secure_filename(file_name)
            file_path = os.path.join(SHARED_DIR, file_name)
            logging.info(f"Looking for file at: {file_path}")
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    while True:
                        bytes_read = f.read(4096)
                        if not bytes_read:
                            break
                        client_socket.sendall(bytes_read)
                logging.info(f"File '{file_name}' sent successfully to {addr}.")
            else:
                logging.warning(f"File '{file_name}' does not exist.")
                error_msg = json.dumps({'error': 'File not found.'})
                client_socket.sendall(error_msg.encode())
        client_socket.close()
    except Exception as e:
        logging.error(f"Error handling file request from {addr}: {e}")
        client_socket.close()

# Client Application
class P2PClient:
    def __init__(self, master):
        self.master = master
        master.title("P2P LAN File Sharing System")
        master.configure(bg='black')  # Set background to black for dark mode

        self.user_id = None
        self.username = None
        self.file_server_port = FILE_SERVER_PORT  # Starting port for file server
        self.server_url = DEFAULT_SERVER_URL  # Initialize with default server URL

        self.chat_display = None  # Initialize as None

        # Initialize SocketIO client
        self.sio = socketio.Client()
        self.sio.on('message', self.on_message)

        # Start SocketIO connection in a separate thread to prevent blocking
        threading.Thread(target=self.connect_socketio, daemon=True).start()

        # UI Elements
        self.label = tk.Label(master, text="Welcome to P2P LAN File Sharing System", font=("Helvetica", 16),
                              bg='black', fg='white')
        self.label.pack(pady=10)

        # Server Configuration Frame
        self.server_frame = tk.Frame(master, bg='black')
        self.server_frame.pack(pady=5)

        self.server_label = tk.Label(self.server_frame, text="Server URL:", bg='black', fg='white')
        self.server_label.grid(row=0, column=0, padx=5, pady=5)

        self.server_entry = tk.Entry(self.server_frame, width=25, bg='gray20', fg='white', insertbackground='white')
        self.server_entry.grid(row=0, column=1, padx=5, pady=5)
        self.server_entry.insert(0, DEFAULT_SERVER_URL)  # Default IP

        self.update_server_button = tk.Button(self.server_frame, text="Update Server", command=self.update_server,
                                             bg='gray30', fg='white', activebackground='gray50', activeforeground='white')
        self.update_server_button.grid(row=0, column=2, padx=5, pady=5)

        # Authentication Frame
        self.auth_frame = tk.Frame(master, bg='black')
        self.auth_frame.pack(pady=5)

        self.register_button = tk.Button(self.auth_frame, text="Register", command=self.register, width=20,
                                         bg='gray30', fg='white', activebackground='gray50', activeforeground='white')
        self.register_button.grid(row=0, column=0, padx=5, pady=5)

        self.login_button = tk.Button(self.auth_frame, text="Login", command=self.login, width=20,
                                      bg='gray30', fg='white', activebackground='gray50', activeforeground='white')
        self.login_button.grid(row=0, column=1, padx=5, pady=5)

        # Actions Frame
        self.actions_frame = tk.Frame(master, bg='black')
        self.actions_frame.pack(pady=5)

        self.share_button = tk.Button(self.actions_frame, text="Share File", command=self.share_file, state=tk.DISABLED,
                                      bg='gray30', fg='white', activebackground='gray50', activeforeground='white',
                                      width=20)
        self.share_button.grid(row=0, column=0, padx=5, pady=5)

        self.search_button = tk.Button(self.actions_frame, text="Search Files", command=self.search_files,
                                       state=tk.DISABLED, bg='gray30', fg='white',
                                       activebackground='gray50', activeforeground='white', width=20)
        self.search_button.grid(row=0, column=1, padx=5, pady=5)

        self.download_button = tk.Button(self.actions_frame, text="Download Selected File",
                                         command=self.download_file, state=tk.DISABLED,
                                         bg='gray30', fg='white', activebackground='gray50',
                                         activeforeground='white', width=25)
        self.download_button.grid(row=0, column=2, padx=5, pady=5)

        self.rate_button = tk.Button(self.actions_frame, text="Rate Selected File", command=self.rate_file,
                                     state=tk.DISABLED, bg='gray30', fg='white',
                                     activebackground='gray50', activeforeground='white', width=20)
        self.rate_button.grid(row=0, column=3, padx=5, pady=5)

        self.chat_button = tk.Button(self.actions_frame, text="Chat", command=self.open_chat, state=tk.DISABLED,
                                     bg='gray30', fg='white', activebackground='gray50',
                                     activeforeground='white', width=10)
        self.chat_button.grid(row=0, column=4, padx=5, pady=5)

        # File Listbox with Scrollbar
        self.list_frame = tk.Frame(master, bg='black')
        self.list_frame.pack(pady=10)

        self.scrollbar = tk.Scrollbar(self.list_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_listbox = tk.Listbox(self.list_frame, width=150, bg='gray20', fg='white',
                                       selectbackground='gray40', selectforeground='white', yscrollcommand=self.scrollbar.set)
        self.file_listbox.pack()
        self.scrollbar.config(command=self.file_listbox.yview)

        # Progress Bar
        self.progress = ttk.Progressbar(master, orient='horizontal', length=500, mode='determinate')
        self.progress.pack(pady=10)

        # Start file server thread
        self.start_server_thread()

    def connect_socketio(self):
        try:
            self.sio.connect(self.server_url)
            logging.info("Connected to SocketIO server.")
            if self.username:
                self.sio.emit('join', {'username': self.username})
        except Exception as e:
            logging.error(f"Failed to connect to chat server: {e}")

    def update_server(self):
        new_server_url = self.server_entry.get().strip()
        if not new_server_url.startswith('http://') and not new_server_url.startswith('https://'):
            messagebox.showerror("Invalid URL", "Please enter a valid server URL starting with http:// or https://")
            return
        self.server_url = new_server_url
        logging.info(f"Server URL updated to: {self.server_url}")
        messagebox.showinfo("Server Update", f"Server URL updated to: {self.server_url}")
        # Reconnect SocketIO with the new server URL
        threading.Thread(target=self.connect_socketio, daemon=True).start()

    def start_server_thread(self):
        threading.Thread(target=start_file_server, args=(self.file_server_port,), daemon=True).start()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def register(self):
        reg_window = tk.Toplevel(self.master)
        reg_window.title("Register")
        reg_window.configure(bg='black')

        tk.Label(reg_window, text="Username", bg='black', fg='white').pack(pady=5)
        username_entry = tk.Entry(reg_window, width=30, bg='gray20', fg='white', insertbackground='white')
        username_entry.pack(pady=5)

        tk.Label(reg_window, text="Password", bg='black', fg='white').pack(pady=5)
        password_entry = tk.Entry(reg_window, show='*', width=30, bg='gray20', fg='white', insertbackground='white')
        password_entry.pack(pady=5)

        def submit_registration():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Username and password are required.")
                return
            try:
                response = requests.post(f"{self.server_url}/register", json={'username': username, 'password': password})
                if response.status_code == 201:
                    data = response.json()
                    messagebox.showinfo("Success", "Registration successful.")
                    self.user_id = data.get('user_id')
                    self.username = username
                    # Optionally, save the username locally
                    conn = sqlite3.connect(DATABASE)
                    c = conn.cursor()
                    c.execute("INSERT OR REPLACE INTO users (user_id, username) VALUES (?, ?)", (self.user_id, self.username))
                    conn.commit()
                    conn.close()
                    reg_window.destroy()
                    self.hide_auth_buttons()
                    self.enable_features()
                    self.register_peer()
                    self.refresh_shared_files()
                else:
                    messagebox.showerror("Error", response.json().get('message', 'Registration failed.'))
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to connect to server: {e}")

        tk.Button(reg_window, text="Register", command=submit_registration, width=15,
                  bg='gray30', fg='white', activebackground='gray50', activeforeground='white').pack(pady=10)

    def login(self):
        login_window = tk.Toplevel(self.master)
        login_window.title("Login")
        login_window.configure(bg='black')

        tk.Label(login_window, text="Username", bg='black', fg='white').pack(pady=5)
        username_entry = tk.Entry(login_window, width=30, bg='gray20', fg='white', insertbackground='white')
        username_entry.pack(pady=5)

        tk.Label(login_window, text="Password", bg='black', fg='white').pack(pady=5)
        password_entry = tk.Entry(login_window, show='*', width=30, bg='gray20', fg='white', insertbackground='white')
        password_entry.pack(pady=5)

        def submit_login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Username and password are required.")
                return
            try:
                response = requests.post(f"{self.server_url}/login", json={'username': username, 'password': password})
                if response.status_code == 200:
                    data = response.json()
                    self.user_id = data['user_id']
                    self.username = username
                    # Optionally, save the username locally
                    conn = sqlite3.connect(DATABASE)
                    c = conn.cursor()
                    c.execute("INSERT OR REPLACE INTO users (user_id, username) VALUES (?, ?)", (self.user_id, self.username))
                    conn.commit()
                    conn.close()
                    messagebox.showinfo("Success", "Login successful.")
                    login_window.destroy()
                    self.hide_auth_buttons()
                    self.enable_features()
                    self.register_peer()
                    self.refresh_shared_files()
                else:
                    messagebox.showerror("Error", response.json().get('message', 'Login failed.'))
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to connect to server: {e}")

        tk.Button(login_window, text="Login", command=submit_login, width=15,
                  bg='gray30', fg='white', activebackground='gray50', activeforeground='white').pack(pady=10)

    def hide_auth_buttons(self):
        self.auth_frame.pack_forget()

    def enable_features(self):
        self.share_button.config(state=tk.NORMAL)
        self.search_button.config(state=tk.NORMAL)
        self.download_button.config(state=tk.NORMAL)
        self.rate_button.config(state=tk.NORMAL)
        self.chat_button.config(state=tk.NORMAL)

    def register_peer(self):
        ip_address = self.get_local_ip()
        logging.info(f"Peer IP Address: {ip_address}")
        # After registering the peer, join the chat room
        if self.sio.connected and self.username:
            self.sio.emit('join', {'username': self.username})

    def share_file(self):
        file_path = filedialog.askopenfilename(initialdir=os.path.expanduser("~"))  # Start from home directory
        if file_path:
            file_name = os.path.basename(file_path)
            sanitized_file_name = secure_filename(file_name)  # Sanitize file name
            file_size = os.path.getsize(file_path)
            file_type = os.path.splitext(file_name)[1].replace('.', '')
            ip_address = self.get_local_ip()
            port = self.file_server_port

            logging.info(f"Registering file with IP: {ip_address}, Port: {port}, File Name: {sanitized_file_name}")

            try:
                response = requests.post(f"{self.server_url}/register_file", json={
                    'file_name': sanitized_file_name,  # Use sanitized name
                    'file_size': file_size,
                    'file_type': file_type,
                    'shared_by': self.user_id,
                    'ip_address': ip_address,
                    'port': port
                })
                if response.status_code == 201:
                    dest_path = os.path.join(SHARED_DIR, sanitized_file_name)
                    if not os.path.exists(dest_path):
                        try:
                            with open(file_path, 'rb') as src, open(dest_path, 'wb') as dst:
                                dst.write(src.read())
                            logging.info(f"File '{sanitized_file_name}' copied to shared_files directory.")
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to copy file: {e}")
                            return
                    messagebox.showinfo("Success", "File shared successfully.")
                    self.refresh_shared_files()
                else:
                    messagebox.showerror("Error", response.json().get('message', 'Failed to share file.'))
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to connect to server: {e}")

    def refresh_shared_files(self):
        try:
            response = requests.get(f"{self.server_url}/search", params={'query': '', 'type': ''})
            if response.status_code == 200:
                files = response.json().get('files', [])
                self.file_listbox.delete(0, tk.END)
                for file in files:
                    display_text = (f"[{file['file_id']}] "  # Include file_id at the beginning
                                   f"Name: {file['file_name']} | "
                                   f"Size: {file['file_size']} bytes | "
                                   f"Type: {file['file_type']} | "
                                   f"Shared by: {file['shared_by']} | "
                                   f"IP: {file['ip_address']} | "
                                   f"Port: {file['port']} | "
                                   f"Rating: {'★' * int(round(file.get('average_rating', 0))) + '☆' * (5 - int(round(file.get('average_rating', 0))))} "
                                   f"({file.get('rating_count',0)} votes)")
                    self.file_listbox.insert(tk.END, display_text)
                logging.info(f"Fetched {len(files)} shared files from the server.")
            else:
                messagebox.showerror("Error", "Failed to fetch shared files.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Failed to connect to server: {e}")

    def search_files(self):
        search_window = tk.Toplevel(self.master)
        search_window.title("Search Files")
        search_window.configure(bg='black')

        tk.Label(search_window, text="File Name", bg='black', fg='white').pack(pady=5)
        name_entry = tk.Entry(search_window, width=40, bg='gray20', fg='white', insertbackground='white')
        name_entry.pack(pady=5)

        tk.Label(search_window, text="File Type", bg='black', fg='white').pack(pady=5)
        type_entry = tk.Entry(search_window, width=40, bg='gray20', fg='white', insertbackground='white')
        type_entry.pack(pady=5)

        def submit_search():
            query = name_entry.get().strip()
            file_type = type_entry.get().strip()
            try:
                response = requests.get(f"{self.server_url}/search", params={'query': query, 'type': file_type})
                if response.status_code == 200:
                    files = response.json().get('files', [])
                    self.file_listbox.delete(0, tk.END)
                    for file in files:
                        display_text = (f"[{file['file_id']}] "  # Include file_id at the beginning
                                       f"Name: {file['file_name']} | "
                                       f"Size: {file['file_size']} bytes | "
                                       f"Type: {file['file_type']} | "
                                       f"Shared by: {file['shared_by']} | "
                                       f"IP: {file['ip_address']} | "
                                       f"Port: {file['port']} | "
                                       f"Rating: {'★' * int(round(file.get('average_rating', 0))) + '☆' * (5 - int(round(file.get('average_rating', 0))))} "
                                       f"({file.get('rating_count',0)} votes)")
                        self.file_listbox.insert(tk.END, display_text)
                    search_window.destroy()
                    logging.info(f"Search completed. Found {len(files)} files.")
                else:
                    messagebox.showerror("Error", "Search failed.")
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Failed to connect to server: {e}")

        tk.Button(search_window, text="Search", command=submit_search, width=15,
                  bg='gray30', fg='white', activebackground='gray50', activeforeground='white').pack(pady=10)

    def parse_file_info(self, display_text):
        file_info = {}
        if display_text.startswith('['):
            end_idx = display_text.find(']')
            if end_idx != -1:
                file_id_str = display_text[1:end_idx]
                try:
                    file_info['file_id'] = int(file_id_str)
                except ValueError:
                    file_info['file_id'] = None
                # Remove the [file_id] part from the display_text
                display_text = display_text[end_idx+1:].strip()
        parts = display_text.split('|')
        for part in parts:
            if ': ' in part:
                key, value = part.strip().split(': ', 1)
                key = key.lower().replace(' ', '_')
                if key == 'name':
                    file_info['file_name'] = value
                elif key == 'ip':
                    file_info['ip_address'] = value
                elif key == 'port':
                    try:
                        file_info['port'] = int(value)
                    except ValueError:
                        file_info['port'] = None
                elif key == 'rating':
                    # Extract filled and empty stars and votes
                    try:
                        stars_part, votes_part = value.split(' (')
                        filled_stars = stars_part.count('★')
                        empty_stars = stars_part.count('☆')
                        file_info['average_rating'] = filled_stars  # Simplified to filled stars
                        votes = votes_part.replace(' votes)', '')
                        file_info['rating_count'] = int(votes)
                    except ValueError:
                        file_info['average_rating'] = 0
                        file_info['rating_count'] = 0
        logging.info(f"Parsed file info: {file_info}")
        return file_info

    def download_file(self):
        selection = self.file_listbox.curselection()
        if selection:
            selected = self.file_listbox.get(selection[0])
            file_info = self.parse_file_info(selected)
            
            if not all(key in file_info for key in ['file_name', 'ip_address', 'port']) or file_info['port'] is None:
                messagebox.showerror("Error", "Incomplete file information. Cannot download.")
                return

            threading.Thread(target=self.download_file_thread, args=(file_info,), daemon=True).start()
        else:
            messagebox.showwarning("Warning", "No file selected.")

    def download_file_thread(self, file_info):
        try:
            logging.info(f"Connecting to {file_info['ip_address']}:{file_info['port']} to download '{file_info['file_name']}'")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)  # Set a timeout for the connection
                s.connect((file_info['ip_address'], file_info['port']))
                request = {'action': 'download', 'file_name': file_info['file_name']}
                s.sendall(json.dumps(request).encode())
                logging.info(f"Sent download request for '{file_info['file_name']}' to {file_info['ip_address']}:{file_info['port']}")

                # Prepare to receive file
                file_path = os.path.join(DOWNLOAD_DIR, file_info['file_name'])
                with open(file_path, 'wb') as f:
                    total_received = 0
                    while True:
                        bytes_read = s.recv(4096)
                        if not bytes_read:
                            break
                        f.write(bytes_read)
                        total_received += len(bytes_read)
                        # Update progress bar
                        if file_info.get('file_size') and file_info['file_size'] > 0:
                            progress_percent = (total_received / file_info['file_size']) * 100
                            self.progress['value'] = progress_percent
                            self.master.update_idletasks()

            logging.info(f"File '{file_info['file_name']}' downloaded successfully to '{DOWNLOAD_DIR}'.")
            self.master.after(0, lambda: messagebox.showinfo("Success", f"File '{file_info['file_name']}' downloaded successfully to '{DOWNLOAD_DIR}'."))
        except socket.timeout:
            logging.error("Connection timed out.")
            self.master.after(0, lambda: messagebox.showerror("Error", "Connection timed out. The peer might be offline or the port is incorrect."))
        except Exception as e:
            logging.error(f"Failed to download file: {e}")
            self.master.after(0, lambda e=e: messagebox.showerror("Error", f"Failed to download file: {e}"))
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)  # Remove incomplete file
        finally:
            # Reset progress bar
            self.progress['value'] = 0

    def rate_file(self):
        selection = self.file_listbox.curselection()
        if selection:
            selected = self.file_listbox.get(selection[0])
            file_info = self.parse_file_info(selected)

            if not file_info.get('file_id'):
                messagebox.showerror("Error", "File ID not found. Cannot rate.")
                return

            rating_window = tk.Toplevel(self.master)
            rating_window.title("Rate File")
            rating_window.configure(bg='black')

            tk.Label(rating_window, text=f"Rate '{file_info['file_name']}'", bg='black', fg='white').pack(pady=5)

            rating_var = tk.IntVar()
            rating_var.set(5)  # Default rating

            stars_frame = tk.Frame(rating_window, bg='black')
            stars_frame.pack(pady=5)

            # Create star buttons
            self.stars = []
            for i in range(1, 6):
                star_button = tk.Button(stars_frame, text='☆', font=("Helvetica", 24),
                                        bg='black', fg='white', activebackground='black',
                                        activeforeground='yellow',
                                        command=lambda i=i: self.set_rating(i, rating_var, stars_frame))
                star_button.pack(side=tk.LEFT)
                self.stars.append(star_button)

            def submit_rating():
                rating = rating_var.get()
                try:
                    response = requests.post(f"{self.server_url}/rate_file", json={
                        'file_id': file_info['file_id'],
                        'user_id': self.user_id,
                        'rating': rating
                    })
                    if response.status_code == 201:
                        messagebox.showinfo("Success", "Rating submitted successfully.")
                        rating_window.destroy()
                        self.refresh_shared_files()
                    else:
                        messagebox.showerror("Error", response.json().get('message', 'Failed to submit rating.'))
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"Failed to connect to server: {e}")

            tk.Button(rating_window, text="Submit Rating", command=submit_rating, width=15,
                      bg='gray30', fg='white', activebackground='gray50', activeforeground='white').pack(pady=10)
        else:
            messagebox.showwarning("Warning", "No file selected.")

    def set_rating(self, rating, rating_var, stars_frame):
        rating_var.set(rating)
        for i, star in enumerate(self.stars, start=1):
            if i <= rating:
                star.config(text='★', fg='yellow')
            else:
                star.config(text='☆', fg='white')

    def open_chat(self):
        chat_window = tk.Toplevel(self.master)
        chat_window.title("Chat")
        chat_window.configure(bg='black')

        # Chat Display
        self.chat_display = tk.Text(chat_window, state=tk.DISABLED, width=60, height=20,
                                    bg='gray20', fg='white', insertbackground='white')
        self.chat_display.pack(pady=5)

        # Message Entry
        message_entry = tk.Entry(chat_window, width=50, bg='gray20', fg='white', insertbackground='white')
        message_entry.pack(pady=5)

        def send_message():
            msg = message_entry.get().strip()
            if msg:
                self.sio.emit('send_message', {'username': self.username, 'msg': msg})
                message_entry.delete(0, tk.END)

        # Send Button
        send_button = tk.Button(chat_window, text="Send", command=send_message, width=10,
                                bg='gray30', fg='white', activebackground='gray50', activeforeground='white')
        send_button.pack(pady=5)

    def on_message(self, data):
        user = data.get('user')
        msg = data.get('msg')
        if self.chat_display:
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"{user}: {msg}\n")
            self.chat_display.config(state=tk.DISABLED)
            self.chat_display.see(tk.END)  # Auto-scroll to the latest message
        else:
            # Optionally, notify the user that a new message has arrived
            logging.info(f"New message from '{user}': {msg}")
            # You can implement desktop notifications or other UI cues here

    def parse_file_info(self, display_text):
        file_info = {}
        if display_text.startswith('['):
            end_idx = display_text.find(']')
            if end_idx != -1:
                file_id_str = display_text[1:end_idx]
                try:
                    file_info['file_id'] = int(file_id_str)
                except ValueError:
                    file_info['file_id'] = None
                # Remove the [file_id] part from the display_text
                display_text = display_text[end_idx+1:].strip()
        parts = display_text.split('|')
        for part in parts:
            if ': ' in part:
                key, value = part.strip().split(': ', 1)
                key = key.lower().replace(' ', '_')
                if key == 'name':
                    file_info['file_name'] = value
                elif key == 'ip':
                    file_info['ip_address'] = value
                elif key == 'port':
                    try:
                        file_info['port'] = int(value)
                    except ValueError:
                        file_info['port'] = None
                elif key == 'rating':
                    # Extract filled and empty stars and votes
                    try:
                        stars_part, votes_part = value.split(' (')
                        filled_stars = stars_part.count('★')
                        empty_stars = stars_part.count('☆')
                        file_info['average_rating'] = filled_stars  # Simplified to filled stars
                        votes = votes_part.replace(' votes)', '')
                        file_info['rating_count'] = int(votes)
                    except ValueError:
                        file_info['average_rating'] = 0
                        file_info['rating_count'] = 0
        logging.info(f"Parsed file info: {file_info}")
        return file_info

    def download_file(self):
        selection = self.file_listbox.curselection()
        if selection:
            selected = self.file_listbox.get(selection[0])
            file_info = self.parse_file_info(selected)
            
            if not all(key in file_info for key in ['file_name', 'ip_address', 'port']) or file_info['port'] is None:
                messagebox.showerror("Error", "Incomplete file information. Cannot download.")
                return

            threading.Thread(target=self.download_file_thread, args=(file_info,), daemon=True).start()
        else:
            messagebox.showwarning("Warning", "No file selected.")

    def download_file_thread(self, file_info):
        try:
            logging.info(f"Connecting to {file_info['ip_address']}:{file_info['port']} to download '{file_info['file_name']}'")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)  # Set a timeout for the connection
                s.connect((file_info['ip_address'], file_info['port']))
                request = {'action': 'download', 'file_name': file_info['file_name']}
                s.sendall(json.dumps(request).encode())
                logging.info(f"Sent download request for '{file_info['file_name']}' to {file_info['ip_address']}:{file_info['port']}")

                # Prepare to receive file
                file_path = os.path.join(DOWNLOAD_DIR, file_info['file_name'])
                with open(file_path, 'wb') as f:
                    total_received = 0
                    while True:
                        bytes_read = s.recv(4096)
                        if not bytes_read:
                            break
                        f.write(bytes_read)
                        total_received += len(bytes_read)
                        # Update progress bar
                        if file_info.get('file_size') and file_info['file_size'] > 0:
                            progress_percent = (total_received / file_info['file_size']) * 100
                            self.progress['value'] = progress_percent
                            self.master.update_idletasks()

            logging.info(f"File '{file_info['file_name']}' downloaded successfully to '{DOWNLOAD_DIR}'.")
            self.master.after(0, lambda: messagebox.showinfo("Success", f"File '{file_info['file_name']}' downloaded successfully to '{DOWNLOAD_DIR}'."))
        except socket.timeout:
            logging.error("Connection timed out.")
            self.master.after(0, lambda: messagebox.showerror("Error", "Connection timed out. The peer might be offline or the port is incorrect."))
        except Exception as e:
            logging.error(f"Failed to download file: {e}")
            self.master.after(0, lambda e=e: messagebox.showerror("Error", f"Failed to download file: {e}"))
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)  # Remove incomplete file
        finally:
            # Reset progress bar
            self.progress['value'] = 0

    def rate_file(self):
        selection = self.file_listbox.curselection()
        if selection:
            selected = self.file_listbox.get(selection[0])
            file_info = self.parse_file_info(selected)

            if not file_info.get('file_id'):
                messagebox.showerror("Error", "File ID not found. Cannot rate.")
                return

            rating_window = tk.Toplevel(self.master)
            rating_window.title("Rate File")
            rating_window.configure(bg='black')

            tk.Label(rating_window, text=f"Rate '{file_info['file_name']}'", bg='black', fg='white').pack(pady=5)

            rating_var = tk.IntVar()
            rating_var.set(5)  # Default rating

            stars_frame = tk.Frame(rating_window, bg='black')
            stars_frame.pack(pady=5)

            # Create star buttons
            self.stars = []
            for i in range(1, 6):
                star_button = tk.Button(stars_frame, text='☆', font=("Helvetica", 24),
                                        bg='black', fg='white', activebackground='black',
                                        activeforeground='yellow',
                                        command=lambda i=i: self.set_rating(i, rating_var, stars_frame))
                star_button.pack(side=tk.LEFT)
                self.stars.append(star_button)

            def submit_rating():
                rating = rating_var.get()
                try:
                    response = requests.post(f"{self.server_url}/rate_file", json={
                        'file_id': file_info['file_id'],
                        'user_id': self.user_id,
                        'rating': rating
                    })
                    if response.status_code == 201:
                        messagebox.showinfo("Success", "Rating submitted successfully.")
                        rating_window.destroy()
                        self.refresh_shared_files()
                    else:
                        messagebox.showerror("Error", response.json().get('message', 'Failed to submit rating.'))
                except requests.exceptions.RequestException as e:
                    messagebox.showerror("Error", f"Failed to connect to server: {e}")

            tk.Button(rating_window, text="Submit Rating", command=submit_rating, width=15,
                      bg='gray30', fg='white', activebackground='gray50', activeforeground='white').pack(pady=10)
        else:
            messagebox.showwarning("Warning", "No file selected.")

    def set_rating(self, rating, rating_var, stars_frame):
        rating_var.set(rating)
        for i, star in enumerate(self.stars, start=1):
            if i <= rating:
                star.config(text='★', fg='yellow')
            else:
                star.config(text='☆', fg='white')

    def open_chat(self):
        chat_window = tk.Toplevel(self.master)
        chat_window.title("Chat")
        chat_window.configure(bg='black')

        # Chat Display
        self.chat_display = tk.Text(chat_window, state=tk.DISABLED, width=60, height=20,
                                    bg='gray20', fg='white', insertbackground='white')
        self.chat_display.pack(pady=5)

        # Message Entry
        message_entry = tk.Entry(chat_window, width=50, bg='gray20', fg='white', insertbackground='white')
        message_entry.pack(pady=5)

        def send_message():
            msg = message_entry.get().strip()
            if msg:
                self.sio.emit('send_message', {'username': self.username, 'msg': msg})
                message_entry.delete(0, tk.END)

        # Send Button
        send_button = tk.Button(chat_window, text="Send", command=send_message, width=10,
                                bg='gray30', fg='white', activebackground='gray50', activeforeground='white')
        send_button.pack(pady=5)

    def on_message(self, data):
        user = data.get('user')
        msg = data.get('msg')
        if self.chat_display:
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"{user}: {msg}\n")
            self.chat_display.config(state=tk.DISABLED)
            self.chat_display.see(tk.END)  # Auto-scroll to the latest message
        else:
            # Optionally, notify the user that a new message has arrived
            logging.info(f"New message from '{user}': {msg}")
            # You can implement desktop notifications or other UI cues here

    def parse_file_info(self, display_text):
        file_info = {}
        if display_text.startswith('['):
            end_idx = display_text.find(']')
            if end_idx != -1:
                file_id_str = display_text[1:end_idx]
                try:
                    file_info['file_id'] = int(file_id_str)
                except ValueError:
                    file_info['file_id'] = None
                # Remove the [file_id] part from the display_text
                display_text = display_text[end_idx+1:].strip()
        parts = display_text.split('|')
        for part in parts:
            if ': ' in part:
                key, value = part.strip().split(': ', 1)
                key = key.lower().replace(' ', '_')
                if key == 'name':
                    file_info['file_name'] = value
                elif key == 'ip':
                    file_info['ip_address'] = value
                elif key == 'port':
                    try:
                        file_info['port'] = int(value)
                    except ValueError:
                        file_info['port'] = None
                elif key == 'rating':
                    # Extract filled and empty stars and votes
                    try:
                        stars_part, votes_part = value.split(' (')
                        filled_stars = stars_part.count('★')
                        empty_stars = stars_part.count('☆')
                        file_info['average_rating'] = filled_stars  # Simplified to filled stars
                        votes = votes_part.replace(' votes)', '')
                        file_info['rating_count'] = int(votes)
                    except ValueError:
                        file_info['average_rating'] = 0
                        file_info['rating_count'] = 0
        logging.info(f"Parsed file info: {file_info}")
        return file_info

# Initialize Client Database
init_client_db()

# Start Tkinter Application
if __name__ == "__main__":
    root = tk.Tk()
    app = P2PClient(root)
    root.mainloop()
