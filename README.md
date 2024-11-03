# P2P LAN File Sharing System

A peer-to-peer file sharing application designed for Local Area Networks (LAN), built with Python. The system enables users to share, search, download, and upload files while also providing chat functionality and file rating capabilities.

## Features

### Core Features
- **User Authentication**: Secure registration and login system
- **File Sharing**: Share files from local machine to other users on the network
- **Search Functionality**: Search shared files by name, type, or description
- **File Transfer**: Direct P2P file transfer between users
- **Real-time Chat**: Built-in messaging system for user communication
- **File Rating**: Rate and review shared files
- **Dark Mode UI**: Modern, user-friendly dark-themed interface

### Security Features
- **Password Hashing**: Secure password storage using bcrypt
- **Database Security**: SQLite with thread-safe operations
- **Sanitized File Names**: Protection against malicious file names

## Technical Stack

- **Backend**: Flask, Flask-RESTful, Flask-SocketIO
- **Frontend**: Tkinter (Python's built-in GUI library)
- **Database**: SQLite3
- **Networking**: Socket Programming
- **Authentication**: Bcrypt

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/p2p-lan-file-sharing.git
cd p2p-lan-file-sharing
