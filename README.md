# Remote FileSystem in Rust

A FUSE-based remote filesystem implementation in Rust that provides transparent access to files stored on a remote server through a local mount point.

## 🎯 Features

- **FUSE Integration**: Mount remote filesystem as a local directory on Linux
- **RESTful API**: Stateless server with JWT authentication
- **User Management**: Multi-user support with authentication and authorization
- **File Permissions**: Unix-style permission system (owner, group, others)
- **Streaming Support**: Efficient handling of large files (100MB+) using streams
- **Caching**: Client-side caching for improved performance
- **Daemon Mode**: Background execution with signal handling
- **Database Backend**: SQLite for metadata and user management

## 🏗️ Architecture

### Server (`/server`)
- **Framework**: Axum (async web framework)
- **Authentication**: JWT tokens with bcrypt password hashing
- **Database**: SQLite (rusqlite) for user and file metadata
- **Virtual Filesystem**: In-memory tree structure mirroring physical filesystem

### Client (`/client`)
- **FUSE**: Linux FUSE implementation for filesystem operations
- **Cache**: TTL-based caching (300s default) for attributes and content
- **Daemon Support**: Background execution using `daemonize` crate

## 📋 Requirements

### Server
- Rust 1.70+
- SQLite3

### Client
- Rust 1.70+
- FUSE3 (`fusermount3`)
- Linux operating system

## 🚀 Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd progetto_rust_filesystem
```

### 2. Install FUSE (Linux)
```bash
# Ubuntu/Debian
sudo apt-get install fuse3 libfuse3-dev

# Fedora/RHEL
sudo dnf install fuse3 fuse3-devel
```

### 3. Build the project
```bash
# Build server
cd server
cargo build --release

# Build client
cd ../client
cargo build --release
```

## 🎮 Usage

### Starting the Server

```bash
cd server
cargo run --release
```

Server will start on `http://0.0.0.0:8080` by default.

### Starting the Client

#### Foreground Mode (Debug)
```bash
cd client
cargo run --release
```

#### Daemon Mode
```bash
cd client
cargo run --release -- --daemon
```

#### Custom Server Configuration
```bash
# Remote server
cargo run -- --server-ip 192.168.1.100 --server-port 9000

# With daemon mode
cargo run -- --daemon --server-ip 192.168.1.100
```

### First-time Setup

1. **Registration** (optional if no account exists)
   - The client will prompt for username and password
   - User will be created both on server and locally (requires sudo)

2. **Login**
   - Enter credentials
   - Client receives JWT token for subsequent requests

3. **Mount**
   - Filesystem mounts at `./mount` directory
   - Access files like a normal directory

## 📡 API Reference

### Authentication Endpoints

#### Register User
```bash
curl -X POST http://127.0.0.1:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}'
```

#### Login
```bash
curl -X POST http://127.0.0.1:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}'
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "username": "alice",
  "user_id": 1,
  "expires_in": 3600
}
```

#### Save Token (Bash)
```bash
TOKEN_ALICE=$(curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}' | \
  grep -o '"token":"[^"]*"' | cut -d'"' -f4)
```

### File Operations

#### List Directory Contents
```bash
curl -X GET http://127.0.0.1:8080/list/ \
  -H "Authorization: Bearer $TOKEN_ALICE"
```

**Response:**
```json
[
  {
    "permissions": 493,
    "links": 1,
    "owner": "alice",
    "group": "users",
    "size": 1024,
    "modified": "Dec  7 14:30",
    "name": "secret.txt",
    "is_directory": false
  }
]
```

#### Read File
```bash
curl -X GET http://127.0.0.1:8080/files/secret.txt \
  -H "Authorization: Bearer $TOKEN_ALICE"
```

#### Write File
```bash
# Simple text
curl -X PUT http://127.0.0.1:8080/files/secret.txt \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -d "This is Alice's private file!"

# With custom permissions
curl -X PUT "http://127.0.0.1:8080/files/secret.txt?permissions=600" \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -d "Highly confidential!"
```

#### Upload Large File (Stream)
```bash
cat large_file.pdf | curl -v --http1.1 -X PUT \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/octet-stream" \
  "http://127.0.0.1:8080/files/large_file.pdf?permissions=644" \
  --data-binary @-
```

#### Download Large File (Stream)
```bash
curl -fSsv -H "Authorization: Bearer $TOKEN_ALICE" \
  "http://127.0.0.1:8080/files/large_file.pdf" \
  -o downloaded.pdf
```

#### Create Directory
```bash
curl -X POST "http://127.0.0.1:8080/mkdir/documents?permissions=755" \
  -H "Authorization: Bearer $TOKEN_ALICE"
```

#### Delete File/Directory
```bash
curl -X DELETE http://127.0.0.1:8080/files/old_file.txt \
  -H "Authorization: Bearer $TOKEN_ALICE"
```

#### Lookup Item Metadata
```bash
curl -X GET http://127.0.0.1:8080/lookup/documents/report.pdf \
  -H "Authorization: Bearer $TOKEN_ALICE"
```

## 🧪 Testing

### Automated Tests
```bash
# Terminal 1: Start server
cd server
cargo run

# Terminal 2: Run tests
cd server
cargo test --test api_test
```

### Manual Testing via FUSE Mount

```bash
# List files
ls -la mount/

# Create directory
mkdir mount/test_dir

# Write file
echo "Hello World" > mount/test.txt

# Read file
cat mount/test.txt

# Copy large file
cp large_file.pdf mount/

# Delete file
rm mount/test.txt
```

## 🔧 Configuration

### Permissions Format
Permissions use Unix octal notation (3 digits):
- First digit: Owner permissions (r=4, w=2, x=1)
- Second digit: Group permissions
- Third digit: Others permissions

Examples:
- `644`: rw-r--r-- (owner read/write, others read)
- `755`: rwxr-xr-x (owner all, others read/execute)
- `600`: rw------- (owner read/write only)

### Cache Configuration
Client cache TTL: 300 seconds (5 minutes)
- Modify `CacheValue::new()` in `client/src/fuse.rs` to adjust

### Database Schema

**USER Table:**
```sql
CREATE TABLE USER (
    User_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL UNIQUE,
    Password TEXT NOT NULL
);
```

**METADATA Table:**
```sql
CREATE TABLE METADATA (
    File_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    user_id INTEGER,
    user_permissions INTEGER,
    group_permissions INTEGER,
    others_permissions INTEGER,
    size INTEGER,
    created_at TEXT,
    last_modified TEXT,
    type INTEGER  -- 0=file, 1=directory
);
```

## 🛠️ Troubleshooting

### Unmount Stuck Filesystem
```bash
fusermount3 -u ./mount
```

### Check Daemon Status
```bash
# Check if running
ps -p $(cat /tmp/myfs.pid)

# Kill daemon
kill $(cat /tmp/myfs.pid)

# View errors
cat /tmp/myfs.err
```

### Permission Denied Errors
- Ensure user exists locally (created automatically on first login)
- Check file ownership in database matches your user_id
- Verify parent directory has write permissions for creation/deletion

### Cache Issues
- Cache invalidates after 300s automatically
- For immediate refresh, restart client or use direct API calls

## 🔐 Security Considerations

⚠️ **This is an educational project. For production use:**

1. Change JWT secret from hardcoded value
2. Use HTTPS instead of HTTP
3. Implement rate limiting
4. Add input validation and sanitization
5. Use environment variables for sensitive configuration
6. Implement proper group permission handling
7. Add audit logging

## 📝 License

This project is for educational purposes as part of a university course (Programmazione di Sistema).

## 🤝 Contributing

This is a university project, but suggestions and improvements are welcome.

## 📚 Technologies Used

- **Rust**: Systems programming language
- **Axum**: Async web framework
- **FUSE**: Filesystem in Userspace
- **SQLite**: Embedded database
- **JWT**: JSON Web Tokens for authentication
- **bcrypt**: Password hashing
- **Tokio**: Async runtime
- **Reqwest**: HTTP client

## 👥 Authors

Alessandro Benvenuti - Politecnico di Torino <br>
Irene Bartolini - Politecnico di Torino
