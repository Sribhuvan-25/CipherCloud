# Secure Cloud File Storage with Automatic Key Rotation and Auditing

Below is a **single Markdown document** that contains **all** the details needed for an AI agent (or any developer) to understand the **project idea**, **requirements**, **implementation approach**, **file structure**, and **sample code**. The goal is to ensure that no parts are “split up” in a confusing way, so the entire specification is presented in one place.

---

## 1. Project Idea

Create a **secure file storage system** where:

1. **Users** can **upload** files **encrypted** on the **client side**, so the server never sees plaintext.
2. Each file is encrypted with a **unique symmetric key** (Data Encryption Key, or DEK).
3. The DEK is **encrypted** (“wrapped”) with the user’s **public key** so only the user’s **private key** can unwrap it.
4. The system supports **automatic key rotation** to reduce risks if a key is compromised.
5. An **audit log** records each operation (upload, download, rotation) in a **tamper-evident** way (hash chaining).

**What we’re trying to achieve**:
- **Confidentiality**: The server can store files but not decrypt them.  
- **Integrity**: Any tampering with files or logs is detectable.  
- **Access Control**: Only users with the correct private key can decrypt.  
- **Key Management**: DEKs can be rotated or re-wrapped when needed.  
- **Auditing**: A cryptographically verifiable log of all file operations.

---

## 2. Required Tools and Concepts

1. **Programming Language**: Python 3.x  
2. **Cryptography Library**: [cryptography](https://pypi.org/project/cryptography/) (for AES, RSA/ECC, hashing, etc.)  
3. **Database or File System**: To store file metadata, user info, and logs (e.g., SQLite).  
4. **REST Framework (Optional)**: Flask or FastAPI to build a simple API.  
5. **Knowledge of**:  
   - **Symmetric Encryption** (AES in GCM mode).  
   - **Asymmetric Encryption** (RSA or ECC) for key wrapping.  
   - **Hashing** for audit log chaining.  

**Why these are needed**:
- **AES** for fast encryption/decryption of file data.  
- **RSA/ECC** to ensure only the legitimate user can unwrap the DEK.  
- **Hash chaining** to make logs tamper-evident.

---

## 3. Implementation Approach

1. **Client-Side Encryption**:
   - Generate a random **DEK** (256-bit) per file.
   - Encrypt the file with **AES-GCM** using this DEK.
   - **Wrap** (encrypt) the DEK with the user’s **public key** (RSA or ECC-based).
   - Send `(encrypted_file, wrapped_DEK, metadata)` to the server.

2. **Server Storage**:
   - Stores the encrypted file (ciphertext) and the wrapped DEK.
   - Never sees the plaintext or unwrapped DEK.
   - Maintains a **database** (or file-based) record of `(fileID, ownerID, wrappedDEK, filePath, metadata)`.

3. **Download / Decryption**:
   - The server sends `(wrapped_DEK, encrypted_file)` to the client.
   - The client uses its **private key** to **unwrap** the DEK, then **decrypts** the file with AES-GCM.

4. **Automatic Key Rotation**:
   - On demand or on a schedule, generate a **new key pair** for the user.
   - Re-wrap existing DEKs with the new public key.
   - Update records so the old key is phased out.

5. **Audit Logging**:
   - Each operation (upload, download, rotation) is recorded with a timestamp, operation type, userID, fileID, plus a **hash** linking to the previous log entry.
   - This chain of hashes makes it obvious if older entries are modified.

---

## 4. Project Structure

A **suggested** directory layout (all in **one** place for clarity):

secure_file_storage/ ├── README.md # Project overview (optional) ├── requirements.txt # Python dependencies ├── crypto_utils.py # All cryptographic functions ├── db_handler.py # Database or file-based storage operations ├── server.py # Server-side logic (Flask or raw sockets) ├── client.py # Client-side logic for uploading/downloading ├── logs/ │ └── audit.log # Tamper-evident log file (if using text logs) └── files/ # Folder where encrypted files are stored


**Explanation**:
- **`crypto_utils.py`**: Key generation, AES encryption, RSA wrapping/unwrapping, hashing for logs.  
- **`db_handler.py`**: Handles reading/writing metadata to DB or files.  
- **`server.py`**: Runs a server that exposes endpoints for upload, download, key rotation.  
- **`client.py`**: Command-line or minimal script that performs client-side encryption and interacts with the server.  
- **`logs/`**: Stores the tamper-evident audit log.  
- **`files/`**: Holds the actual encrypted files on the server side.

---

## 5. Detailed Implementation Steps

### 5.1 Generating Keys

- **User Key Pair** (RSA/ECC):
  1. `private_key, public_key = rsa.generate_private_key(...)`
  2. Store the **private key** on the client side (PEM format).  
  3. Store the **public key** in the server database, mapped to a `userID`.

### 5.2 File Upload (Client)

1. **Generate DEK**: A random 256-bit key for AES.
2. **Encrypt File**: Use AES-GCM (`aes_encrypt`) to produce `(iv, ciphertext, tag)`.
3. **Wrap DEK**: `wrappedDEK = wrap_key_with_rsa(public_key, DEK)`.
4. **Send to Server**:
   - `fileID`, `userID`, `wrappedDEK` (base64), `ciphertext` (base64), `tag`, `metadata`.
5. **Server**:
   - Saves the ciphertext to a file (e.g., `files/<fileID>`).
   - Stores `(fileID, userID, wrappedDEK, filePath, metadata)` in the DB.
   - Appends an **upload** event to the audit log (hash chain).

### 5.3 File Download (Client)

1. **Request**: `GET /download/<fileID>`.
2. **Server**:
   - Looks up `(wrappedDEK, ciphertext_path)` from DB.
   - Reads the ciphertext file from disk.
   - Sends `wrappedDEK` (base64) and the ciphertext (base64) back to the client.
   - Appends a **download** event to the audit log.
3. **Client**:
   - **Unwrap** the DEK with its private key: `DEK = unwrap_key_with_rsa(privateKey, wrappedDEK)`.
   - **Decrypt** the ciphertext using AES-GCM.

### 5.4 Automatic Key Rotation

1. **Trigger**: Admin or a scheduled job decides to rotate keys for a user.
2. **Server or Client** (depending on design):
   - Generates a **new key pair** (`newPrivateKey`, `newPublicKey`).
   - For each file belonging to the user:
     1. Retrieve the **old** `wrappedDEK`.
     2. **Unwrap** it with the old private key (the user’s client might do this if the server doesn’t hold private keys).
     3. **Re-wrap** it with the new public key.
     4. Update the DB record for that file.
   - Log the **rotateKey** event in the audit log.

### 5.5 Audit Logging

- **Structure**:
  - Each entry has:  
    - `timestamp`, `operation` (upload/download/rotate), `userID`, `fileID`, `prev_hash`, `current_hash`.
- **Hash Chain**:
  - `current_hash = SHA256(prev_hash + log_data)` (where `log_data` might be the concatenation of `timestamp`, `userID`, `fileID`, etc.).
- **Tamper Detection**:
  - If any old entry is changed, subsequent `prev_hash` references break the chain.

---

## 6. Sample Code (All in One Document)

Below are **code stubs** that give enough context for an AI agent to generate a **fully working** system. 

### 6.1 `crypto_utils.py`

```python
import os
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_rsa_keypair(key_size=2048):
    """
    Generate RSA private/public key pair.
    Returns (private_key_object, public_key_object).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Serialize public key to PEM format (bytes).
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key, password=None):
    """
    Serialize private key to PEM format (bytes).
    Optionally encrypt with a password.
    """
    encryption_algo = serialization.NoEncryption()
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password.encode())

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algo
    )

def load_public_key(pem_data):
    """
    Load/deserialize a public key from PEM bytes.
    """
    return serialization.load_pem_public_key(pem_data)

def load_private_key(pem_data, password=None):
    """
    Load/deserialize a private key from PEM bytes, optionally with a password.
    """
    return serialization.load_pem_private_key(
        pem_data,
        password=password.encode() if password else None
    )

def generate_data_encryption_key():
    """
    Generate a 256-bit random key for AES.
    """
    return secrets.token_bytes(32)

def aes_encrypt(key, plaintext):
    """
    Encrypt plaintext with AES-256 in GCM mode.
    Return (iv, ciphertext, tag).
    """
    iv = secrets.token_bytes(12)  # recommended IV size for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def aes_decrypt(key, iv, ciphertext, tag):
    """
    Decrypt ciphertext with AES-256 in GCM mode.
    Return the plaintext.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def wrap_key_with_rsa(public_key, key_to_wrap):
    """
    Encrypt (wrap) the symmetric DEK with an RSA public key.
    """
    return public_key.encrypt(
        key_to_wrap,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def unwrap_key_with_rsa(private_key, wrapped_key):
    """
    Decrypt (unwrap) the symmetric DEK with an RSA private key.
    """
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def compute_hash_chain(prev_hash, log_data):
    """
    Compute SHA-256 hash that chains log entries (tamper-evident).
    """
    digest = hashes.Hash(hashes.SHA256())
    if isinstance(prev_hash, str):
        prev_hash = prev_hash.encode()
    digest.update(prev_hash)
    if isinstance(log_data, str):
        log_data = log_data.encode()
    digest.update(log_data)
    return digest.finalize().hex()

db_handler.py
import sqlite3
import os

DB_PATH = "secure_storage.db"

def init_db():
    """
    Create tables for users, files, and audit_log if they do not exist.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            wrappedDEK BLOB NOT NULL,
            ciphertext_path TEXT NOT NULL,
            metadata TEXT,
            FOREIGN KEY(owner_id) REFERENCES users(user_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            prev_hash TEXT,
            current_hash TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            operation TEXT,
            user_id TEXT,
            file_id TEXT
        )
    ''')
    conn.commit()
    conn.close()

def register_user(user_id, public_key_pem):
    """
    Insert (user_id, public_key) into users table.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO users (user_id, public_key) VALUES (?, ?)", (user_id, public_key_pem))
    conn.commit()
    conn.close()

def store_file_metadata(file_id, user_id, wrapped_dek, file_path, metadata=""):
    """
    Insert a record into the files table.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO files (file_id, owner_id, wrappedDEK, ciphertext_path, metadata) VALUES (?, ?, ?, ?, ?)",
              (file_id, user_id, wrapped_dek, file_path, metadata))
    conn.commit()
    conn.close()

def get_file_metadata(file_id):
    """
    Retrieve metadata for a given file_id.
    Returns (owner_id, wrappedDEK, ciphertext_path, metadata).
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT owner_id, wrappedDEK, ciphertext_path, metadata FROM files WHERE file_id=?", (file_id,))
    row = c.fetchone()
    conn.close()
    return row

def append_audit_log(user_id, file_id, operation, prev_hash, current_hash):
    """
    Insert an audit log entry referencing prev_hash and current_hash.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (prev_hash, current_hash, operation, user_id, file_id) VALUES (?, ?, ?, ?, ?)",
              (prev_hash, current_hash, operation, user_id, file_id))
    conn.commit()
    conn.close()

def get_last_log_hash():
    """
    Retrieve the most recent log entry's current_hash to chain the next log entry.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT current_hash FROM audit_log ORDER BY log_id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else "genesis"

server.py
import os
import base64
from flask import Flask, request, jsonify
from db_handler import init_db, store_file_metadata, get_file_metadata, append_audit_log, get_last_log_hash
from crypto_utils import compute_hash_chain

app = Flask(__name__)
init_db()

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Expects JSON:
    {
      "fileID": <string>,
      "userID": <string>,
      "wrappedDEK": <base64 string>,
      "ciphertext": <base64 string>,
      "metadata": <optional string>
    }
    """
    data = request.get_json()
    file_id = data['fileID']
    user_id = data['userID']
    wrapped_dek = base64.b64decode(data['wrappedDEK'])
    b64_ciphertext = data['ciphertext']
    metadata = data.get('metadata', "")

    # Write ciphertext to local folder "files/"
    if not os.path.exists("files"):
        os.makedirs("files")
    file_path = os.path.join("files", file_id)
    with open(file_path, "wb") as f:
        f.write(base64.b64decode(b64_ciphertext))

    # Store file metadata
    store_file_metadata(file_id, user_id, wrapped_dek, file_path, metadata)

    # Audit log
    prev_hash = get_last_log_hash()
    log_data = f"{user_id}{file_id}upload"
    current_hash = compute_hash_chain(prev_hash, log_data)
    append_audit_log(user_id, file_id, "upload", prev_hash, current_hash)

    return jsonify({"status": "ok"}), 200

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """
    Returns JSON with wrappedDEK and ciphertext in base64 form.
    """
    record = get_file_metadata(file_id)
    if not record:
        return jsonify({"error": "File not found"}), 404

    owner_id, wrapped_dek, ciphertext_path, meta = record
    with open(ciphertext_path, "rb") as f:
        ciphertext_bytes = f.read()
    b64_ciphertext = base64.b64encode(ciphertext_bytes).decode()

    # Audit log
    prev_hash = get_last_log_hash()
    log_data = f"{owner_id}{file_id}download"
    current_hash = compute_hash_chain(prev_hash, log_data)
    append_audit_log(owner_id, file_id, "download", prev_hash, current_hash)

    return jsonify({
        "wrappedDEK": base64.b64encode(wrapped_dek).decode(),
        "ciphertext": b64_ciphertext,
        "metadata": meta
    }), 200

@app.route('/rotateKey', methods=['POST'])
def rotate_key():
    """
    Expects JSON: { "userID": <string>, "newPublicKey": <PEM string> }
    Demonstrates how to re-wrap existing DEKs with a new public key.
    (Simplified: actual re-wrapping logic depends on design.)
    """
    data = request.get_json()
    user_id = data['userID']
    new_public_key_pem = data['newPublicKey']

    # In a real system, we would:
    # 1) For each file owned by user_id:
    #    - Unwrap old DEK (requires old private key, might be on client)
    #    - Re-wrap with new_public_key
    #    - Update DB
    # 2) Log the key rotation

    prev_hash = get_last_log_hash()
    log_data = f"{user_id}rotateKey"
    current_hash = compute_hash_chain(prev_hash, log_data)
    append_audit_log(user_id, "", "rotateKey", prev_hash, current_hash)

    return jsonify({"status": "rotation_completed"}), 200

if __name__ == "__main__":
    app.run(port=5000, debug=True)

client.py
import base64
import requests
from crypto_utils import (
    load_private_key,
    load_public_key,
    generate_data_encryption_key,
    aes_encrypt,
    aes_decrypt,
    wrap_key_with_rsa,
    unwrap_key_with_rsa
)

SERVER_URL = "http://127.0.0.1:5000"

def upload_file(file_path, file_id, user_id, user_public_key_pem):
    """
    1. Read plaintext from file_path
    2. Generate DEK
    3. Encrypt file (AES-GCM)
    4. Wrap DEK with user_public_key
    5. Send to /upload
    """
    # Load user's public key
    public_key = load_public_key(user_public_key_pem.encode())

    # Read file
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Generate DEK
    dek = generate_data_encryption_key()

    # AES-GCM encrypt
    iv, ciphertext, tag = aes_encrypt(dek, plaintext)

    # Wrap DEK
    wrapped_dek = wrap_key_with_rsa(public_key, dek)

    # Combine IV + ciphertext + tag for simpler storage
    combined = iv + ciphertext + tag

    payload = {
        "fileID": file_id,
        "userID": user_id,
        "wrappedDEK": base64.b64encode(wrapped_dek).decode(),
        "ciphertext": base64.b64encode(combined).decode(),
        "metadata": "Example file upload"
    }

    resp = requests.post(f"{SERVER_URL}/upload", json=payload)
    print("Upload response:", resp.json())

def download_file(file_id, user_private_key_pem, output_path, password=None):
    """
    1. GET /download/file_id
    2. Unwrap DEK with user's private key
    3. AES-GCM decrypt
    4. Save plaintext to output_path
    """
    # Load private key
    private_key = load_private_key(user_private_key_pem.encode(), password)

    resp = requests.get(f"{SERVER_URL}/download/{file_id}")
    if resp.status_code != 200:
        print("Error downloading file:", resp.text)
        return

    data = resp.json()
    wrapped_dek = base64.b64decode(data["wrappedDEK"])
    combined = base64.b64decode(data["ciphertext"])

    # Extract iv, ciphertext, tag (iv=12 bytes, tag=16 bytes)
    iv = combined[:12]
    tag = combined[-16:]
    ciphertext = combined[12:-16]

    # Unwrap DEK
    dek = unwrap_key_with_rsa(private_key, wrapped_dek)

    # Decrypt
    plaintext = aes_decrypt(dek, iv, ciphertext, tag)

    # Save to output
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"File saved to {output_path}")

if __name__ == "__main__":
    # Example usage:
    # 1) Suppose we have a userPublicKey.pem and userPrivateKey.pem
    # 2) upload_file("secret_doc.txt", "file123", "userA", userPublicKeyPEMstring)
    # 3) download_file("file123", userPrivateKeyPEMstring, "decrypted_doc.txt")
    pass
