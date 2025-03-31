# Secure Cloud File Storage with Automatic Key Rotation and Auditing

This **Markdown document** provides a **complete project specification** for creating a **secure file storage system**. The idea is to offer enough details so that an AI-based code generator (or any developer) can immediately begin **building the project** without confusion. The scope, objectives, security architecture, and implementation strategy are all presented in a single file. 

---

## Table of Contents
1. [Introduction](#introduction)  
2. [Project Description](#project-description)  
3. [Objectives and Expected Outcomes](#objectives-and-expected-outcomes)  
4. [Key Cryptographic Concepts](#key-cryptographic-concepts)  
5. [Technical Requirements](#technical-requirements)  
6. [System Architecture](#system-architecture)  
    1. [High-Level Overview](#high-level-overview)  
    2. [Detailed Workflow](#detailed-workflow)  
7. [Implementation Details](#implementation-details)  
    1. [Core Components](#core-components)  
    2. [File Upload Process (Encryption)](#file-upload-process-encryption)  
    3. [File Download Process (Decryption)](#file-download-process-decryption)  
    4. [Automatic Key Rotation](#automatic-key-rotation)  
    5. [Audit Logging](#audit-logging)  
8. [Project Structure](#project-structure)  
9. [Sample Data Models and APIs](#sample-data-models-and-apis)  
10. [Detailed Code Stubs](#detailed-code-stubs)  
    1. [crypto_utils.py](#cryptoutilspy)  
    2. [db_handler.py](#db_handlerpy)  
    3. [server.py](#serverpy)  
    4. [client.py](#clientpy)  
11. [Testing and Validation](#testing-and-validation)  
12. [Potential Enhancements](#potential-enhancements)  
13. [Conclusion](#conclusion)  

---

## 1. Introduction
Storing files in the cloud introduces **security and privacy challenges**. End users require guarantees that:
- **Confidentiality**: No one but authorized users can read file contents.  
- **Integrity**: Files can’t be manipulated or corrupted without detection.  
- **Availability**: Users can reliably access files when needed.  
- **Auditing**: Administrators and security teams can track who accessed or modified files and when.

This project addresses these challenges by implementing a client-server system that **encrypts files client-side**, manages cryptographic keys, automates key rotation, and logs all operations in a tamper-evident audit log.

---

## 2. Project Description
1. **Secure Cloud Storage**: A user uploads files to the server in encrypted form. The user alone has the ability to decrypt them.  
2. **Key Management**: Each file is encrypted with a unique symmetric key (Data Encryption Key – DEK). The DEK is itself encrypted (“wrapped”) with the user’s public key or a master key.  
3. **Automatic Key Rotation**: Mechanism to rotate keys periodically (or on demand) to reduce exposure time if a key is compromised.  
4. **Audit Logging**: All file operations (upload, download, key rotation) are recorded in a tamper-evident log, ensuring accountability and detectability of malicious modifications.

---

## 3. Objectives and Expected Outcomes
- **Objective 1**: Implement a secure **client-side encryption** workflow.  
- **Objective 2**: Manage **Data Encryption Keys (DEKs)** so the server can store them but **cannot** decrypt them.  
- **Objective 3**: Provide an interface for **automatic key rotation**, ensuring older DEKs or user keys can be replaced.  
- **Objective 4**: Create an **audit log** system that makes unauthorized changes or access attempts easy to detect.

**Expected outcomes** include:
1. A **server application** that stores encrypted files and handles metadata.  
2. A **client application** that encrypts files locally, uploads them, downloads them, and decrypts them.  
3. **Documentation** showing the cryptographic design, code structure, and usage instructions.

---

## 4. Key Cryptographic Concepts
1. **Symmetric Encryption (AES)**: 
   - AES (Advanced Encryption Standard) is used to encrypt the file contents.  
   - A randomly generated 256-bit **Data Encryption Key (DEK)** is used per file.

2. **Asymmetric Encryption (RSA or ECC)**:
   - Each user has a **public/private key pair**.  
   - The DEK is encrypted (“wrapped”) using the user’s **public key**. Only the corresponding **private key** can decrypt it.

3. **Key Rotation**:
   - Periodically generating new keys (user or system) and **re-encrypting** DEKs or data.  
   - Minimizes the damage if an old key is compromised.

4. **Audit Logging**:
   - Each operation is recorded with a **timestamp** and **cryptographic hash** or **digital signature** so tampering is detectable.

---

## 5. Technical Requirements

- **Language**: Python 3.x  
- **Crypto Libraries**:  
  - [cryptography](https://pypi.org/project/cryptography/) for AES, RSA/ECC, hashing, etc.  
- **Database**:  
  - Could be SQLite, PostgreSQL, or even a file-based system for storing metadata.  
- **Networking**:  
  - For simplicity, we can use a **REST** interface (with Flask/FastAPI) or raw **sockets**. The exact approach is up to the implementer.  
- **Operating Systems**:  
  - Should run on Linux, macOS, or Windows with minimal changes.  
- **Python Environment**:
  - pip install cryptography  
  - pip install flask (or FastAPI) if using a REST approach  

---

## 6. System Architecture

### 6.1 High-Level Overview


1. **Client**:
   - Generates/loads user private key.  
   - Encrypts files with a random DEK.  
   - Encrypts (wraps) that DEK with the user’s public key.  
   - Uploads `(encrypted_file, wrapped_DEK, metadata, signature/HMAC)` to the server.

2. **Server**:
   - Receives the upload.  
   - Stores the encrypted file and the `wrapped_DEK` in a database or filesystem.  
   - Maintains an **audit log** for each operation.  

3. **Key Rotation**:
   - On rotation, new user keys or new DEKs are generated, and existing data is re-wrapped or re-encrypted as needed.  
   - The server updates its records but never sees file plaintext.

4. **Audit Log**:
   - Each log entry includes a hash linking to the previous entry, forming a chain that’s tamper-evident.

---

### 6.2 Detailed Workflow
1. **File Upload**:  
   - Client requests a random DEK → encrypt file → wrap DEK → send to server.  
   - Server saves `(encrypted_file, wrapped_DEK, fileID, userID, metadata)`.

2. **File Download**:  
   - Client fetches `(wrapped_DEK, encrypted_file, metadata)` from server.  
   - Client unwraps DEK with private key → decrypts file locally.

3. **Automatic Key Rotation**:  
   - A scheduled job or admin command triggers new keys for a user.  
   - All DEKs for that user’s files are re-wrapped with the new public key.  
   - Older private keys remain valid for older files or are invalidated—depending on your design.

4. **Auditing**:  
   - For every upload, download, or rotation event, server records an entry:  
     - `timestamp`, `operation`, `userID`, `fileID`, `prevLogHash`, `currentLogHash`, ...
   - The chain of log entries prevents undetected tampering.

---

## 7. Implementation Details

### 7.1 Core Components

1. **User Key Pairs**:
   - **Generate** (RSA 2048 or ECC) for each user.  
   - **Store** the private key locally (client side).  
   - **Store** the public key on the server or in a DB table mapped by `userID`.

2. **Symmetric Encryption**:
   - Use AES-256 in GCM mode (preferred) for authenticated encryption.  
   - If using CBC mode, add an HMAC for authenticity.

3. **DEK Wrapping**:
   - For each file, generate a random 256-bit DEK.  
   - Encrypt (wrap) the DEK using the user’s public key: `wrappedDEK = RSA_Encrypt(publicKey, DEK)`.  
   - Store `wrappedDEK` alongside the encrypted file.

### 7.2 File Upload Process (Encryption)

1. **Client**:
   1. Generate or load user’s private key from disk.  
   2. Generate a random DEK (32 bytes).  
   3. Encrypt the file with the DEK (AES-GCM recommended).  
   4. Encrypt (wrap) the DEK using the user’s **public key**.  
   5. Send to server: 
      ```
      {
        "fileID": <some unique file identifier>,
        "wrappedDEK": <base64-encoded wrapped DEK>,
        "ciphertext": <base64-encoded AES ciphertext>,
        "authTagOrHmac": <optional, if not using GCM>
      }
      ```
2. **Server**:
   1. Receives the data.  
   2. Stores `(fileID, userID, wrappedDEK, ciphertext, metadata)`.  
   3. Logs an **upload event** (`operation="upload"`) in the audit trail.

### 7.3 File Download Process (Decryption)

1. **Client**:
   1. Requests the encrypted file from the server by providing `fileID`.  
   2. Receives `(wrappedDEK, ciphertext, ... )`.  
   3. Uses private key to unwrap the DEK: `DEK = RSA_Decrypt(privateKey, wrappedDEK)`.  
   4. Decrypts the ciphertext with the DEK (AES-GCM).  
   5. Obtains the original file in plaintext form.
2. **Server**:
   1. Looks up `(wrappedDEK, ciphertext, userID, etc.)` in its storage.  
   2. Sends them to the requesting client.  
   3. Logs a **download event** in the audit trail.

### 7.4 Automatic Key Rotation

1. **Rotation Trigger**:
   - Admin triggers or a scheduled script runs.  
2. **Server**:
   1. Generates a new key pair for the user or instructs the user to do so.  
   2. For each file belonging to that user, fetch the old `wrappedDEK`.  
   3. Temporarily decrypt the DEK using the old private key **(which might require client cooperation, if server never sees that private key)**.  
   4. Re-wrap the DEK with the new public key.  
   5. Update the DB record with the new `wrappedDEK`.  
   6. Log the key rotation event.  

*(Note: This step can be done entirely on the client side if the server does not possess the private key. The exact design is flexible.)*

### 7.5 Audit Logging

1. **Tamper-Evident Log**:
   - Each log entry includes: 
     - `timestamp`, `userID`, `fileID`, `operation`, `prevHash`, `entryHash`, ...
   - `entryHash` might be a SHA-256 of `(timestamp + userID + fileID + operation + prevHash)`.
   - The first entry references a known “genesis hash”.
2. **Server**:
   - Appends each new entry to the log.  
   - If an attacker modifies an old entry, the chain of hashes breaks.

---

## 8. Project Structure

A possible Python-based arrangement (using minimal or no frameworks):


1. **`crypto_utils.py`**: All cryptographic operations (key generation, AES encryption, RSA wrapping, logging hash).  
2. **`db_handler.py`**: Database (or file) operations for storing and retrieving metadata.  
3. **`server.py`**: Implements the server logic to handle file uploads, downloads, key rotation endpoints, and logging.  
4. **`client.py`**: Command-line or minimal GUI tool that interacts with the server, encrypts/decrypts data, manages private keys.  
5. **`logs/`**: Contains the audit log file if using a text-based approach.

---

## 9. Sample Data Models and APIs

### 9.1 Database Tables

- **Table: `users`**
  - `user_id` (primary key)  
  - `public_key` (text or bytes)  
  - `metadata` (optional)

- **Table: `files`**
  - `file_id` (primary key)  
  - `owner_id` (foreign key → `users.user_id`)  
  - `wrappedDEK` (blob)  
  - `ciphertext_path` (file path or blob)  
  - `metadata` (optional JSON)

- **Table: `audit_log`**
  - `log_id` (primary key)  
  - `prev_hash` (text)  
  - `current_hash` (text)  
  - `timestamp` (datetime)  
  - `operation` (e.g., upload/download/rotate)  
  - `user_id`  
  - `file_id`

### 9.2 Potential API Endpoints (if using REST)

- **POST** `/upload`
  - Request Body: `{ "fileID", "wrappedDEK", "ciphertext", ... }`
  - Response: `{"status":"ok"}`

- **GET** `/download/<fileID>`
  - Response: `{ "wrappedDEK", "ciphertext", ... }`

- **POST** `/rotateKey/<userID>`
  - Request Body: possibly new public key if the user generated a new one.
  - Response: `{"status":"rotation_completed"}`

---

## 10. Detailed Code Stubs

Below are **example stubs** in Python to guide AI-based code generation. These stubs are incomplete but provide **enough context** for an AI system to generate the entire working code.

### 10.1 `crypto_utils.py`
```python
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import keywrap
import secrets

def generate_rsa_keypair(key_size=2048):
    """
    Generate an RSA private key and derive its public key.
    Return (private_key, public_key) as cryptography objects.
    """
    # TODO: Implementation
    pass

def serialize_public_key(public_key):
    """
    Serialize a public key to PEM or similar format (bytes).
    """
    # TODO: Implementation
    pass

def serialize_private_key(private_key):
    """
    Serialize a private key to PEM (possibly encrypted with a passphrase).
    """
    # TODO: Implementation
    pass

def load_public_key(pem_data):
    """
    Deserialize a public key from PEM bytes.
    """
    # TODO: Implementation
    pass

def load_private_key(pem_data, password=None):
    """
    Deserialize a private key from PEM bytes, optionally using a password.
    """
    # TODO: Implementation
    pass

def generate_data_encryption_key():
    """
    Generate a random 256-bit key for AES encryption.
    """
    # TODO: Implementation
    pass

def aes_encrypt(key, plaintext):
    """
    Encrypt data with AES (256-bit) in GCM mode.
    Return (iv, ciphertext, tag).
    """
    # TODO: Implementation
    pass

def aes_decrypt(key, iv, ciphertext, tag):
    """
    Decrypt data with AES (256-bit) in GCM mode.
    Return plaintext bytes.
    """
    # TODO: Implementation
    pass

def wrap_key_with_rsa(public_key, key_to_wrap):
    """
    Encrypt (wrap) the symmetric key using an RSA public key.
    Return wrapped key bytes.
    """
    # TODO: Implementation
    pass

def unwrap_key_with_rsa(private_key, wrapped_key):
    """
    Decrypt (unwrap) the symmetric key using an RSA private key.
    Return the original symmetric key bytes.
    """
    # TODO: Implementation
    pass

def compute_hash_chain(prev_hash, log_data):
    """
    Combine the previous hash with the current log data, 
    compute a new hash (e.g., SHA-256) to maintain the chain.
    """
    # TODO: Implementation
    pass

db_handler.py
import sqlite3
import os

DB_PATH = "secure_storage.db"

def init_db():
    """
    Create tables if they don't exist:
    users, files, audit_log
    """
    # TODO: Implementation
    pass

def register_user(user_id, public_key_pem):
    """
    Store (user_id, public_key_pem) in 'users' table.
    """
    # TODO: Implementation
    pass

def store_file_metadata(file_id, user_id, wrapped_dek, file_path):
    """
    Insert row into 'files' table.
    """
    # TODO: Implementation
    pass

def get_file_metadata(file_id):
    """
    Retrieve row from 'files' table for file_id.
    Return the relevant fields (wrappedDEK, file_path, etc.).
    """
    # TODO: Implementation
    pass

def append_audit_log(user_id, file_id, operation, prev_hash, current_hash):
    """
    Insert new log entry into 'audit_log'.
    """
    # TODO: Implementation
    pass

def get_last_log_hash():
    """
    Retrieve the most recent log entry's current_hash 
    to chain the next one.
    """
    # TODO: Implementation
    pass

server.py
import os
from flask import Flask, request, jsonify, send_file
from db_handler import init_db, store_file_metadata, get_file_metadata, append_audit_log, get_last_log_hash
from crypto_utils import wrap_key_with_rsa, unwrap_key_with_rsa, compute_hash_chain

app = Flask(__name__)
init_db()

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Expects JSON with:
      fileID, userID, wrappedDEK, ciphertext (base64), etc.
    Stores them in DB or filesystem.
    Logs the event in the audit log.
    """
    # TODO: Implementation
    pass

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """
    Retrieve file metadata (wrappedDEK, path to ciphertext).
    Return as JSON or file stream.
    Log the event.
    """
    # TODO: Implementation
    pass

@app.route('/rotateKey', methods=['POST'])
def rotate_key():
    """
    Demonstrate key rotation for a user (on demand).
    Possibly triggers re-wrapping existing DEKs 
    with a new public key.
    Log the event.
    """
    # TODO: Implementation
    pass

if __name__ == "__main__":
    app.run(port=5000, debug=True)

client.py
import requests
import base64
from crypto_utils import (
    load_private_key,
    load_public_key,
    aes_encrypt,
    aes_decrypt,
    wrap_key_with_rsa,
    unwrap_key_with_rsa,
    generate_data_encryption_key
)

SERVER_URL = "http://127.0.0.1:5000"

def upload_file(file_path, file_id, user_id, user_public_key_pem):
    """
    1. Generate DEK
    2. Encrypt file
    3. Wrap DEK with user_public_key
    4. POST to /upload
    """
    # TODO: Implementation
    pass

def download_file(file_id, user_private_key_pem):
    """
    1. GET /download/file_id
    2. Unwrap DEK with user_private_key
    3. Decrypt ciphertext
    4. Save plaintext locally
    """
    # TODO: Implementation
    pass

if __name__ == "__main__":
    # Example usage:
    # 1) Register user (handled separately) 
    # 2) upload_file(...)
    # 3) download_file(...)
    pass
