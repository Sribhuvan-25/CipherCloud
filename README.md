# Secure Cloud Storage System

A zero-knowledge encrypted cloud storage solution with end-to-end encryption, providing secure file storage while ensuring the server never has access to unencrypted data.

## Project Overview

This project implements a secure cloud storage system with the following features:

- **End-to-End Encryption**: All files are encrypted on the client side before being uploaded
- **Zero-Knowledge Architecture**: The server never sees unencrypted data or private keys
- **Tamper-Evident Audit Logs**: Cryptographically linked logs create a verifiable chain of events
- **Key Rotation**: Users can update their encryption keys while maintaining access to files
- **File Management**: Upload, download, update, and delete files securely
- **Interactive UI**: Streamlit-based demo interface for easy visualization of security features

The system uses a hybrid cryptographic approach, combining RSA for key protection and AES-GCM for efficient file encryption.

## Security Architecture

### Key Management

- **RSA Key Pair**: Each user has a 2048-bit RSA key pair
  - Public key: Stored on server, used to encrypt Data Encryption Keys (DEKs)
  - Private key: Kept by user only, needed to decrypt DEKs
  
- **AES File Encryption**: Each file gets a unique 256-bit AES key (DEK)
  - DEK is used to encrypt/decrypt the file contents
  - DEK is wrapped (encrypted) with the user's public key before storage

### Data Flow

1. **Upload Process**:
   - Client generates random AES key (DEK)
   - File is encrypted with DEK using AES-GCM
   - DEK is wrapped using user's public key
   - Encrypted file and wrapped DEK are sent to server

2. **Download Process**:
   - Client retrieves encrypted file and wrapped DEK
   - Client uses private key to unwrap (decrypt) the DEK
   - File is decrypted using the DEK

3. **Update Process**:
   - Client generates new DEK for the updated file
   - New file content is encrypted with the new DEK
   - New DEK is wrapped with user's public key
   - Server replaces old file while preserving file ID
   - Update operation is recorded in audit log

4. **Delete Process**:
   - Server removes encrypted file from storage
   - Wrapped DEK is deleted permanently
   - Metadata is preserved in audit log
   - Deletion entry is added to audit log
   - File ID cannot be reused

5. **Key Rotation**:
   - User generates new RSA key pair
   - Server re-encrypts all DEKs with new public key
   - User must save new private key

### Authentication

The system uses a challenge-response mechanism for secure user authentication:

1. **Login Process**:
   - User requests a challenge from the server
   - Server generates random challenge and encrypts it with user's public key
   - Client decrypts challenge using private key
   - Client signs challenge with private key
   - Server verifies signature using public key
   - If verification succeeds, access token is granted

2. **Security Features**:
   - Challenge-response prevents replay attacks
   - Private key possession is verified without transmission
   - All authentication attempts are logged in audit trail
   - Failed attempts are recorded for security monitoring

## Installation

### Prerequisites

- Python 3.8+
- SQLite (for the database)
- FastAPI (for the API server)
- Streamlit (for the demo UI)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-cloud-storage.git
   cd secure-cloud-storage
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Environment Setup

1. Create and activate a conda environment:
   ```bash
   conda create -n secure-cloud python=3.8
   conda activate secure-cloud
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### API Server

Start the FastAPI server:

```bash
python main.py
```

The API server will be available at http://localhost:8000

### Demo UI

Start the Streamlit demo interface:

```bash
streamlit run app_demo.py
```

The demo UI will be available at http://localhost:8501

## Usage Guide

### 1. Registration and Authentication

- **Register**: Create a user account and generate an RSA key pair
- **Download Private Key**: Save your private key securely (without it, data is lost)
- **Login**: Upload your private key to authenticate

### 2. File Operations

- **Upload**: Select a file to encrypt and upload
- **Download**: Decrypt and download your files
- **Update**: Modify a file while maintaining encryption
- **Delete**: Securely remove files

### 3. Security Features

- **Key Rotation**: Update your encryption keys periodically
- **Audit Trail**: View a tamper-evident log of all activities
- **Integrity Verification**: Validate the security of your audit logs

## Project Structure

```
secure-cloud-storage/
├── app/                    # Main application code
│   ├── api/                # API endpoints and route handlers
│   ├── core/               # Core functionality and configuration
│   ├── db/                 # Database models and operations
│   ├── client/             # Client-side implementation and secure operations
│   ├── utils/              # Utility functions for crypto and logging
│   └── main.py             # FastAPI application entry point
├── main.py                 # FastAPI application entry point             
├── app_demo.py             # Streamlit demo UI for interactive testing
├── requirements.txt        # Project dependencies and versions
└── README.md               # Project documentation and setup guide
```

## Security Considerations

- **Private Key Storage**: Users are responsible for storing their private key securely
- **Client-Side Security**: All encryption/decryption happens in the client's browser
- **No Key Recovery**: If a private key is lost, encrypted data cannot be recovered


## Acknowledgements

This project was developed as part of the CSC 8224 Cloud Security course. # CipherCloud
# CipherCloud
