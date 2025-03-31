# Secure Cloud Storage System - Demo Guide & Cryptographic Features

## Overview
This guide demonstrates a secure cloud storage system implementing client-side encryption, key rotation, and tamper-evident logging using modern cryptographic techniques.

## 1. Project Components & Cryptographic Features

### Core Cryptographic Concepts
1. **Symmetric Encryption (AES-GCM)**
   - Data Encryption Keys (DEK) - 256-bit
   - Authenticated encryption
   - Unique IV/nonce per encryption

2. **Asymmetric Encryption (RSA)**
   - 2048-bit key pairs
   - OAEP padding for security
   - Used for key wrapping

3. **Key Wrapping**
   - DEK protection using RSA
   - Secure key transport
   - Key rotation support

4. **Hash Chaining**
   - SHA-256 based
   - Tamper-evident logging
   - Chronological integrity

## 2. Demo Flow & Test Cases

### Setup
```bash
# Start the server
python main.py

# Open new terminal for tests
cd /path/to/project
```

### Test 1: Basic File Operations
```bash
python test_file_operations.py
```
**Demonstrates:**
- DEK generation
- Client-side encryption
- Key wrapping
- Secure upload/download
- Successful decryption

### Test 2: Key Rotation
```bash
python test_key_rotation.py
```
**Demonstrates:**
- New key pair generation
- DEK re-wrapping
- Maintaining file access
- Rotation logging

### Test 3: Multi-User Security
```bash
python test_multi_user.py
```
**Demonstrates:**
- Multiple user support
- Access control enforcement
- User isolation
- Public key distribution

### Test 4: Audit Logging
```bash
python test_audit_log.py
```
**Demonstrates:**
- Operation logging
- Hash chain integrity
- Tamper detection
- Chronological verification

## 3. Security Properties

### Confidentiality
- Server never sees plaintext data
- Unique DEK per file
- Secure key wrapping

### Access Control
- Public key based access
- User isolation
- Permission enforcement

### Key Management
- Secure key generation
- Key rotation support
- Safe key distribution

### Integrity
- Hash-chained audit logs
- Tamper detection
- Operation verification

## 4. Cryptographic Algorithms

### AES-GCM
- Purpose: File encryption
- Key size: 256-bit
- Features:
  - Authenticated encryption
  - Integrity protection
  - Nonce handling

### RSA
- Purpose: Key wrapping
- Key size: 2048-bit
- Features:
  - OAEP padding
  - Public/private key pairs
  - Secure key transport

### SHA-256
- Purpose: Hash chaining
- Features:
  - Audit log integrity
  - Tamper detection
  - Sequential validation

## 5. Test Output Examples

### File Operations Test
```
=== Testing File Operations ===
Generated new DEK
Loaded public key
Wrapped DEK with public key
Upload successful
Download successful
Decryption verified
```

### Key Rotation Test
```
=== Testing Key Rotation ===
Generated new key pair
Key rotation successful
File access maintained
```

### Multi-User Test
```
=== Testing Multi-User Access ===
Users created
File upload successful
Access control verified
```

### Audit Log Test
```
=== Verifying Audit Log ===
Operations logged
Hash chain valid
No tampering detected
```

## 6. Implementation Details

### File Structure
```
secure_file_storage/
├── app/
│   ├── api/
│   │   └── routes.py
│   ├── core/
│   │   └── config.py
│   ├── utils/
│   │   ├── crypto.py
│   │   └── logging.py
│   └── db/
│       └── models.py
├── storage/
│   ├── files/
│   └── logs/
└── tests/
    └── test_*.py
```

### Key Files
- `crypto.py`: Cryptographic operations
- `logging.py`: Audit logging
- `models.py`: Data storage
- `routes.py`: API endpoints

## 7. Future Enhancements
1. Enhanced error handling
2. Backup/recovery procedures
3. Key expiration policies
4. Additional audit features

---
This demo guide provides a comprehensive overview of the system's cryptographic features and security properties, along with practical demonstration steps. 