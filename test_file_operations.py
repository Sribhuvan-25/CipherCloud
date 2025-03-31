import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_client import register_and_login
from test_config import BASE_URL
import os

def test_file_operations():
    # First get a token
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    
    print("\n=== Testing File Operations ===")
    
    # Generate a data encryption key (DEK)
    dek = AESGCM.generate_key(bit_length=256)
    print("Generated new DEK")
    
    # Load public key
    with open("keys/public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    print("Loaded public key")
    
    # Wrap (encrypt) the DEK with public key
    wrapped_dek = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Wrapped DEK with public key")
    
    # Create a test file
    test_data = b"Hello, this is a test file with some secret information!"
    print(f"\nOriginal content: {test_data.decode()}")
    
    # Encrypt the file with DEK
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)  # Use random nonce for production
    ciphertext = aesgcm.encrypt(nonce, test_data, None)
    print("Encrypted file content")
    
    # Upload encrypted file
    files = {
        'file': ('test.txt', nonce + ciphertext, 'application/octet-stream')
    }
    data = {
        'wrapped_dek': base64.b64encode(wrapped_dek).decode(),
        'metadata': '{"original_name": "test.txt", "description": "Test file"}'
    }
    
    print("\n=== Uploading File ===")
    response = requests.post(
        f"{BASE_URL}/upload",
        headers=headers,
        files=files,
        data=data
    )
    response.raise_for_status()
    upload_result = response.json()
    print("Upload response:", upload_result)
    file_id = upload_result["file_id"]
    
    print("\n=== Downloading File ===")
    # Download the file
    response = requests.get(
        f"{BASE_URL}/download/{file_id}",
        headers=headers
    )
    response.raise_for_status()
    download_data = response.json()
    print("Download successful")
    
    # Decrypt the downloaded file
    ciphertext = base64.b64decode(download_data["ciphertext"])
    wrapped_dek = base64.b64decode(download_data["wrappedDEK"])
    
    # Load private key
    with open("keys/private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    print("Loaded private key")
    
    # Unwrap (decrypt) the DEK
    dek = private_key.decrypt(
        wrapped_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Unwrapped DEK with private key")
    
    # Decrypt the file
    nonce = ciphertext[:12]
    file_ciphertext = ciphertext[12:]
    aesgcm = AESGCM(dek)
    plaintext = aesgcm.decrypt(nonce, file_ciphertext, None)
    print("\nDecrypted content:", plaintext.decode())
    
    # Verify the content matches
    assert test_data == plaintext, "Decrypted content doesn't match original!"
    print("\n=== Test Successful! ===")
    print("File encryption, upload, download, and decryption working correctly")

if __name__ == "__main__":
    test_file_operations() 