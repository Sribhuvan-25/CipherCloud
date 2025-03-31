import requests
import base64
from test_client import register_and_login
from test_config import BASE_URL
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from test_file_operations import test_file_operations

def test_key_rotation():
    # First get a token
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    
    print("\n=== Testing Key Rotation ===")
    
    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Save new keys
    with open("keys/new_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("keys/new_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    # Rotate key
    with open("keys/new_public.pem", "rb") as f:
        new_public_key = f.read()
    
    response = requests.post(
        f"{BASE_URL}/rotate-key",
        headers=headers,
        json={"new_public_key": base64.b64encode(new_public_key).decode()}
    )
    print("Key rotation response:", response.json())
    
    # Move new keys to replace old keys
    os.replace("keys/new_private.pem", "keys/private.pem")
    os.replace("keys/new_public.pem", "keys/public.pem")
    
    # Try uploading and downloading with new key
    print("\nTesting file operations with new key...")
    test_file_operations()

if __name__ == "__main__":
    test_key_rotation() 