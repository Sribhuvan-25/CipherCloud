import requests
import base64
from test_config import BASE_URL
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def create_test_user(user_id: str):
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Save keys
    os.makedirs(f"keys/{user_id}", exist_ok=True)
    
    # Save private key
    with open(f"keys/{user_id}/private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"keys/{user_id}/public.pem", "wb") as f:
        f.write(public_key_data)
    
    # Register user
    response = requests.post(
        f"{BASE_URL}/register",
        json={
            "user_id": user_id,
            "public_key": base64.b64encode(public_key_data).decode()
        }
    )
    print(f"Registration response for {user_id}:", response.json())
    
    # Login
    response = requests.post(
        f"{BASE_URL}/token",
        data={
            "username": user_id,
            "password": "test_password"
        }
    )
    return response.json()["access_token"]


def upload_test_file(token: str, user_id: str = "user1", content: bytes = b"Test file content"):
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Generate DEK and encrypt file
        dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, content, None)
        
        # Load public key for the user
        with open(f"keys/{user_id}/public.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        
        # Wrap DEK with RSA-OAEP
        wrapped_dek = public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Upload file
        files = {
            'file': ('test.txt', nonce + ciphertext, 'application/octet-stream')
        }
        data = {
            'wrapped_dek': base64.b64encode(wrapped_dek).decode(),
            'metadata': '{"original_name": "test.txt", "description": "Test file"}'
        }
        
        response = requests.post(
            f"{BASE_URL}/upload",
            headers=headers,
            files=files,
            data=data
        )
        response.raise_for_status()
        return response.json()["file_id"]
    
    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        raise


def test_multi_user_update_delete():
    print("\n=== Testing Multi-User Update and Delete ===")
    
    try:
        # Create two test users
        user1_token = create_test_user("user1")
        user2_token = create_test_user("user2")
        
        # User 1 uploads a file
        print("\nUser 1 uploading file...")
        file_id = upload_test_file(user1_token, "user1")
        print(f"File uploaded with ID: {file_id}")
        
        # User 2 uploads a file
        print("\nUser 2 uploading file...")
        file_id_user2 = upload_test_file(user2_token, "user2", b"User 2's file content")
        print(f"User 2's file uploaded with ID: {file_id_user2}")
        
        # User 2 updates their file
        print("\nUser 2 updating their file...")
        headers = {"Authorization": f"Bearer {user2_token}"}
        new_content = b"Updated content for User 2's file"
        files = {
            'new_file': ('test.txt', new_content, 'application/octet-stream')
        }
        response = requests.put(
            f"{BASE_URL}/update/{file_id_user2}",
            headers=headers,
            files=files
        )
        response.raise_for_status()
        print("User 2's file updated successfully")
        
        # User 2 deletes their file
        print("\nUser 2 deleting their file...")
        response = requests.delete(
            f"{BASE_URL}/delete/{file_id_user2}",
            headers=headers
        )
        response.raise_for_status()
        print("User 2's file deleted successfully")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")
        raise


if __name__ == "__main__":
    test_multi_user_update_delete() 