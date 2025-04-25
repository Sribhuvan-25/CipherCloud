import base64
import requests
import json
from pathlib import Path
from typing import Optional, Dict, Any
from ..utils.crypto import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    generate_data_encryption_key,
    aes_encrypt,
    aes_decrypt,
    wrap_key_with_rsa,
    unwrap_key_with_rsa
)

"""
app_demo.py does exactly the same thing as this file. Without using this class. This was built later and didn't have enough 
time to refactor the code. But the functionality is the same in app_demo.py. of client side encryption even though this class is not used.

"""

class SecureCloudClient:
    def __init__(self, base_url: str, user_id: str):
        self.base_url = base_url.rstrip('/')
        self.user_id = user_id
        self.token: Optional[str] = None
        self._private_key = None
        self._public_key = None

    def generate_keypair(self, save_dir: Optional[Path] = None) -> Dict[str, bytes]:
        """Generate new RSA keypair for the user"""
        private_key, public_key = generate_rsa_keypair()
        self._private_key = private_key
        self._public_key = public_key

        if save_dir:
            save_dir = Path(save_dir)
            save_dir.mkdir(parents=True, exist_ok=True)
            
            with open(save_dir / f"{self.user_id}_private.pem", 'wb') as f:
                f.write(serialize_private_key(private_key))
            with open(save_dir / f"{self.user_id}_public.pem", 'wb') as f:
                f.write(serialize_public_key(public_key))

        return {
            'private_key': serialize_private_key(private_key),
            'public_key': serialize_public_key(public_key)
        }

    def load_private_key(self, key_path: str, password: Optional[str] = None):
        """Load private key from file"""
        with open(key_path, 'rb') as f:
            key_data = f.read()
        self._private_key = load_private_key(key_data, password)

    def set_token(self, token: str):
        """Set the authentication token"""
        self.token = token

    def _get_headers(self) -> Dict[str, str]:
        if not self.token:
            raise ValueError("Authentication token not set")
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }

    async def upload_file(self, file_path: str) -> Dict[str, Any]:
        """
        Upload a file with client-side encryption:
        1. Generate DEK
        2. Encrypt file with DEK
        3. Wrap DEK with public key
        4. Send to server
        """
        if not self._public_key:
            raise ValueError("Public key not loaded")

        # Read file
        file_path = Path(file_path)
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # Generate and use DEK for file encryption
        dek = generate_data_encryption_key()
        iv, ciphertext, tag = aes_encrypt(dek, plaintext)

        # Wrap DEK with public key
        wrapped_dek = wrap_key_with_rsa(self._public_key, dek)

        # Combine IV + ciphertext + tag
        encrypted_data = iv + ciphertext + tag

        # Prepare multipart form data
        files = {
            'file': (file_path.name, encrypted_data, 'application/octet-stream')
        }
        data = {
            'wrapped_dek': base64.b64encode(wrapped_dek).decode(),
            'metadata': json.dumps({
                'filename': file_path.name,
                'size': len(plaintext)
            })
        }

        # Send to server
        response = requests.post(
            f"{self.base_url}/api/v1/upload",
            files=files,
            data=data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()

    async def download_file(self, file_id: str, output_path: str) -> None:
        """
        Download and decrypt a file:
        1. Get encrypted file and wrapped DEK from server
        2. Unwrap DEK with private key
        3. Decrypt file with DEK
        """
        if not self._private_key:
            raise ValueError("Private key not loaded")

        # Get encrypted file from server
        response = requests.get(
            f"{self.base_url}/api/v1/download/{file_id}",
            headers=self._get_headers()
        )
        response.raise_for_status()
        data = response.json()

        # Decode wrapped DEK and encrypted file
        wrapped_dek = base64.b64decode(data['wrappedDEK'])
        encrypted_data = base64.b64decode(data['ciphertext'])

        # Extract IV, ciphertext, and tag
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]

        # Unwrap DEK and decrypt file
        dek = unwrap_key_with_rsa(self._private_key, wrapped_dek)
        plaintext = aes_decrypt(dek, iv, ciphertext, tag)

        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)

    async def rotate_key(self) -> Dict[str, Any]:
        """
        Rotate user's key pair:
        1. Generate new key pair
        2. Send new public key to server
        3. Update local private key
        """
        # Generate new key pair
        new_keys = self.generate_keypair()

        # Send new public key to server
        response = requests.post(
            f"{self.base_url}/api/v1/rotate-key",
            json={'new_public_key': new_keys['public_key'].decode()},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json() 