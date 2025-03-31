from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import base64
import os

class CryptoManager:
    @staticmethod
    def generate_key_pair():
        """Generate an RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_public_key(public_key):
        """Serialize public key to PEM format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def serialize_private_key(private_key, password=None):
        """Serialize private key to PEM format with optional password"""
        encryption = (serialization.BestAvailableEncryption(password.encode())
                     if password else serialization.NoEncryption())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    @staticmethod
    def generate_file_key():
        """Generate a new AES key for file encryption"""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_file(key, data):
        """Encrypt file data using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_file(key, encrypted_data):
        """Decrypt file data using AES-GCM"""
        data = base64.b64decode(encrypted_data.encode('utf-8'))
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def wrap_key_with_rsa(public_key, key_to_wrap):
        """Wrap a symmetric key using RSA public key"""
        return public_key.encrypt(
            key_to_wrap,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def unwrap_key_with_rsa(private_key, wrapped_key):
        """Unwrap a symmetric key using RSA private key"""
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

def load_public_key(pem_data):
    """Load a public key from PEM format"""
    return serialization.load_pem_public_key(pem_data)

def load_private_key(pem_data, password=None):
    """Load a private key from PEM format"""
    return serialization.load_pem_private_key(
        pem_data,
        password=password.encode() if password else None
    )

# Export the functions directly for easier imports
wrap_key_with_rsa = CryptoManager.wrap_key_with_rsa
unwrap_key_with_rsa = CryptoManager.unwrap_key_with_rsa 