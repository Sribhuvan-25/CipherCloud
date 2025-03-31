from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

def generate_keys(user_directory):
    # Ensure the user directory exists
    os.makedirs(user_directory, exist_ok=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Write private key to file
    with open(os.path.join(user_directory, "private.pem"), "wb") as f:
        f.write(private_pem)

    # Generate public key
    public_key = private_key.public_key()

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write public key to file
    with open(os.path.join(user_directory, "public.pem"), "wb") as f:
        f.write(public_pem)

    print(f"Keys generated for {user_directory}")

# Example usage
generate_keys("keys/user3")