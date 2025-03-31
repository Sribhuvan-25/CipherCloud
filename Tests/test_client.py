import requests
import base64
from test_config import BASE_URL
import os
import sys

def register_and_login():
    try:
        # Create keys directory if it doesn't exist
        os.makedirs("keys", exist_ok=True)
        
        # Generate key pair if it doesn't exist
        if not os.path.exists("keys/private.pem"):
            os.system("openssl genrsa -out keys/private.pem 2048")
            os.system("openssl rsa -in keys/private.pem -pubout -out keys/public.pem")
        
        # Read public key
        with open("keys/public.pem", "rb") as f:
            public_key = f.read()
        
        # Register/Update user
        response = requests.post(
            f"{BASE_URL}/register",
            json={
                "user_id": "test_user",
                "public_key": base64.b64encode(public_key).decode()
            }
        )
        response.raise_for_status()
        result = response.json()
        print("Registration:", result)
        
        if result["status"] != "success":
            raise ValueError(f"Registration failed: {result.get('detail', 'Unknown error')}")
        
        # Login to get token
        response = requests.post(
            f"{BASE_URL}/token",
            data={
                "username": "test_user",
                "password": "test_password"  # In a real system, use proper authentication
            }
        )
        response.raise_for_status()
        token_data = response.json()
        print("Login response:", token_data)
        
        if "access_token" not in token_data:
            raise ValueError("No access token in response")
            
        return token_data["access_token"]
    
    except requests.exceptions.RequestException as e:
        print(f"HTTP Error: {e}")
        if hasattr(e.response, 'json'):
            print("Error details:", e.response.json())
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    token = register_and_login()
    print("Access Token:", token) 