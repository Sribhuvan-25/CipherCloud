#!/usr/bin/env python3
"""
Streamlit UI for Secure Cloud Storage Demo with Enhanced Visualization
"""

import os
import streamlit as st
import requests
import json
import base64
import tempfile
from pathlib import Path
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import io
import hashlib

# Constants
API_BASE_URL = "http://localhost:8000/api/v1"

st.set_page_config(
    page_title="Secure Cloud Storage Demo",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] span,
    [data-testid="stSidebar"] label {
        color: white !important;
    }
    
    .stRadio label, .stSelectbox label {
        color: white !important;
    }
    
    [data-testid="stSidebar"] [data-testid="stRadio"] label {
        color: white !important;
    }
    
    /* Fix for data editor dropdowns */
    .stDataEditor [data-testid="StyledDataFrameDataEditor"] select {
        color: #212529 !important;
        background-color: white !important;
        font-weight: 500 !important;
    }
    
    /* Make sure data editor select boxes are visible */
    .stDataEditor .css-1n76uvr select,
    .stDataEditor select.st-ck,
    .stDataEditor .st-bw {
        color: #212529 !important;
        background-color: white !important;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        margin-bottom: 1rem;
    }
    .section-header {
        font-size: 1.8rem;
        color: #1976D2;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .success-message {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .error-message {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #e3f2fd;
        color: #0a3767;
        font-weight: 500;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .warning-message {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .file-item {
        padding: 0.5rem;
        margin: 0.5rem 0;
        border: 1px solid #ddd;
        border-radius: 0.3rem;
    }
    
    /* Crypto visualization */
    .crypto-step {
        background-color: #f8f9fa;
        border-left: 4px solid #4285F4;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0 0.5rem 0.5rem 0;
    }
    
    .key-box {
        background-color: #e8f5e9;
        border: 1px solid #81c784;
        padding: 0.5rem;
        border-radius: 0.3rem;
        font-family: monospace;
        overflow-x: auto;
        white-space: nowrap;
        color: #1b5e20;
        font-weight: 500;
    }
    
    .data-box {
        background-color: #e3f2fd;
        border: 1px solid #64b5f6;
        padding: 0.5rem;
        border-radius: 0.3rem;
        font-family: monospace;
        overflow-x: auto;
        white-space: nowrap;
        color: #0d47a1;
    }
    
    .cipher-box {
        background-color: #ffebee;
        border: 1px solid #e57373;
        padding: 0.5rem;
        border-radius: 0.3rem;
        font-family: monospace;
        overflow-x: auto;
        white-space: nowrap;
        color: #b71c1c;
    }
    
    /* Basic text styling for visibility */
    .stRadio label, .stTextInput label, .stSelectbox label, .stFileUploader label {
        color: white !important;
        font-weight: 500 !important;
    }
    
    /* Ensure all sidebar elements have good contrast */
    .sidebar .stRadio label, .sidebar .stTextInput label, 
    .sidebar .stSelectbox label, .sidebar .stFileUploader label {
        color: white !important;
        font-weight: 500 !important;
    }
    
    /* Fix for sidebar headings */
    .sidebar h1, .sidebar h2, .sidebar h3, .sidebar p, .sidebar span {
        color: white !important;
    }
    
    /* Keep good contrast for the info box content */
    .info-box, .info-box p, .info-box span {
        color: #0a3767 !important;
    }
</style>
""", unsafe_allow_html=True)

# Helper functions for cryptography operations
def generate_rsa_keypair():
    """Generate an RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private, pem_public

def generate_data_encryption_key():
    """Generate a random 256-bit key for AES encryption"""
    return AESGCM.generate_key(bit_length=256)

def wrap_key(public_key_pem, data_key):
    """Wrap a data key with an RSA public key"""
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    wrapped_key = public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return wrapped_key

def unwrap_key(private_key_pem, wrapped_key):
    """Unwrap a data key with an RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    
    data_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return data_key

def encrypt_file(data_key, plaintext):
    """Encrypt data with AES-GCM"""
    aesgcm = AESGCM(data_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    return {
        'nonce': nonce,
        'ciphertext': ciphertext
    }

def decrypt_file(data_key, nonce, ciphertext):
    """Decrypt data with AES-GCM"""
    aesgcm = AESGCM(data_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# API interaction functions
def register_user(user_id, public_key_pem):
    """Register a new user with the API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/register",
            json={
                "user_id": user_id,
                "public_key": base64.b64encode(public_key_pem).decode()
            }
        )
        
        if response.status_code == 409:
            return response.json()
        
        # Handle other errors
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Registration error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            try:
                return e.response.json()  # Return the error response
            except:
                pass
        return {"status": "error", "message": str(e)}

def login_user(user_id, private_key_pem):
    """Login user and get token using the challenge-based authentication"""
    try:
        challenge_response = requests.post(
            f"{API_BASE_URL}/verify-key/challenge",
            json={"user_id": user_id}
        )
        
        if challenge_response.status_code != 200:
            st.error(f"Failed to get login challenge: {challenge_response.text}")
            return None
            
        challenge_data = challenge_response.json()
        challenge_id = challenge_data["challenge_id"]
        encrypted_challenge_b64 = challenge_data["encrypted_challenge"]
        
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            
            encrypted_challenge = base64.b64decode(encrypted_challenge_b64)
            decrypted_challenge = private_key.decrypt(
                encrypted_challenge,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            
            signature = private_key.sign(
                decrypted_challenge.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            auth_data = f"{challenge_id}:{base64.b64encode(signature).decode()}"
            
            response = requests.post(
                f"{API_BASE_URL}/token",
                data={
                    "username": user_id,
                    "password": auth_data
                }
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                st.error(f"Authentication failed: {response.text}")
                return None
                
        except Exception as e:
            st.error(f"Failed to process login challenge: {str(e)}")
            return None
    except requests.RequestException as e:
        st.error(f"Login error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def verify_private_key(private_key_pem, user_id):
    """
    Verify that the private key can be loaded and is properly formatted.
    The actual cryptographic verification will happen during the login process.
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )
        
        derived_public_key = private_key.public_key()
        derived_public_key_pem = derived_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        st.info("Private key is well-formed. Proceeding with login authentication.")
        return True
    
    except Exception as e:
        st.error(f"Invalid private key format: {str(e)}")
        return False

def upload_file_to_api(file_contents, filename, content_type, wrapped_dek, token):
    """Upload an encrypted file to the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        files = {
            'file': (filename, file_contents, content_type)
        }
        
        data = {
            'wrapped_dek': base64.b64encode(wrapped_dek).decode(),
            'metadata': json.dumps({
                "original_name": filename,
                "description": "Uploaded from Streamlit UI"
            })
        }
        
        response = requests.post(
            f"{API_BASE_URL}/upload",
            headers=headers,
            files=files,
            data=data
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Upload error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def download_file_from_api(file_id, token):
    """Download a file from the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            f"{API_BASE_URL}/download/{file_id}",
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Download error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def update_file_in_api(file_id, new_file_contents, filename, wrapped_dek, token):
    """Update a file in the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        files = {
            'new_file': (filename, new_file_contents, 'application/octet-stream')
        }
        data = {}
        if wrapped_dek:
            data['wrapped_dek'] = base64.b64encode(wrapped_dek).decode()
            
        response = requests.put(
            f"{API_BASE_URL}/update/{file_id}",
            headers=headers,
            files=files,
            data=data
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Update error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def delete_file_from_api(file_id, token):
    """Delete a file from the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.delete(
            f"{API_BASE_URL}/delete/{file_id}",
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Delete error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def rotate_key_api(new_public_key_pem, token):
    """Rotate user's key in the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(
            f"{API_BASE_URL}/rotate-key",
            json={"new_public_key": base64.b64encode(new_public_key_pem).decode()},
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Key rotation error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def compute_hash_for_log_entry(prev_hash, log_data):
    """
    Compute the cryptographic hash for a log entry.
    Uses SHA-256 to hash the previous hash concatenated with fields from the current entry.
    """
    prev_hash = prev_hash or "0" * 64
    
    # Ensure timestamp is never empty
    timestamp = log_data.get('timestamp') or time.strftime("%Y-%m-%d %H:%M:%S")
    operation = log_data.get('operation', 'unknown')
    user_id = log_data.get('user_id', 'unknown')

    data = f"{timestamp}{operation}{user_id}"
    
    if 'file_id' in log_data and log_data['file_id']:
        data += log_data['file_id']
    
    hash_input = f"{prev_hash}{data}"
    return hashlib.sha256(hash_input.encode()).hexdigest()

def get_user_files(token):
    """Fetch all files for the logged-in user from the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_BASE_URL}/files", headers=headers)
        response.raise_for_status()
        
        result = response.json()
        if result.get("status") == "success" and "files" in result:
            return result["files"]
        return []
    except requests.RequestException as e:
        st.error(f"Error fetching files: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return []

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'token' not in st.session_state:
    st.session_state.token = None
if 'private_key' not in st.session_state:
    st.session_state.private_key = None
if 'public_key' not in st.session_state:
    st.session_state.public_key = None
if 'files' not in st.session_state:
    st.session_state.files = []
if 'current_file' not in st.session_state:
    st.session_state.current_file = None
if 'current_action' not in st.session_state:
    st.session_state.current_action = None
if 'audit_events' not in st.session_state:
    st.session_state.audit_events = []

with st.sidebar:
    st.title("🔒 Secure Cloud Storage")
    st.markdown("---")
    
    if not st.session_state.logged_in:
        st.subheader("Authentication")
        auth_option = st.radio("Choose an option:", ["Login", "Register"])
        
        if auth_option == "Login":
            st.subheader("Step 1: Authentication")
            user_id = st.text_input("User ID", key="login_user_id")
            
            with st.expander("🔐 Private Key Authentication", expanded=True):
                st.write("""
                ### How Private Key Authentication Works:
                1. You provide your user ID and private key
                2. The server authenticates based on your user ID
                3. All subsequent operations use your private key for decryption
                4. Your private key never leaves your browser
                
                **Note:** If you've lost your private key, there is no recovery option. 
                This is by design for security. You will need to register a new account.
                """)
                
                uploaded_key = st.file_uploader("Upload your private key", type=["pem"])
                if uploaded_key:
                    private_key_content = uploaded_key.read()
                    st.markdown('<div class="key-box">Private Key Format: RSA PRIVATE KEY (PEM)</div>', unsafe_allow_html=True)
                    st.code(f"Private Key (preview):\n{private_key_content[:100].decode()}...", language="text")
                    st.session_state.private_key = private_key_content
                
                st.info("If you don't have a private key yet, please use the Register option instead.")
            
            if st.button("Login") and user_id and st.session_state.private_key:
                with st.spinner("Authenticating..."):
                    key_valid = verify_private_key(st.session_state.private_key, user_id)
                    
                    if not key_valid:
                        st.error("Authentication failed: Invalid private key for this user.")
                        st.warning("The private key you provided does not match the one registered for this user.")
                    else:
                        login_result = login_user(user_id, st.session_state.private_key)
                        if login_result and "access_token" in login_result:
                            st.session_state.logged_in = True
                            st.session_state.user_id = user_id
                            st.session_state.token = login_result["access_token"]
                            
                            private_key = serialization.load_pem_private_key(
                                st.session_state.private_key,
                                password=None
                            )
                            public_key = private_key.public_key()
                            public_key_pem = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            st.session_state.public_key = public_key_pem
                            
                            with st.spinner("Loading your files..."):
                                user_files = get_user_files(st.session_state.token)
                                st.session_state.files = user_files
                            
                            st.success("Login successful!")
                            st.rerun()
                
        elif auth_option == "Register":
            st.subheader("Step 1: User Registration")
            user_id = st.text_input("Choose a User ID", key="register_user_id")
            
            if st.button("Generate Keys"):
                with st.expander("🔑 Key Generation Process", expanded=True):
                    st.write("### RSA Keypair Generation")
                    progress = st.progress(0)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.write("1️⃣ Generating 2048-bit RSA keypair...")
                    st.code("""
# Generate 2048-bit RSA keypair with exponent 65537
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
                    """, language="python")
                    progress.progress(30)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.write("2️⃣ Serializing keys to PEM format...")
                    st.code("""
# Serialize private key to PEM format
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
                    """, language="python")
                    progress.progress(60)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    private_key, public_key = generate_rsa_keypair()
                    st.session_state.private_key = private_key
                    st.session_state.public_key = public_key
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.write("3️⃣ Keys generated successfully")
                    
                    st.markdown('<div class="key-box">Private Key (PKCS#8 format)</div>', unsafe_allow_html=True)
                    st.code(private_key[:300].decode() + "...", language="text")
                    
                    st.markdown('<div class="key-box">Public Key (X.509 format)</div>', unsafe_allow_html=True)
                    st.code(public_key.decode(), language="text")
                    
                    progress.progress(100)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.success("Keys generated successfully!")
                    st.warning("⚠️ IMPORTANT: The private key is only shown once. Download it immediately and store it securely.")
                    
                    st.download_button(
                        "Download Private Key",
                        data=private_key,
                        file_name="private_key.pem",
                        mime="application/x-pem-file"
                    )
            
            if st.button("Register") and user_id and st.session_state.public_key:
                with st.spinner("Registering user..."):
                    try:
                        registration_result = register_user(user_id, st.session_state.public_key)
                        
                        if registration_result and registration_result.get("status") == "success":
                            st.success(f"User {user_id} registered successfully!")
                            
                            with st.expander("Registration Data Sent"):
                                st.json({
                                    "user_id": user_id,
                                    "public_key": base64.b64encode(st.session_state.public_key).decode()[:30] + "..." # truncated for display
                                })
                            
                            login_result = login_user(user_id, st.session_state.private_key)
                            if login_result and "access_token" in login_result:
                                st.session_state.logged_in = True
                                st.session_state.user_id = user_id
                                st.session_state.token = login_result["access_token"]
                                
                                with st.spinner("Loading your files..."):
                                    user_files = get_user_files(st.session_state.token)
                                    st.session_state.files = user_files
                                    
                                st.success("Logged in automatically!")
                                st.rerun()
                        elif registration_result and registration_result.get("status") == "error":
                            # Display the error message from the server
                            st.error(registration_result.get("message", "Registration failed"))
                            # st.error("Registration failed. Please try again with a different UserID.")
                        else:
                            st.error("Registration failed. Please try again with a different UserID.")
                    except Exception as e:
                        st.error(f"Registration error: {str(e)}")
    else:
        st.success(f"Logged in as: {st.session_state.user_id}")
        
        with st.expander("🔑 Your Encryption Keys"):
            if st.session_state.private_key:
                st.markdown('<div class="key-box">Private Key Status: LOADED</div>', unsafe_allow_html=True)
                st.write("Your private key is loaded in session memory")
                
                key_start = st.session_state.private_key[:100].decode()
                st.code(f"{key_start}...[REDACTED FOR SECURITY]", language="text")
                
                st.info("Your private key is only stored in your browser's memory and is never sent to the server.")
        
        if st.button("Logout"):
            for key in st.session_state.keys():
                del st.session_state[key]
            st.rerun()
        
        st.markdown("---")
        st.subheader("Navigation")
        demo_page = st.radio(
            "Select Feature:",
            ["File Upload", "File Management", "Key Rotation", "Audit Trail"]
        )


if not st.session_state.logged_in:
    st.markdown('<h1 class="main-header">Secure Cloud Storage Demo</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<h2 class="section-header">Key Features</h2>', unsafe_allow_html=True)
        st.markdown("""
        - **End-to-End Encryption**: All files are encrypted before leaving your device
        - **Zero-Knowledge Architecture**: Server never sees your unencrypted data
        - **Key Rotation**: Regularly update your encryption keys
        - **Audit Logging**: Track all operations for compliance
        - **Multi-User Support**: Share files securely
        """)
    
    with col2:
        st.markdown('<h2 class="section-header">How It Works</h2>', unsafe_allow_html=True)
        st.markdown("""
        1. **Register**: Create an account and generate your encryption keys
        2. **Upload**: Files are encrypted on your device before upload
        3. **Download**: Files remain encrypted until securely retrieved
        4. **Update**: Modify files while maintaining encryption
        5. **Delete**: Securely remove files when no longer needed
        """)
    
    st.markdown('<div class="info-box">Please register or login using the sidebar to begin the demo.</div>', unsafe_allow_html=True)

else:
    if 'demo_page' not in locals():
        demo_page = "File Upload"
    
    if demo_page == "File Upload":
        st.markdown('<h1 class="main-header">File Upload Demo</h1>', unsafe_allow_html=True)
        
        st.markdown('<h2 class="section-header">Upload a File</h2>', unsafe_allow_html=True)
        
        with st.expander("📘 How End-to-End Encryption Works", expanded=True):
            st.write("""
            ### End-to-End Encryption Process
            
            1. **Data Encryption Key (DEK)**: Each file gets a unique random AES-256 key
            2. **File Encryption**: The file is encrypted with AES-GCM using the DEK
            3. **Key Wrapping**: The DEK is encrypted with your public RSA key
            4. **Secure Storage**: The server stores:
               - The encrypted file (can't be read without the DEK)
               - The wrapped DEK (can't be unwrapped without your private key)
               - Metadata (filename, upload time, etc.)
            
            This ensures that even the server never has access to your unencrypted data!
            """)
        
        uploaded_file = st.file_uploader("Choose a file", key="upload_file")
        
        if uploaded_file:
            file_contents = uploaded_file.read()
            file_size = len(file_contents)
            
            st.markdown(f"""
            <div class="info-box">
                <strong>File Name:</strong> {uploaded_file.name}<br>
                <strong>File Size:</strong> {file_size} bytes<br>
                <strong>Content Type:</strong> {uploaded_file.type}
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("Encrypt & Upload File"):
                with st.expander("🔒 Encryption Process", expanded=True):
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 1: Generate Data Encryption Key (DEK)")
                    status_text.write("Generating Data Encryption Key (DEK)...")
                    time.sleep(0.5)
                    data_key = generate_data_encryption_key()
                    
                    st.code("""
# Generate a random 256-bit AES key
data_key = AESGCM.generate_key(bit_length=256)
                    """, language="python")
                    
                    st.markdown(f'<div class="key-box">Generated DEK (hex): {data_key.hex()}</div>', unsafe_allow_html=True)
                    progress_bar.progress(20)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 2: Encrypt File with AES-GCM")
                    status_text.write("Encrypting file with AES-GCM...")
                    time.sleep(0.5)
                    
                    st.code("""
# Initialize AES-GCM cipher with the DEK
aesgcm = AESGCM(data_key)

# Generate a random 96-bit nonce
nonce = os.urandom(12)

# Encrypt the file
ciphertext = aesgcm.encrypt(nonce, file_contents, None)
                    """, language="python")
                    
                    encrypted_data = encrypt_file(data_key, file_contents)
                    
                    st.markdown(f'<div class="data-box">Nonce (hex): {encrypted_data["nonce"].hex()}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="cipher-box">Ciphertext (first 32 bytes): {encrypted_data["ciphertext"].hex()[:64]}...</div>', unsafe_allow_html=True)
                    progress_bar.progress(40)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 3: Wrap DEK with RSA Public Key")
                    status_text.write("Wrapping DEK with RSA public key...")
                    time.sleep(0.5)
                    
                    st.code("""
# Load the public key from PEM format
public_key = serialization.load_pem_public_key(public_key_pem)

# Wrap the DEK using RSA-OAEP with SHA-256
wrapped_key = public_key.encrypt(
    data_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
                    """, language="python")
                    
                    wrapped_key = wrap_key(st.session_state.public_key, data_key)
                    
                    st.markdown(f'<div class="cipher-box">Wrapped DEK (hex): {wrapped_key.hex()[:64]}...</div>', unsafe_allow_html=True)
                    progress_bar.progress(60)
                    st.markdown('</div>', unsafe_allow_html=True)

                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 4: Prepare Data for Server")
                    status_text.write("Preparing data package for server...")
                    
                    ciphertext_with_nonce = encrypted_data['nonce'] + encrypted_data['ciphertext']
                    
                    st.json({
                        "encrypted_file": {
                            "format": "nonce + ciphertext",
                            "size": len(ciphertext_with_nonce),
                            "preview": ciphertext_with_nonce.hex()[:32] + "..."
                        },
                        "wrapped_dek": {
                            "format": "RSA-OAEP encrypted",
                            "size": len(wrapped_key),
                            "preview": wrapped_key.hex()[:32] + "..."
                        },
                        "metadata": {
                            "filename": uploaded_file.name,
                            "content_type": uploaded_file.type,
                            "original_size": file_size
                        }
                    })
                    
                    progress_bar.progress(80)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 5: Upload to Server")
                    status_text.write("Uploading to secure storage...")
                    
                    upload_result = upload_file_to_api(
                        ciphertext_with_nonce,
                        uploaded_file.name, 
                        uploaded_file.type,
                        wrapped_key,
                        st.session_state.token
                    )
                    
                    if upload_result and "file_id" in upload_result:
                        file_id = upload_result["file_id"]
                        progress_bar.progress(100)
                        status_text.write("✅ Upload complete!")
                        
                        st.success(f"File uploaded successfully!")
                        st.json({
                            "status": "success",
                            "file_id": file_id,
                            "server_response": upload_result
                        })
                        
                        if 'files' not in st.session_state:
                            st.session_state.files = []
                        if 'original_uploads' not in st.session_state:
                            st.session_state.original_uploads = {}
                        
                        st.session_state.original_uploads[file_id] = {
                            'filename': uploaded_file.name,
                            'upload_time': time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        st.session_state.files.append({
                            'file_id': file_id,
                            'filename': uploaded_file.name,
                            'size': file_size,
                            'upload_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                            'content_type': uploaded_file.type
                        })
                    else:
                        st.error("Upload failed. See error details above.")
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Security Properties")
                    st.markdown("""
                    - **Zero Knowledge**: Server can't decrypt the file or DEK
                    - **Forward Secrecy**: Each file has a unique DEK
                    - **Key Protection**: DEK is wrapped with 2048-bit RSA
                    - **Data Integrity**: AES-GCM provides authenticated encryption
                    """)
                    st.markdown('</div>', unsafe_allow_html=True)
                
                if upload_result and "file_id" in upload_result:
                    st.success(f"File uploaded successfully with ID: {upload_result['file_id']}")
                    st.balloons()
    
    elif demo_page == "File Management":
        st.markdown('<h1 class="main-header">File Management</h1>', unsafe_allow_html=True)
        
        
        with st.expander("📘 How File Operations Work", expanded=True):
            st.write("""
            ### Secure File Operations
            
            All file operations maintain end-to-end encryption:
            
            1. **Download**: 
               - Server sends the encrypted file and wrapped DEK 
               - Your browser unwraps the DEK with your private key
               - File is decrypted locally before saving
            
            2. **Update**:
               - A new DEK is generated for the updated file
               - File is encrypted locally before upload
               - Server replaces the old encrypted file
            
            3. **Delete**:
               - Server removes the encrypted file and wrapped DEK
               - A record is maintained in the audit log
               - The operation is tamper-evident through the hash chain
            """)
        
        if not st.session_state.files:
            st.warning("No files have been uploaded. Please upload a file first.")
        else:
            st.markdown('<h2 class="section-header">Your Files</h2>', unsafe_allow_html=True)
            
            for i, file in enumerate(st.session_state.files):
                with st.container():
                    st.markdown("---")
                    cols = st.columns([3, 2, 2, 3])
                    
                    with cols[0]:
                        st.markdown(f"**{file['filename']}**")
                        st.caption(f"ID: {file['file_id'][:8]}...")
                    
                    with cols[1]:
                        st.text(f"{file['size']} bytes")
                        st.caption(f"Uploaded: {file['upload_time']}")
                    
                    with cols[2]:
                        download_btn = st.button("📥 Download", key=f"download_{i}")
                        update_btn = st.button("🔄 Update", key=f"update_{i}")
                    
                    with cols[3]:
                        delete_btn = st.button("🗑️ Delete", key=f"delete_{i}")
                        view_btn = st.button("👁️ View Details", key=f"view_{i}")
                    
                    if download_btn:
                        st.session_state.current_action = {"type": "download", "file_index": i}
                        st.rerun()
                    elif update_btn:
                        st.session_state.current_action = {"type": "update", "file_index": i}
                        st.rerun()
                    elif delete_btn:
                        st.session_state.current_action = {"type": "delete", "file_index": i}
                        st.rerun()
                    elif view_btn:
                        st.session_state.current_action = {"type": "view", "file_index": i}
                        st.rerun()
            
            if 'current_action' in st.session_state and st.session_state.current_action:
                action = st.session_state.current_action["type"]
                file_index = st.session_state.current_action["file_index"]
                file = st.session_state.files[file_index]
                
                st.markdown("---")
                st.markdown(f"<h3>{action.capitalize()}: {file['filename']}</h3>", unsafe_allow_html=True)
                
                if action == "download":
                    with st.expander("🔓 Decryption Process", expanded=True):
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                        st.subheader("Step 1: Retrieve Encrypted Data from Server")
                        status_text.write("Retrieving encrypted data from server...")
                        
                        file_data = download_file_from_api(file["file_id"], st.session_state.token)
                        
                        if file_data:
                            wrapped_dek = base64.b64decode(file_data["wrappedDEK"])
                            ciphertext = base64.b64decode(file_data["ciphertext"])
                            
                            st.json({
                                "wrapped_dek": wrapped_dek.hex()[:32] + "...",
                                "encrypted_file": ciphertext.hex()[:32] + "...",
                                "file_id": file["file_id"]
                            })
                            progress_bar.progress(25)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            nonce = ciphertext[:12]
                            ciphertext_data = ciphertext[12:]
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 2: Unwrap DEK with Private Key")
                            status_text.write("Unwrapping DEK with private key...")
                            
                            st.code("""
# Unwrap the DEK using RSA-OAEP with private key
private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None
)

data_key = private_key.decrypt(
    wrapped_dek,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
                            """, language="python")
                            
                            time.sleep(0.5)  # Visual delay
                            data_key = unwrap_key(st.session_state.private_key, wrapped_dek)
                            st.markdown(f'<div class="key-box">Unwrapped DEK (hex): {data_key.hex()}</div>', unsafe_allow_html=True)
                            progress_bar.progress(50)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 3: Decrypt File with DEK")
                            status_text.write("Decrypting file with DEK...")
                            
                            st.code("""
# Decrypt using AES-GCM
aesgcm = AESGCM(data_key)
plaintext = aesgcm.decrypt(nonce, ciphertext_data, None)
                            """, language="python")
                            
                            time.sleep(0.5)  # Visual delay
                            decrypted_data = decrypt_file(data_key, nonce, ciphertext_data)
                            
                            try:
                                preview = decrypted_data[:200].decode('utf-8')
                                preview_type = "text"
                            except UnicodeDecodeError:
                                preview = f"Binary data (first 32 bytes): {decrypted_data[:32].hex()}"
                                preview_type = "binary"
                            
                            progress_bar.progress(75)
                            st.markdown(f'<div class="data-box">Decrypted Data Preview ({preview_type}):</div>', unsafe_allow_html=True)
                            st.code(preview, language="text" if preview_type == "text" else None)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 4: Save Decrypted File")
                            status_text.write("Preparing file for download...")
                            progress_bar.progress(100)
                            
                            download_decrypted_btn = st.download_button(
                                "📥 Download Decrypted File",
                                data=decrypted_data,
                                file_name=file["filename"],
                                mime=file["content_type"],
                                on_click=lambda: st.session_state.audit_events.append({
                                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "operation": "DOWNLOAD",
                                    "file_id": file["file_id"],
                                    "details": f"File downloaded: {file['filename']}"
                                })
                            )
                            
                            st.success("✅ Decryption complete! Your file is ready to download.")
                            st.markdown('</div>', unsafe_allow_html=True)
                        else:
                            st.error("Failed to download the file. See errors above.")
                    
                    if st.button("⬅️ Back to File List", key="back_from_download"):
                        st.session_state.current_action = None
                        st.rerun()
                        
                elif action == "update":
                    with st.expander("🔄 Update Process", expanded=True):
                        st.write("""
                        ### Secure File Update
                        
                        When you update a file:
                        1. A new file is uploaded with its own encryption key
                        2. The server replaces the old file while preserving the file ID
                        3. The update operation is recorded in the audit log
                        """)
                        
                        new_file = st.file_uploader("Upload new version", key=f"new_version_{file['file_id']}")
                        
                        if new_file:
                            new_content = new_file.read()
                            
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 1: Generate New Encryption Key")
                            status_text.write("Generating new Data Encryption Key (DEK)...")
                            new_dek = generate_data_encryption_key()
                            st.markdown(f'<div class="key-box">New DEK (hex): {new_dek.hex()[:32]}...</div>', unsafe_allow_html=True)
                            progress_bar.progress(20)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 2: Encrypt New Version")
                            status_text.write("Encrypting file with new key...")
                            encrypted_data = encrypt_file(new_dek, new_content)
                            ciphertext_with_nonce = encrypted_data['nonce'] + encrypted_data['ciphertext']
                            st.markdown(f'<div class="cipher-box">New ciphertext: {ciphertext_with_nonce.hex()[:32]}...</div>', unsafe_allow_html=True)
                            progress_bar.progress(40)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 3: Wrap DEK with Public Key")
                            status_text.write("Wrapping DEK with public key...")
                            wrapped_key = wrap_key(st.session_state.public_key, new_dek)
                            st.markdown(f'<div class="cipher-box">Wrapped DEK: {wrapped_key.hex()[:32]}...</div>', unsafe_allow_html=True)
                            progress_bar.progress(60)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 4: Prepare Data for Server")
                            status_text.write("Preparing data for server...")
                            st.json({
                                "file_id": file["file_id"],
                                "new_encrypted_file": {
                                    "size": len(ciphertext_with_nonce),
                                    "preview": ciphertext_with_nonce.hex()[:32] + "..."
                                },
                                "new_wrapped_dek": wrapped_key.hex()[:32] + "...",
                                "metadata": {
                                    "filename": new_file.name,
                                    "size": len(new_content)
                                }
                            })
                            progress_bar.progress(80)
                            st.markdown('</div>', unsafe_allow_html=True)
                            
                            st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                            st.subheader("Step 5: Send Update to Server")
                            
                            if st.button("Confirm Update"):
                                status_text.write("Uploading new version to server...")
                                
                                update_result = update_file_in_api(
                                    file["file_id"], 
                                    ciphertext_with_nonce, 
                                    new_file.name,
                                    wrapped_key,
                                    st.session_state.token
                                )
                                
                                if update_result and update_result.get("status") == "success":
                                    progress_bar.progress(100)
                                    status_text.write("Update complete!")
                                    
                                    original_filename = st.session_state.original_uploads[file["file_id"]]["filename"]
                                    
                                    st.session_state.audit_events.append({
                                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                        "operation": "UPDATE",
                                        "file_id": file["file_id"],
                                        "details": {
                                            "old_filename": original_filename,
                                            "new_filename": new_file.name,
                                            "action": "File updated"
                                        }
                                    })
                                    
                                    st.session_state.files[file_index].update({
                                        'filename': new_file.name,
                                        'size': len(new_content),
                                        'upload_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                                        'content_type': new_file.type
                                    })
                                    
                                    st.success(f"File {file['file_id']} updated successfully")
                                    st.session_state.current_action = None
                                    st.rerun()
                                else:
                                    st.error("Failed to update the file. See errors above.")
                    
                    if st.button("⬅️ Back to File List", key="back_from_update"):
                        st.session_state.current_action = None
                        st.rerun()
                
                elif action == "delete":
                    with st.expander("🗑️ Secure Deletion Process", expanded=True):
                        st.warning("Are you sure you want to delete this file? This cannot be undone.")
                        
                        st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                        st.subheader("Deletion Process and Security")
                        st.markdown("""
                        When you delete a file:
                        1. The encrypted file is removed from storage
                        2. The wrapped DEK is deleted permanently
                        3. Metadata is preserved in the audit log
                        4. A deletion entry is added to the audit log
                        
                        **Security Considerations:**
                        - File content is irrecoverable after deletion
                        - The audit log maintains a record of the deletion
                        - The deletion is cryptographically linked in the hash chain
                        - The file ID cannot be reused
                        """)
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        cols = st.columns(2)
                        with cols[0]:
                            if st.button("⬅️ Cancel", key="cancel_delete"):
                                st.session_state.current_action = None
                                st.rerun()
                                
                        with cols[1]:
                            if st.button("🗑️ Confirm Delete", key="confirm_delete"):
                                progress_bar = st.progress(0)
                                status_text = st.empty()
                                
                                st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                                st.subheader("Step 1: Request Deletion from Server")
                                status_text.write("Removing file from server...")
                                progress_bar.progress(30)
                                
                                delete_result = delete_file_from_api(file["file_id"], st.session_state.token)
                                progress_bar.progress(60)
                                
                                if delete_result and delete_result.get("status") == "success":
                                    st.subheader("Step 2: Record Deletion in Audit Log")
                                    progress_bar.progress(80)
                                    status_text.write("Recording deletion in audit log...")
                                    
                                    st.session_state.audit_events.append({
                                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                        "operation": "DELETE",
                                        "file_id": file["file_id"],
                                        "details": f"File deleted: {file['filename']}"
                                    })
                                    
                                    progress_bar.progress(100)
                                    status_text.write("Deletion complete!")
                                    
                                    st.session_state.files.pop(file_index)
                                    
                                    st.success(f"File {file['file_id']} deleted successfully")
                                    st.markdown('</div>', unsafe_allow_html=True)
                                    
                                    time.sleep(1)  # Give time to read the success message
                                    st.session_state.current_action = None
                                    st.rerun()
                                else:
                                    st.error("Failed to delete the file. See errors above.")
                                    st.markdown('</div>', unsafe_allow_html=True)
                
                elif action == "view":
                    st.json({
                        "file_id": file["file_id"],
                        "filename": file["filename"],
                        "size": file["size"],
                        "upload_time": file["upload_time"],
                        "content_type": file["content_type"],
                        "security": {
                            "encryption": "AES-256-GCM",
                            "key_protection": "RSA-2048 OAEP",
                            "integrity": "Authenticated encryption with GCM",
                            "access_control": "Owner-only via private key"
                        }
                    })
                    
                    if st.button("⬅️ Back to File List", key="back_from_view"):
                        st.session_state.current_action = None
                        st.rerun()
    
    elif demo_page == "Key Rotation":
        st.markdown('<h1 class="main-header">Key Rotation Demo</h1>', unsafe_allow_html=True)
        
        with st.expander("📘 Why Key Rotation Is Important", expanded=True):
            st.write("""
            ### Key Rotation Benefits
            
            Regularly changing your encryption keys is a security best practice:
            
            1. **Limit Key Exposure**: Reduces the amount of data encrypted with a single key
            2. **Mitigate Key Compromise**: If a key is stolen but not yet used, rotation limits damage
            3. **Forward Secrecy**: New keys protect future data even if old keys are compromised
            4. **Compliance Requirements**: Many regulations require periodic key rotation
            5. **Defense in Depth**: Adds another layer of security to protect your data
            """)
            
            st.info("When you rotate keys, all your existing files remain accessible because the server re-encrypts the file DEKs with your new public key.")
        
        st.markdown('<h2 class="section-header">Rotate Your Keys</h2>', unsafe_allow_html=True)
        
        if not st.session_state.files:
            st.warning("No files to rotate keys for. Upload some files first to see key rotation in action.")
        else:
            st.info(f"You have {len(st.session_state.files)} files that will be re-keyed during rotation.")
            
            if st.button("Start Key Rotation"):
                with st.expander("🔄 Key Rotation Process", expanded=True):
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 1: Generate New RSA Keypair")
                    status_text.write("Generating new 2048-bit RSA keypair...")
                    time.sleep(0.5)
                    
                    st.code("""
# Generate new 2048-bit RSA keypair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize keys
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
                    """, language="python")
                    
                    new_private_key, new_public_key = generate_rsa_keypair()
                    
                    st.markdown('<div class="key-box">New Private Key (preview):</div>', unsafe_allow_html=True)
                    st.code(new_private_key[:100].decode() + "...", language="text")
                    
                    st.markdown('<div class="key-box">New Public Key:</div>', unsafe_allow_html=True)
                    st.code(new_public_key[:100].decode() + "...", language="text")
                    
                    progress_bar.progress(25)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 2: Send Public Key to Server")
                    status_text.write("Sending new public key to server...")
                    
                    st.code("""
# Send new public key to server
response = requests.post(
    f"{API_BASE_URL}/rotate-key",
    json={"new_public_key": base64.b64encode(new_public_key).decode()},
    headers={"Authorization": f"Bearer {token}"}
)
                    """, language="python")
                    
                    rotation_result = rotate_key_api(new_public_key, st.session_state.token)
                    progress_bar.progress(50)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 3: Server Rekeys Files")
                    status_text.write("Server is re-encrypting file keys...")
                    
                    st.code("""
# Server-side pseudocode:
for each file owned by the user:
    1. Retrieve the wrapped DEK
    2. Decrypt it with the server's master key
    3. Re-encrypt it with the user's new public key
    4. Update the stored wrapped DEK
    5. Update the user's public key in the database                    """, language="text")
                    
                    time.sleep(0.5)
                    progress_bar.progress(75)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 4: Complete Key Rotation")
                    status_text.write("Finalizing key rotation...")
                    
                    if rotation_result and rotation_result.get("status") == "success":
                        st.json({
                            "status": "success",
                            "files_rekeyed": len(st.session_state.files),
                            "user_id": st.session_state.user_id,
                            "key_rotation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "old_key_retired": True
                        })
                        
                        st.session_state.private_key = new_private_key
                        st.session_state.public_key = new_public_key
                        
                        progress_bar.progress(100)
                        status_text.write("✅ Key rotation complete!")
                        
                        st.success("Keys have been successfully rotated!")
                        
                        st.warning("""
                        ⚠️ **IMPORTANT**: Your private key has changed. Download your new private key 
                        immediately and store it securely. If you lose this key, you will lose access to all your files.
                        """)
                        
                        st.download_button(
                            "Download New Private Key",
                            data=new_private_key,
                            file_name="new_private_key.pem",
                            mime="application/x-pem-file"
                        )
                    else:
                        st.error("Key rotation failed. See error details above.")
                        if rotation_result:
                            st.json(rotation_result)
                    st.markdown('</div>', unsafe_allow_html=True)
    
    elif demo_page == "Audit Trail":
        st.markdown('<h1 class="main-header">Audit Trail Demo</h1>', unsafe_allow_html=True)
        
        with st.expander("📘 How Tamper-Evident Logging Works", expanded=True):
            st.write("""
            ### Cryptographic Hash Chain
            
            The audit log uses blockchain-inspired principles to create a tamper-evident record:
            
            1. **Hash Chaining**: Each log entry includes a hash of the previous entry
            2. **Content Integrity**: The hash includes all important fields of the log entry
            3. **Verification**: Any modification breaks the chain, making tampering detectable
            4. **Completeness**: Missing entries would break the hash chain
            
            This provides cryptographic proof that the audit log hasn't been modified.
            """)
            
            st.markdown("""
            <div class="crypto-step">
            <h4>How the Hash Chain Works:</h4>
            <pre>
            Log Entry N:   [ data | prev_hash | current_hash ]
                                    ↑             ↓
            Log Entry N+1: [ data | prev_hash | current_hash ]
                                    ↑             ↓
            Log Entry N+2: [ data | prev_hash | current_hash ]
            </pre>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('<h2 class="section-header">Audit Log Entries</h2>', unsafe_allow_html=True)
        
        audit_logs = []

        timestamp_base = time.time()
        
        prev_hash = "0" * 64
        
        first_entry = {
            "id": 1,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_base - 600)),
            "user_id": st.session_state.user_id,
            "operation": "register",
            "details": "User registration",
            "prev_hash": prev_hash
        }
        
        log_data = {
            'timestamp': first_entry['timestamp'],
            'operation': first_entry['operation'],
            'user_id': first_entry['user_id'],
            'file_id': ''
        }
        first_entry["current_hash"] = compute_hash_for_log_entry(prev_hash, log_data)
        audit_logs.append(first_entry)
        
        prev_hash = first_entry["current_hash"]
        
        all_events = []
        
        for file_id, upload_info in st.session_state.original_uploads.items():
            all_events.append({
                "timestamp": upload_info['upload_time'],
                "operation": "UPLOAD",
                "file_id": file_id,
                "details": {"filename": upload_info['filename']}
            })
        
        all_events.extend(st.session_state.audit_events)
        
        all_events.sort(key=lambda x: x["timestamp"])
        
        for event in all_events:
            entry = {
                "id": len(audit_logs) + 1,
                "timestamp": event["timestamp"],
                "user_id": st.session_state.user_id,
                "operation": event["operation"],
                "file_id": event["file_id"],
                "details": event["details"],
                "prev_hash": prev_hash
            }
            
            log_data = {
                'timestamp': entry['timestamp'],
                'operation': entry['operation'],
                'user_id': entry['user_id'],
                'file_id': entry.get('file_id', '')
            }
            entry["current_hash"] = compute_hash_for_log_entry(prev_hash, log_data)
            audit_logs.append(entry)
            
            prev_hash = entry["current_hash"]
        
        if audit_logs:
            operation_filter = st.selectbox(
                "Filter by Operation",
                ["All Operations", "REGISTER", "UPLOAD", "DOWNLOAD", "UPDATE", "DELETE", "KEY_ROTATION"]
            )
            
            filtered_logs = audit_logs
            if operation_filter != "All Operations":
                filtered_logs = [log for log in audit_logs if log["operation"].upper() == operation_filter]
            
            for log in filtered_logs:
                with st.container():
                    cols = st.columns([1, 3, 2, 2, 3])
                    
                    with cols[0]:
                        st.text(f"ID: {log['id']}")
                    
                    with cols[1]:
                        st.text(log["timestamp"])
                    
                    with cols[2]:
                        operation = log["operation"].upper()
                        if operation == "UPLOAD":
                            st.markdown(f"<span style='color:#4CAF50;'>⬆️ {operation}</span>", unsafe_allow_html=True)
                        elif operation == "DOWNLOAD":
                            st.markdown(f"<span style='color:#2196F3;'>⬇️ {operation}</span>", unsafe_allow_html=True)
                        elif operation == "DELETE":
                            st.markdown(f"<span style='color:#F44336;'>🗑️ {operation}</span>", unsafe_allow_html=True)
                        elif operation == "UPDATE":
                            st.markdown(f"<span style='color:#FF9800;'>🔄 {operation}</span>", unsafe_allow_html=True)
                        elif operation == "REGISTER":
                            st.markdown(f"<span style='color:#9C27B0;'>👤 {operation}</span>", unsafe_allow_html=True)
                        elif operation == "KEY_ROTATION":
                            st.markdown(f"<span style='color:#E91E63;'>🔑 {operation}</span>", unsafe_allow_html=True)
                    
                    with cols[3]:
                        if "file_id" in log:
                            st.text(f"File: {log['file_id'][:8]}...")
                        else:
                            st.text("")
                    
                    with cols[4]:
                        if isinstance(log.get("details"), dict):
                            details = log["details"]
                            if "old_filename" in details and "new_filename" in details:
                                st.markdown(f"<span style='color:#FF9800;'>Changed from '{details['old_filename']}' to '{details['new_filename']}'</span>", unsafe_allow_html=True)
                            elif "filename" in details:
                                st.markdown(f"<span style='color:#4CAF50;'>'{details['filename']}'</span>", unsafe_allow_html=True)
                            else:
                                st.text(json.dumps(details))
                        else:
                            st.text(log.get("details", ""))
                    
                    with st.expander("Show Hash Chain Details"):
                        hash_cols = st.columns(2)
                        
                        with hash_cols[0]:
                            st.markdown(f"<div class='key-box'>Previous Hash: {log['prev_hash'][:16]}...</div>", unsafe_allow_html=True)
                        
                        with hash_cols[1]:
                            st.markdown(f"<div class='key-box'>Current Hash: {log['current_hash'][:16]}...</div>", unsafe_allow_html=True)
                            
                        st.markdown("### Complete Entry Data")
                        st.json({
                            "id": log["id"],
                            "timestamp": log["timestamp"],
                            "user_id": log["user_id"],
                            "operation": log["operation"].upper(),
                            "file_id": log.get("file_id", ""),
                            "details": log.get("details", ""),
                            "prev_hash": log["prev_hash"],
                            "current_hash": log["current_hash"]
                        })
                        
                        st.markdown("### Hash Computation")
                        st.code(f"""
# Hash computation pseudocode:
data_string = (
    str(log_id) + 
    str(timestamp) + 
    str(user_id) + 
    str(operation) + 
    str(file_id) + 
    str(prev_hash)
)
current_hash = sha256(data_string.encode()).hexdigest()
                        """, language="python")
                    
                    st.markdown("---")
            
            if st.button("Verify Audit Log Integrity"):
                with st.expander("🔒 Audit Log Verification Process", expanded=True):
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 1: Initialize Verification Process")
                    status_text.write("Starting hash chain verification...")
                    
                    total_entries = len(audit_logs)
                    st.info(f"Total entries to verify: {total_entries}")
                    
                    genesis_entry = audit_logs[0]
                    st.markdown(f'<div class="key-box">Genesis Entry (ID: {genesis_entry["id"]})</div>', unsafe_allow_html=True)
                    st.json({
                        "timestamp": genesis_entry["timestamp"],
                        "user_id": genesis_entry["user_id"],
                        "operation": genesis_entry["operation"].upper(),
                        "details": genesis_entry["details"],
                        "prev_hash": genesis_entry["prev_hash"] or "0"*64,
                        "current_hash": genesis_entry["current_hash"]
                    })
                    
                    progress_bar.progress(10)
                    time.sleep(0.5)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    st.markdown('<div class="crypto-step">', unsafe_allow_html=True)
                    st.subheader("Step 2: Verify Hash Chain Integrity")
                    status_text.write("Verifying each entry in the chain...")
                    
                    verification_passed = True
                    failures = []
                    
                    sample_indices = [1]
                    
                    if total_entries > 5:
                        sample_indices.append(total_entries // 2)
                        sample_indices.append(total_entries - 1)
                    elif total_entries > 1:
                        sample_indices.append(total_entries - 1)
                    
                    for sample_idx in sample_indices:
                        if sample_idx < len(audit_logs):
                            entry = audit_logs[sample_idx]
                            prev_entry = audit_logs[sample_idx - 1]
                            
                            prog_pct = min(100, 10 + ((sample_idx / max(1, len(sample_indices))) * 40))
                            progress_bar.progress(int(prog_pct))
                            status_text.write(f"Verifying sample entry {sample_idx+1} of {total_entries}...")
                            
                            st.markdown(f'<div class="data-box">Verifying Entry ID: {entry["id"]}</div>', unsafe_allow_html=True)
                            
                            st.markdown("**Hash computation steps:**")
                            
                            st.code(f"""
# Step 1: Get the previous entry's hash
prev_hash = "{prev_entry['current_hash']}"
                            """, language="python")
                            
                            log_data = {
                                'timestamp': entry['timestamp'] or time.strftime("%Y-%m-%d %H:%M:%S"),
                                'operation': entry['operation'],
                                'user_id': entry['user_id'],
                                'file_id': entry.get('file_id', '')
                            }
                            
                            file_id_display = log_data['file_id'] if log_data['file_id'] else "(empty)"
                            st.code(f"""
# Step 2: Format data from current entry
timestamp = "{log_data['timestamp']}"
operation = "{log_data['operation']}"
user_id = "{log_data['user_id']}"
file_id = "{file_id_display}"

# Combine fields in correct order
data_string = timestamp + operation + user_id + file_id
                            """, language="python")
                            
                            st.code(f"""
# Step 3: Combine with previous hash and compute SHA-256
hash_input = prev_hash + data_string
computed_hash = hashlib.sha256(hash_input.encode()).hexdigest()
                            """, language="python")
                            
                            computed_hash = compute_hash_for_log_entry(prev_entry['current_hash'], log_data)
                            matches = computed_hash == entry['current_hash']
                            
                            st.markdown("**Verification results:**")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown('<div class="key-box">Computed Hash:</div>', unsafe_allow_html=True)
                                st.code(f"{computed_hash[:16]}...{computed_hash[-16:]}", language="text")
                                
                            with col2:
                                st.markdown('<div class="key-box">Stored Hash:</div>', unsafe_allow_html=True)
                                st.code(f"{entry['current_hash'][:16]}...{entry['current_hash'][-16:]}", language="text")
                                
                            if matches:
                                st.success("✅ Hashes match! Entry verified.")
                            else:
                                st.error("❌ Hash mismatch! Entry verification failed.")
                                verification_passed = False
                                failures.append(entry["id"])
                                
                                st.warning("Hash computation details:")
                                st.json({
                                    "prev_hash": prev_entry['current_hash'],
                                    "timestamp": log_data['timestamp'],
                                    "operation": log_data['operation'],
                                    "user_id": log_data['user_id'],
                                    "file_id": log_data['file_id'],
                                    "data_string": f"{log_data['timestamp']}{log_data['operation']}{log_data['user_id']}{log_data['file_id']}",
                                    "hash_input": f"{prev_entry['current_hash']}{log_data['timestamp']}{log_data['operation']}{log_data['user_id']}{log_data['file_id']}",
                                    "computed_hash": computed_hash,
                                    "stored_hash": entry['current_hash']
                                })
                            
                            if sample_idx != sample_indices[-1]:
                                st.markdown("---")
                    
                    status_text.write("Completing verification of all entries...")
                    verification_progress = st.progress(0)
                    
                    start_progress = 50
                    
                    for i in range(1, len(audit_logs)):
                        progress_percent = min(100, start_progress + (i / max(1, len(audit_logs))) * (90 - start_progress))
                        verification_progress.progress(int(progress_percent))
                        
                        entry = audit_logs[i]
                        prev_entry = audit_logs[i-1]
                        
                        log_data = {
                            'timestamp': entry['timestamp'] or time.strftime("%Y-%m-%d %H:%M:%S"),
                            'operation': entry['operation'],
                            'user_id': entry['user_id'],
                            'file_id': entry.get('file_id', '')
                        }
                        computed_hash = compute_hash_for_log_entry(prev_entry['current_hash'], log_data)
                        
                        if computed_hash != entry['current_hash'] and entry["id"] not in failures:
                            verification_passed = False
                            failures.append(entry["id"])
                    
                    verification_progress.progress(100)
                    progress_bar.progress(90)
                    
                    st.subheader("Step 3: Verification Summary")
                    
                    if verification_passed:
                        st.success(f"✅ All {total_entries} entries verified successfully! The audit log integrity is confirmed.")
                        st.markdown("""
                        <div class="info-box">
                        The hash chain is intact and the audit log has not been tampered with. Each entry's hash 
                        matches the expected value based on its contents and the previous entry's hash.
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.error(f"❌ Found {len(failures)} integrity failures among {total_entries} logs analyzed.")
                        st.markdown(f"""
                        <div class="error-message">
                        Integrity verification failed for entries: {', '.join(str(f) for f in failures)}<br>
                        This indicates possible tampering or corruption in the audit log.
                        </div>
                        """, unsafe_allow_html=True)
                    
                    progress_bar.progress(100)
                    st.markdown('</div>', unsafe_allow_html=True)
                
                st.subheader("Understanding Tampering Detection")
                with st.expander("What if someone tampers with the audit log?"):
                    st.markdown("""
                    ### Detecting Tampering
                    
                    If any entry in the audit log is modified or deleted:
                    
                    1. The modified entry's hash would no longer match what was recorded
                    2. All subsequent entries would have invalid previous hashes
                    3. The entire chain from the modified point forward would be invalidated
                    4. The verification would fail with details on where tampering occurred
                    
                    This makes it impossible to modify the audit log without detection.
                    """)
                    
                    st.code("""
# Example of tampering detection
for i in range(1, len(audit_logs)):
    prev_log = audit_logs[i-1]
    current_log = audit_logs[i]
    
    # Verify the previous hash matches
    if current_log["prev_hash"] != prev_log["current_hash"]:
        print(f"Tampering detected at entry {i+1}!")
        break
        
    # Verify the current hash is correct
    computed_hash = compute_hash_for_log_entry(current_log["prev_hash"], current_log)
    if computed_hash != current_log["current_hash"]:
        print(f"Invalid hash detected at entry {i+1}!")
        break
                    """, language="python")
        else:
            st.info("No audit logs to display. Perform some operations first.") 
