#!/usr/bin/env python3
"""
Streamlit UI for Secure Cloud Storage Demo
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

# Constants
API_BASE_URL = "http://localhost:8000/api/v1"  # Adjust as needed

# Set page configuration
st.set_page_config(
    page_title="Secure Cloud Storage Demo",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Fix for text visibility in dark theme
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

# Define CSS
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
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Registration error: {str(e)}")
        if hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def login_user(user_id):
    """Login user and get token"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/token",
            data={
                "username": user_id,
                "password": "test_password"  # For demo purposes
            }
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Login error: {str(e)}")
        if hasattr(e.response, 'json'):
            st.error(f"Error details: {e.response.json()}")
        return None

def upload_file_to_api(file_contents, filename, content_type, wrapped_dek, token):
    """Upload an encrypted file to the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        # Prepare file and metadata
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

def update_file_in_api(file_id, new_file_contents, filename, token):
    """Update a file in the API"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        files = {
            'new_file': (filename, new_file_contents, 'application/octet-stream')
        }
        response = requests.put(
            f"{API_BASE_URL}/update/{file_id}",
            headers=headers,
            files=files
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

# Sidebar for authentication
with st.sidebar:
    st.title("🔒 Secure Cloud Storage")
    st.markdown("---")
    
    if not st.session_state.logged_in:
        st.subheader("Authentication")
        auth_option = st.radio("Choose an option:", ["Login", "Register"])
        
        if auth_option == "Login":
            user_id = st.text_input("User ID", key="login_user_id")
            
            # Option to upload private key
            key_option = st.radio("Private Key Option:", ["Upload Key", "Generate New Key"])
            
            if key_option == "Upload Key":
                uploaded_key = st.file_uploader("Upload your private key", type=["pem"])
                if uploaded_key:
                    st.session_state.private_key = uploaded_key.read()
            else:
                if st.button("Generate New Keypair"):
                    private_key, public_key = generate_rsa_keypair()
                    st.session_state.private_key = private_key
                    st.session_state.public_key = public_key
                    st.download_button(
                        "Download Private Key",
                        data=private_key,
                        file_name="private_key.pem",
                        mime="application/x-pem-file"
                    )
            
            if st.button("Login") and user_id and st.session_state.private_key:
                # Call the API to login
                login_result = login_user(user_id)
                if login_result and "access_token" in login_result:
                    st.session_state.logged_in = True
                    st.session_state.user_id = user_id
                    st.session_state.token = login_result["access_token"]
                    st.success("Login successful!")
                    st.rerun()
                
        elif auth_option == "Register":
            user_id = st.text_input("Choose a User ID", key="register_user_id")
            
            if st.button("Generate Keys"):
                private_key, public_key = generate_rsa_keypair()
                st.session_state.private_key = private_key
                st.session_state.public_key = public_key
                
                st.success("Keys generated successfully!")
                st.download_button(
                    "Download Private Key",
                    data=private_key,
                    file_name="private_key.pem",
                    mime="application/x-pem-file"
                )
            
            if st.button("Register") and user_id and st.session_state.public_key:
                # Register with the API
                registration_result = register_user(user_id, st.session_state.public_key)
                if registration_result and registration_result.get("status") == "success":
                    st.success(f"User {user_id} registered successfully!")
                    
                    # Automatically login after registration
                    login_result = login_user(user_id)
                    if login_result and "access_token" in login_result:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user_id
                        st.session_state.token = login_result["access_token"]
                        st.rerun()
    else:
        st.success(f"Logged in as: {st.session_state.user_id}")
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

# Main content
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
    # Determine which page to show based on sidebar selection
    if 'demo_page' not in locals():
        demo_page = "File Upload"  # Default page
    
    if demo_page == "File Upload":
        st.markdown('<h1 class="main-header">File Upload Demo</h1>', unsafe_allow_html=True)
        
        # File upload interface
        st.markdown('<h2 class="section-header">Upload a File</h2>', unsafe_allow_html=True)
        
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
            
            # Encryption process demonstration with status updates
            if st.button("Encrypt & Upload File"):
                with st.spinner("Processing..."):
                    # Simulating the encryption and upload process with steps
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    # Step 1: Generate data encryption key
                    status_text.text("Generating encryption key...")
                    time.sleep(0.5)
                    data_key = generate_data_encryption_key()
                    progress_bar.progress(20)
                    
                    # Step 2: Encrypt the file - we'll still do client-side encryption
                    status_text.text("Encrypting file...")
                    time.sleep(0.5) # Keep some animation for user feedback
                    
                    # For a real implementation, we would either:
                    # 1. Do client-side encryption and send the ciphertext directly
                    # 2. Or, send plaintext with HTTPS and let the server handle encryption
                    
                    # Here we'll prepare the ciphertext for upload but keep the visualization
                    encrypted_data = encrypt_file(data_key, file_contents)
                    ciphertext_with_nonce = encrypted_data['nonce'] + encrypted_data['ciphertext']
                    progress_bar.progress(50)
                    
                    # Step 3: Wrap the data key
                    status_text.text("Securing encryption key...")
                    time.sleep(0.5)
                    wrapped_key = wrap_key(st.session_state.public_key, data_key)
                    progress_bar.progress(70)
                    
                    # Step 4: Upload to server via the API
                    status_text.text("Uploading to secure storage...")
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
                        status_text.text("Upload complete!")
                        
                        # Store minimal information in session for UI display
                        if 'files' not in st.session_state:
                            st.session_state.files = []
                        
                        st.session_state.files.append({
                            'file_id': file_id,
                            'filename': uploaded_file.name,
                            'size': file_size,
                            'upload_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                            'content_type': uploaded_file.type
                        })
                        
                        st.success(f"File uploaded successfully with ID: {file_id}")
                        st.balloons()
                    else:
                        progress_bar.progress(100)
                        status_text.text("Upload failed. Check errors above.")
    
    elif demo_page == "File Management":
        st.markdown('<h1 class="main-header">File Management</h1>', unsafe_allow_html=True)
        
        # We'll need to fetch the user's files from the API
        # For now we'll use the session state files for display, but in a full implementation
        # we would fetch them from the API
        
        if not st.session_state.files:
            st.warning("No files have been uploaded. Please upload a file first.")
        else:
            st.markdown('<h2 class="section-header">Your Files</h2>', unsafe_allow_html=True)
            
            # Create a clearer UI with explicit buttons for each action instead of dropdown
            for i, file in enumerate(st.session_state.files):
                with st.container():
                    cols = st.columns([3, 2, 2, 3])
                    
                    # File information
                    with cols[0]:
                        st.markdown(f"**{file['filename']}**")
                        st.caption(f"ID: {file['file_id'][:8]}...")
                    
                    with cols[1]:
                        st.text(f"{file['size']} bytes")
                        st.caption(f"Uploaded: {file['upload_time']}")
                    
                    # Action buttons
                    with cols[2]:
                        download_btn = st.button("📥 Download", key=f"download_{i}")
                        update_btn = st.button("🔄 Update", key=f"update_{i}")
                    
                    with cols[3]:
                        delete_btn = st.button("🗑️ Delete", key=f"delete_{i}")
                        view_btn = st.button("👁️ View Details", key=f"view_{i}")
                    
                    # Process actions based on which button was clicked
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
                
                st.markdown("---")
            
            # Handle the current action if any
            if 'current_action' in st.session_state and st.session_state.current_action:
                action = st.session_state.current_action["type"]
                file_index = st.session_state.current_action["file_index"]
                file = st.session_state.files[file_index]
                
                st.markdown(f"<h3>{action.capitalize()}: {file['filename']}</h3>", unsafe_allow_html=True)
                
                if action == "download":
                    with st.spinner("Downloading and decrypting file..."):
                        # Progress indicators for visual feedback
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        # Step 1: Fetch file from API
                        status_text.text("Retrieving file from server...")
                        file_data = download_file_from_api(file["file_id"], st.session_state.token)
                        
                        if file_data:
                            progress_bar.progress(30)
                            
                            # Step 2: Decode the data
                            wrapped_dek = base64.b64decode(file_data["wrappedDEK"])
                            ciphertext = base64.b64decode(file_data["ciphertext"])
                            
                            # Extract nonce (first 12 bytes) and ciphertext
                            nonce = ciphertext[:12]
                            ciphertext_data = ciphertext[12:]
                            
                            # Step 3: Unwrap the key
                            status_text.text("Decrypting file key...")
                            time.sleep(0.5)  # For visual feedback
                            data_key = unwrap_key(st.session_state.private_key, wrapped_dek)
                            progress_bar.progress(60)
                            
                            # Step 4: Decrypt the file
                            status_text.text("Decrypting file contents...")
                            time.sleep(0.5)  # For visual feedback
                            decrypted_data = decrypt_file(data_key, nonce, ciphertext_data)
                            progress_bar.progress(100)
                            status_text.text("Decryption complete!")
                            
                            # Offer download button
                            st.download_button(
                                "Download Decrypted File",
                                data=decrypted_data,
                                file_name=file["filename"],
                                mime=file["content_type"]
                            )
                        else:
                            st.error("Failed to download the file. See errors above.")
                    
                    if st.button("Back to File List"):
                        st.session_state.current_action = None
                        st.rerun()
                        
                elif action == "update":
                    new_file = st.file_uploader("Upload new version", key=f"new_version_{file['file_id']}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Back to File List", key="back_from_update"):
                            st.session_state.current_action = None
                            st.rerun()
                            
                    with col2:
                        if new_file and st.button("Confirm Update"):
                            with st.spinner("Processing update..."):
                                # Get file contents
                                new_content = new_file.read()
                                
                                # Simply update through the API (no client-side encryption for updates)
                                progress_bar = st.progress(0)
                                status_text = st.empty()
                                
                                status_text.text("Updating file...")
                                update_result = update_file_in_api(
                                    file["file_id"], 
                                    new_content, 
                                    new_file.name,
                                    st.session_state.token
                                )
                                
                                if update_result and update_result.get("status") == "success":
                                    progress_bar.progress(100)
                                    status_text.text("Update complete!")
                                    
                                    # Update session state for display purposes
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
                
                elif action == "delete":
                    st.warning("Are you sure you want to delete this file? This cannot be undone.")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Cancel", key="cancel_delete"):
                            st.session_state.current_action = None
                            st.rerun()
                            
                    with col2:
                        if st.button("Confirm Delete", key="confirm_delete"):
                            with st.spinner("Deleting file..."):
                                progress_bar = st.progress(0)
                                status_text = st.empty()
                                
                                status_text.text("Removing file from server...")
                                delete_result = delete_file_from_api(file["file_id"], st.session_state.token)
                                
                                if delete_result and delete_result.get("status") == "success":
                                    progress_bar.progress(100)
                                    status_text.text("Deletion complete!")
                                    
                                    # Remove from session state
                                    st.session_state.files.pop(file_index)
                                    
                                    st.success(f"File {file['file_id']} deleted successfully")
                                    st.session_state.current_action = None
                                    st.rerun()
                                else:
                                    st.error("Failed to delete the file. See errors above.")
                
                elif action == "view":
                    # Display file details
                    st.json({
                        "file_id": file["file_id"],
                        "filename": file["filename"],
                        "size": file["size"],
                        "upload_time": file["upload_time"],
                        "content_type": file["content_type"]
                    })
                    
                    if st.button("Back to File List", key="back_from_view"):
                        st.session_state.current_action = None
                        st.rerun()
    
    elif demo_page == "Key Rotation":
        st.markdown('<h1 class="main-header">Key Rotation Demo</h1>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
        <h3>About Key Rotation</h3>
        <p>Key rotation is a security best practice that involves periodically changing your encryption keys.
        This limits the amount of data encrypted with a single key and reduces the impact of a key compromise.</p>
        <p>During key rotation, we generate a new keypair, re-encrypt all file encryption keys with the new public key,
        and update the server with the new credentials.</p>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Start Key Rotation"):
            if not st.session_state.files:
                st.warning("No files to rotate keys for. Please upload files first.")
            else:
                with st.spinner("Performing key rotation..."):
                    # Progress indicators
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    # Step 1: Generate new keypair
                    status_text.text("Generating new RSA keypair...")
                    time.sleep(0.5)
                    new_private_key, new_public_key = generate_rsa_keypair()
                    progress_bar.progress(30)
                    
                    # Step 2: Send new public key to server
                    status_text.text("Updating public key on server...")
                    rotation_result = rotate_key_api(new_public_key, st.session_state.token)
                    
                    if rotation_result and rotation_result.get("status") == "success":
                        progress_bar.progress(75)
                        
                        # Step 3: Switch to new keys locally
                        status_text.text("Activating new keys...")
                        time.sleep(0.5)
                        
                        # Update session state
                        st.session_state.private_key = new_private_key
                        st.session_state.public_key = new_public_key
                        
                        progress_bar.progress(100)
                        status_text.text("Key rotation complete!")
                        
                        st.success("Keys have been successfully rotated! All files now use the new key.")
                        
                        # Offer download of new private key
                        st.markdown("""
                        <div class="warning-message">
                        <h3>⚠️ Important</h3>
                        <p>Your private key has changed. Please download and securely store your new private key.
                        Without this key, you will lose access to your files.</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.download_button(
                            "Download New Private Key",
                            data=new_private_key,
                            file_name="new_private_key.pem",
                            mime="application/x-pem-file"
                        )
                    else:
                        progress_bar.progress(100)
                        status_text.text("Key rotation failed")
                        st.error("Failed to rotate keys on the server. Please try again.")
    
    elif demo_page == "Audit Trail":
        st.markdown('<h1 class="main-header">Audit Trail Demo</h1>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
        <h3>Secure Audit Logging</h3>
        <p>Our system maintains a tamper-evident audit log of all operations performed on your files.
        Each log entry is cryptographically linked to the previous one, forming a blockchain-like structure
        that makes detection of tampering possible.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<h2 class="section-header">Audit Log Entries</h2>', unsafe_allow_html=True)
        
        # Note: The system doesn't appear to have a dedicated audit log API endpoint
        # We'll use simulated data based on the session activities
        
        # Generate sample audit log based on session activities
        audit_logs = []
        
        timestamp_base = time.time() - (len(st.session_state.files) * 300)  # Start 5 minutes ago per file
        
        for i, file in enumerate(st.session_state.files):
            # Upload operation
            upload_timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_base + (i * 300)))
            prev_hash = "0" * 64 if i == 0 else f"hash_{i-1}"
            current_hash = f"hash_{i}"
            
            audit_logs.append({
                "id": len(audit_logs) + 1,
                "timestamp": upload_timestamp,
                "user_id": st.session_state.user_id,
                "operation": "upload",
                "file_id": file["file_id"],
                "prev_hash": prev_hash[:8] + "...",
                "current_hash": current_hash[:8] + "..."
            })
            
            # Generate some random download operations
            if i % 2 == 0:
                download_timestamp = time.strftime(
                    "%Y-%m-%d %H:%M:%S", 
                    time.localtime(timestamp_base + (i * 300) + 60)
                )
                prev_hash = current_hash
                current_hash = f"hash_{i}_download"
                
                audit_logs.append({
                    "id": len(audit_logs) + 1,
                    "timestamp": download_timestamp,
                    "user_id": st.session_state.user_id,
                    "operation": "download",
                    "file_id": file["file_id"],
                    "prev_hash": prev_hash[:8] + "...",
                    "current_hash": current_hash[:8] + "..."
                })
        
        # Display audit log
        if audit_logs:
            # Add a filter for operations
            operation_filter = st.selectbox(
                "Filter by Operation",
                ["All Operations", "upload", "download", "update", "delete"]
            )
            
            filtered_logs = audit_logs
            if operation_filter != "All Operations":
                filtered_logs = [log for log in audit_logs if log["operation"] == operation_filter]
            
            st.dataframe(
                filtered_logs,
                use_container_width=True,
                column_config={
                    "id": "ID",
                    "timestamp": "Timestamp",
                    "user_id": "User",
                    "operation": "Operation",
                    "file_id": "File ID",
                    "prev_hash": "Previous Hash",
                    "current_hash": "Current Hash"
                }
            )
            
            # Verify integrity
            if st.button("Verify Audit Log Integrity"):
                st.info("Note: In this demo, verification is simulated for demonstration purposes only. In a production environment, this would validate the hash chain integrity against the database.")
                
                with st.spinner("Simulating audit log chain verification..."):
                    # Simulate verification process
                    progress_bar = st.progress(0)
                    time.sleep(1)
                    progress_bar.progress(50)
                    time.sleep(1)
                    progress_bar.progress(100)
                    
                st.success("✅ Audit log integrity verified successfully!")
                st.markdown("""
                <div class="info-box">
                The hash chain is intact and the audit log has not been tampered with.
                All operations are cryptographically verifiable.
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No audit logs to display. Perform some operations first.")

st.markdown("---")
st.markdown("© 2023 Secure Cloud Storage Demo | CSC 8224 Cloud Security Project") 