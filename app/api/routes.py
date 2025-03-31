from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Body
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
import uuid
import base64
from typing import Optional
from pydantic import BaseModel
import json
from pathlib import Path
import aiofiles
import logging
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from datetime import datetime

from ..core.security import get_current_user, create_access_token
from ..utils.crypto import wrap_key_with_rsa, load_public_key
from ..utils.logging import AuditLogger
from ..db.models import Database

router = APIRouter()

# Add this function to create AuditLogger dependency
async def get_audit_logger(db: Database = Depends(Database.get_instance)) -> AuditLogger:
    return AuditLogger(db)

class FileUploadResponse(BaseModel):
    file_id: str
    status: str

class FileMetadata(BaseModel):
    name: str
    size: int
    content_type: str

class UserRegistration(BaseModel):
    user_id: str
    public_key: str

class ChallengeRequest(BaseModel):
    user_id: str

class ChallengeResponse(BaseModel):
    challenge_id: str
    encrypted_challenge: str

class VerifyResponse(BaseModel):
    user_id: str
    challenge_id: str
    challenge_response: str

class VerifyLoginRequest(BaseModel):
    user_id: str
    message: str
    signature: str

# Add this to store challenges
active_challenges = {}

@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    wrapped_dek: str = Form(...),
    metadata: Optional[str] = Form(None),
    current_user: str = Depends(get_current_user),
    db: Database = Depends(Database.get_instance),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    try:
        # Create storage directory if it doesn't exist
        storage_path = Path("storage/files")
        storage_path.mkdir(parents=True, exist_ok=True)
        
        # Generate file ID and path
        file_id = str(uuid.uuid4())
        file_path = storage_path / file_id
        
        # Save encrypted file
        try:
            contents = await file.read()
            async with aiofiles.open(file_path, mode='wb') as f:
                await f.write(contents)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to save file: {str(e)}"
            )
        
        # Parse metadata
        try:
            metadata_dict = json.loads(metadata) if metadata else {}
            metadata_dict.update({
                "filename": file.filename,
                "content_type": file.content_type,
                "size": len(contents)
            })
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400,
                detail="Invalid metadata format"
            )
        
        try:
            # Store metadata in database
            await db.store_file_metadata(
                file_id=file_id,
                user_id=current_user,
                wrapped_dek=base64.b64decode(wrapped_dek),
                file_path=str(file_path),
                metadata=metadata_dict
            )
            
            # Log operation
            await audit_logger.log_operation(
                operation="upload",
                user_id=current_user,
                file_id=file_id,
                details={"filename": file.filename}
            )
        except Exception as e:
            # Clean up the file if database operations fail
            file_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=500,
                detail=f"Database error: {str(e)}"
            )
        
        return FileUploadResponse(file_id=file_id, status="success")
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{file_id}")
async def download_file(
    file_id: str,
    current_user: str = Depends(get_current_user),
    db: Database = Depends(Database.get_instance),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    try:
        # Get file metadata
        file_data = await db.get_file_metadata(file_id)
        if not file_data:
            raise HTTPException(
                status_code=404,
                detail="File not found"
            )
            
        if file_data["owner_id"] != current_user:
            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )
        
        # Read file
        async with aiofiles.open(file_data["file_path"], "rb") as f:
            ciphertext = await f.read()
        
        # Log operation
        await audit_logger.log_operation(
            operation="download",
            user_id=current_user,
            file_id=file_id
        )
        
        return JSONResponse({
            "wrappedDEK": base64.b64encode(file_data["wrapped_dek"]).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "metadata": file_data["metadata"]
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rotate-key")
async def rotate_key(
    request: dict = Body(...),  # Change to accept dict with new_public_key field
    current_user: str = Depends(get_current_user),
    db: Database = Depends(Database.get_instance),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    try:
        if 'new_public_key' not in request:
            raise HTTPException(
                status_code=400,
                detail="new_public_key is required"
            )
            
        # Store new public key
        public_key_data = base64.b64decode(request['new_public_key'])
        await db.update_user_public_key(current_user, public_key_data)
        
        # Log operation
        await audit_logger.log_operation(
            operation="key_rotation",
            user_id=current_user
        )
        
        return {"status": "success", "message": "Public key updated"}
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/register")
async def register_user(
    registration: UserRegistration,
    db: Database = Depends(Database.get_instance)
):
    try:
        # Decode public key from base64
        public_key_data = base64.b64decode(registration.public_key)
        
        # Check if user exists
        existing_user = await db.get_user(registration.user_id)
        
        # Store user data (will update if user exists)
        await db.store_user(registration.user_id, public_key_data)
        
        message = "User updated successfully" if existing_user else "User registered successfully"
        return {"status": "success", "message": message}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Database = Depends(Database.get_instance)
):
    try:
        # Step 1: Check if the user exists
        user = await db.get_user(form_data.username)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Step 2: Require a signed login challenge in the password field
        # Format should be: "challenge_id:signature" where signature is base64-encoded
        try:
            # The "password" field is repurposed to contain verification data
            if ":" not in form_data.password:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid authentication format. Expected 'challenge_id:signature'",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            challenge_id, signature_b64 = form_data.password.split(":", 1)
            
            # Verify the challenge exists
            if challenge_id not in active_challenges:
                raise HTTPException(
                    status_code=401, 
                    detail="Challenge expired or invalid. Request a new challenge before login.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            challenge_data = active_challenges[challenge_id]
            
            # Verify the user ID matches
            if challenge_data["user_id"] != form_data.username:
                raise HTTPException(
                    status_code=403, 
                    detail="User ID mismatch in challenge",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Get the challenge message that should have been signed
            challenge = challenge_data["challenge"]
            
            # Get the user's public key
            public_key_pem = user.get("public_key")
            if not public_key_pem:
                raise HTTPException(
                    status_code=401,
                    detail="User has no registered public key",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Load the public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # Verify the signature
            try:
                signature = base64.b64decode(signature_b64)
                public_key.verify(
                    signature,
                    challenge.encode(),
                    asymmetric_padding.PSS(
                        mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                        salt_length=asymmetric_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                # Clean up the challenge
                del active_challenges[challenge_id]
                # Log failed verification
                await db.append_audit_log(form_data.username, "LOGIN_KEY_VERIFICATION", "Failed")
                raise HTTPException(
                    status_code=401,
                    detail=f"Key verification failed: {str(e)}",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Verification succeeded - clean up the challenge
            del active_challenges[challenge_id]
            
            # Log successful verification
            await db.append_audit_log(form_data.username, "LOGIN_KEY_VERIFICATION", "Success")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=401,
                detail=f"Key verification error: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Step 3: Create and return the access token
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.put("/update/{file_id}")
async def update_file(
    file_id: str,
    new_file: UploadFile = File(...),
    wrapped_dek: Optional[str] = Form(None),
    current_user: str = Depends(get_current_user),
    db: Database = Depends(Database.get_instance),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    try:
        # Check if file exists and belongs to the user
        file_data = await db.get_file_metadata(file_id)
        if not file_data or file_data["owner_id"] != current_user:
            raise HTTPException(status_code=404, detail="File not found or access denied")

        # Update file content
        new_contents = await new_file.read()
        async with aiofiles.open(file_data["file_path"], mode='wb') as f:
            await f.write(new_contents)
            
        # Update the wrapped DEK if provided
        if wrapped_dek:
            try:
                # Update the wrapped key in the database
                await db.update_wrapped_dek(
                    file_id=file_id,
                    wrapped_dek=base64.b64decode(wrapped_dek)
                )
            except Exception as e:
                # Log the error but don't fail the whole update
                logging.error(f"Failed to update wrapped DEK: {str(e)}")

        # Update metadata if needed
        metadata = file_data["metadata"]
        metadata.update({
            "filename": new_file.filename or metadata.get("filename"),
            "size": len(new_contents),
            "last_modified": datetime.utcnow().isoformat()
        })
        
        # Update metadata in the database
        try:
            await db.update_file_metadata(
                file_id=file_id, 
                metadata=metadata
            )
        except Exception as e:
            # Log the error but don't fail the whole update
            logging.error(f"Failed to update metadata: {str(e)}")

        # Log operation
        await audit_logger.log_operation(
            operation="update",
            user_id=current_user,
            file_id=file_id
        )

        return {"status": "success", "message": "File updated successfully"}
    except Exception as e:
        logging.error(f"Update error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/delete/{file_id}")
async def delete_file(
    file_id: str,
    current_user: str = Depends(get_current_user),
    db: Database = Depends(Database.get_instance),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    try:
        # Check if file exists and belongs to the user
        file_data = await db.get_file_metadata(file_id)
        if not file_data or file_data["owner_id"] != current_user:
            logging.error(f"File not found or access denied for user {current_user} and file {file_id}")
            raise HTTPException(status_code=404, detail="File not found or access denied")

        # Delete file
        file_path = Path(file_data["file_path"])
        if file_path.exists():
            logging.info(f"Deleting file at path: {file_path}")
            file_path.unlink()
        else:
            logging.error(f"File not found on disk for path: {file_path}")
            raise HTTPException(status_code=404, detail="File not found on disk")

        # Remove metadata from database
        await db.delete_file_metadata(file_id)

        # Log operation
        await audit_logger.log_operation(
            operation="delete",
            user_id=current_user,
            file_id=file_id
        )

        return {"status": "success", "message": "File deleted successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logging.error(f"Error deleting file: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/verify-key/challenge")
async def get_challenge(
    request: ChallengeRequest,
    db: Database = Depends(Database.get_instance)
):
    """
    Generate a challenge for key verification.
    This function creates a random challenge, encrypts it with the user's public key,
    and returns the encrypted challenge to be decrypted with the private key.
    """
    try:
        # Get user data from database
        user = await db.get_user(request.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Generate a random challenge
        challenge = secrets.token_hex(32)  # 64 character hex string
        challenge_id = str(uuid.uuid4())
        
        # Store the challenge for verification
        active_challenges[challenge_id] = {
            "user_id": request.user_id,
            "challenge": challenge
        }
        
        # Load the user's public key
        try:
            public_key = serialization.load_pem_public_key(user["public_key"])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid public key: {str(e)}")
        
        # Encrypt the challenge with the user's public key
        encrypted_challenge = public_key.encrypt(
            challenge.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return the encrypted challenge
        return {
            "challenge_id": challenge_id,
            "encrypted_challenge": base64.b64encode(encrypted_challenge).decode()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Challenge generation failed: {str(e)}")

@router.post("/verify-key/response")
async def verify_challenge_response(
    response: VerifyResponse,
    db: Database = Depends(Database.get_instance)
):
    """
    Verify the response to a challenge.
    This function checks if the decrypted challenge matches the original challenge,
    which proves the user possesses the private key corresponding to their registered public key.
    """
    try:
        # Check if the challenge exists
        if response.challenge_id not in active_challenges:
            raise HTTPException(status_code=400, detail="Challenge expired or invalid")
        
        challenge_data = active_challenges[response.challenge_id]
        
        # Verify the user ID matches
        if challenge_data["user_id"] != response.user_id:
            raise HTTPException(status_code=403, detail="User ID mismatch")
        
        # Decode the response
        try:
            decoded_response = base64.b64decode(response.challenge_response).decode()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid challenge response format")
        
        # Verify the response matches the original challenge
        if decoded_response != challenge_data["challenge"]:
            # Clean up regardless of result
            del active_challenges[response.challenge_id]
            return {"verified": False, "message": "Challenge verification failed"}
        
        # Clean up the challenge after successful verification
        del active_challenges[response.challenge_id]
        
        return {
            "verified": True,
            "message": "Private key successfully verified"
        }
    except HTTPException:
        raise
    except Exception as e:
        # Clean up on error
        if response.challenge_id in active_challenges:
            del active_challenges[response.challenge_id]
        raise HTTPException(status_code=500, detail=f"Challenge verification failed: {str(e)}")

@router.post("/verify-login", response_model=VerifyResponse)
async def verify_login(request: VerifyLoginRequest, current_user: dict = Depends(get_current_user), db: Database = Depends(Database.get_instance)):
    """
    Verify a login attempt by checking a signature against the user's stored public key.
    """
    try:
        # Get the user_id, message, and signature from the request
        user_id = request.user_id
        message = request.message
        signature_b64 = request.signature
        
        # Only allow verification of the current user or admin users
        if current_user["user_id"] != user_id and current_user.get("role") != "admin":
            return VerifyResponse(verified=False, message="Unauthorized to verify this user")
        
        # Get the user from the database
        user = await db.get_user(user_id)
        if not user:
            return VerifyResponse(verified=False, message="User not found")
        
        # Get the public key PEM from the user data
        public_key_pem_b64 = user.get("public_key")
        if not public_key_pem_b64:
            return VerifyResponse(verified=False, message="User has no public key")
        
        # Decode the public key
        try:
            public_key_pem = base64.b64decode(public_key_pem_b64)
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        except Exception as e:
            return VerifyResponse(verified=False, message=f"Invalid public key: {str(e)}")
        
        # Decode the signature
        try:
            signature = base64.b64decode(signature_b64)
        except Exception as e:
            return VerifyResponse(verified=False, message=f"Invalid signature encoding: {str(e)}")
        
        # Verify the signature
        try:
            public_key.verify(
                signature,
                message.encode(),
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # If verification succeeds, return success
            # Log this verification in the audit log
            await db.append_audit_log(user_id, "KEY_VERIFICATION", "Success")
            return VerifyResponse(verified=True, message="Signature verified successfully")
        except Exception as e:
            # If verification fails, return failure
            await db.append_audit_log(user_id, "KEY_VERIFICATION", "Failed")
            return VerifyResponse(verified=False, message=f"Signature verification failed: {str(e)}")
    except Exception as e:
        return VerifyResponse(verified=False, message=f"Verification error: {str(e)}")

# Add endpoint to get user's public key
@router.get("/users/{user_id}/public_key")
async def get_user_public_key(
    user_id: str,
    db: Database = Depends(Database.get_instance)
):
    """
    Get a user's public key for verification purposes.
    """
    try:
        user = await db.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "user_id": user_id,
            "public_key": base64.b64encode(user["public_key"]).decode()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))