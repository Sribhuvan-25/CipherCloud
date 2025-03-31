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
        # In a real system, implement proper authentication
        # For testing, we'll accept any registered user
        user = await db.get_user(form_data.username)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create access token with user_id as subject
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
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

        # Log operation
        await audit_logger.log_operation(
            operation="update",
            user_id=current_user,
            file_id=file_id
        )

        return {"status": "success", "message": "File updated successfully"}
    except Exception as e:
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