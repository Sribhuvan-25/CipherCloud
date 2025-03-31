import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from ..db.models import Database

class AuditLogger:
    _instance = None

    def __new__(cls, db: Database):
        if cls._instance is None:
            cls._instance = super(AuditLogger, cls).__new__(cls)
            cls._instance.db = db
            cls._instance._setup_logging()
        return cls._instance

    def _setup_logging(self):
        if hasattr(self, 'logger'):
            return
            
        log_dir = Path("storage/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler for audit logs
        audit_handler = logging.FileHandler(log_dir / "audit.log")
        audit_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(message)s')
        )
        
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers to prevent duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            
        self.logger.addHandler(audit_handler)

    async def log_operation(
        self,
        operation: str,
        user_id: str,
        file_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an operation to both database and file"""
        timestamp = datetime.utcnow().isoformat()
        
        # Get previous hash and compute new one
        prev_hash = await self.db.get_last_log_hash()
        log_data = f"{timestamp}{operation}{user_id}{file_id or ''}"
        
        # Log to database
        await self.db.append_audit_log(
            user_id=user_id,
            operation=operation,
            file_id=file_id,
            prev_hash=prev_hash,
            details=details
        )
        
        # Log to file
        self.logger.info(
            f"Operation: {operation} | User: {user_id} | File: {file_id or 'N/A'} | "
            f"Details: {details or 'N/A'}"
        ) 