import sqlite3
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

class Database:
    _instance = None

    def __init__(self, db_path: str):
        """Initialize database connection"""
        if Database._instance is not None:
            raise RuntimeError("Use get_instance() instead")
        
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls) -> 'Database':
        """Get or create the database instance"""
        if cls._instance is None:
            from app.core.config import settings
            cls._instance = cls(settings.SQLITE_URL)
        return cls._instance

    def _get_connection(self):
        """Get a database connection"""
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize database tables"""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    file_path TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY(owner_id) REFERENCES users(user_id)
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    file_id TEXT,
                    prev_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    details TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id)
                )
            ''')

    async def init_db(self):
        """Async wrapper for database initialization"""
        self._init_db()

    async def store_file_metadata(
        self, 
        file_id: str, 
        user_id: str, 
        wrapped_dek: bytes, 
        file_path: str, 
        metadata: Dict[str, Any]
    ) -> None:
        """Store file metadata in the database"""
        with self._get_connection() as conn:
            try:
                conn.execute(
                    """INSERT INTO files 
                       (file_id, owner_id, wrapped_dek, file_path, metadata)
                       VALUES (?, ?, ?, ?, ?)""",
                    (file_id, user_id, wrapped_dek, file_path, json.dumps(metadata))
                )
            except sqlite3.Error as e:
                print(f"Database error: {str(e)}")
                raise Exception(f"Failed to store file metadata: {str(e)}")

    async def get_file_metadata(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve file metadata from the database"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT owner_id, wrapped_dek, file_path, metadata FROM files WHERE file_id = ?",
                (file_id,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'owner_id': row[0],
                    'wrapped_dek': row[1],
                    'file_path': row[2],
                    'metadata': json.loads(row[3])
                }
            return None

    async def get_last_log_hash(self) -> str:
        """Get the hash of the last audit log entry"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT current_hash FROM audit_log ORDER BY timestamp DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return row[0] if row else "0" * 64

    async def append_audit_log(
        self,
        user_id: str,
        operation: str,
        file_id: Optional[str] = None,
        prev_hash: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Append a new audit log entry"""
        timestamp = datetime.utcnow().isoformat()
        current_hash = self._compute_hash(
            prev_hash or "0" * 64,
            f"{timestamp}{operation}{user_id}{file_id or ''}"
        )
        
        with self._get_connection() as conn:
            try:
                conn.execute(
                    """INSERT INTO audit_log 
                       (timestamp, user_id, operation, file_id, prev_hash, 
                        current_hash, details)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (timestamp, user_id, operation, file_id, prev_hash,
                     current_hash, json.dumps(details) if details else None)
                )
                return current_hash
            except sqlite3.Error as e:
                print(f"Database error: {str(e)}")
                raise Exception(f"Failed to append audit log: {str(e)}")

    def _compute_hash(self, prev_hash: str, data: str) -> str:
        """Compute hash for audit log chain"""
        from hashlib import sha256
        return sha256(f"{prev_hash}{data}".encode()).hexdigest()

    async def store_user(self, user_id: str, public_key: bytes) -> None:
        """Store user information in the database"""
        with self._get_connection() as conn:
            try:
                # Try to insert new user
                conn.execute(
                    "INSERT INTO users (user_id, public_key) VALUES (?, ?)",
                    (user_id, public_key)
                )
            except sqlite3.IntegrityError:
                # If user exists, update their public key
                conn.execute(
                    "UPDATE users SET public_key = ? WHERE user_id = ?",
                    (public_key, user_id)
                )

    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve user information from the database"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT user_id, public_key FROM users WHERE user_id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'user_id': row[0],
                    'public_key': row[1]
                }
            return None

    async def update_user_public_key(self, user_id: str, public_key: bytes) -> None:
        """Update user's public key"""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET public_key = ? WHERE user_id = ?",
                (public_key, user_id)
            ) 
            
    async def delete_file_metadata(self, file_id: str) -> None:
        """Delete file metadata from the database"""
        with self._get_connection() as conn:
            try:
                conn.execute(
                    "DELETE FROM files WHERE file_id = ?",
                    (file_id,)
                )
            except sqlite3.Error as e:
                print(f"Database error: {str(e)}")
                raise Exception(f"Failed to delete file metadata: {str(e)}")

    async def update_wrapped_dek(self, file_id: str, wrapped_dek: bytes):
        """Update wrapped data encryption key for a file"""
        with self._get_connection() as conn:
            try:
                cursor = conn.execute(
                    "SELECT file_id FROM files WHERE file_id = ?",
                    (file_id,)
                )
                if not cursor.fetchone():
                    raise ValueError(f"File {file_id} not found")
                
                conn.execute(
                    "UPDATE files SET wrapped_dek = ? WHERE file_id = ?",
                    (wrapped_dek, file_id)
                )
                return True
            except sqlite3.Error as e:
                print(f"Database error: {str(e)}")
                raise Exception(f"Failed to update wrapped DEK: {str(e)}")
        
    async def update_file_metadata(self, file_id: str, metadata: dict):
        """Update metadata for a file"""
        with self._get_connection() as conn:
            try:
                cursor = conn.execute(
                    "SELECT file_id FROM files WHERE file_id = ?",
                    (file_id,)
                )
                if not cursor.fetchone():
                    raise ValueError(f"File {file_id} not found")
                
                conn.execute(
                    "UPDATE files SET metadata = ? WHERE file_id = ?",
                    (json.dumps(metadata), file_id)
                )
                return True
            except sqlite3.Error as e:
                print(f"Database error: {str(e)}")
                raise Exception(f"Failed to update file metadata: {str(e)}")

    async def get_user_files(self, user_id: str) -> list:
        """Retrieve all files owned by a user"""
        with self._get_connection() as conn:
            try:
                cursor = conn.execute(
                    """SELECT file_id, wrapped_dek, file_path, metadata 
                       FROM files WHERE owner_id = ?""",
                    (user_id,)
                )
                
                files = []
                for row in cursor.fetchall():
                    files.append({
                        'file_id': row[0],
                        'wrapped_dek': row[1],
                        'file_path': row[2],
                        'metadata': json.loads(row[3] or '{}'),
                        'owner_id': user_id
                    })
                
                return files
            except sqlite3.Error as e:
                print(f"Database error: {str(e)}")
                raise Exception(f"Failed to retrieve user files: {str(e)}")

    async def get_user_audit_logs(self, user_id: str) -> List[Dict[str, Any]]:
        """Retrieve all audit log entries for a user"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """SELECT id, timestamp, operation, file_id, prev_hash, 
                          current_hash, details
                   FROM audit_log 
                   WHERE user_id = ?
                   ORDER BY timestamp""",
                (user_id,)
            )
            rows = cursor.fetchall()
            return [{
                'id': row[0],
                'timestamp': row[1],
                'operation': row[2],
                'file_id': row[3],
                'prev_hash': row[4],
                'current_hash': row[5],
                'details': json.loads(row[6]) if row[6] else None
            } for row in rows] 