import sqlite3
from pathlib import Path
from app.core.config import settings

def verify_audit_log():
    print("\n=== Verifying Audit Log ===")
    
    # Check file logs
    log_file = Path("storage/logs/audit.log")
    if log_file.exists():
        print("\nFile Audit Log:")
        with open(log_file) as f:
            print(f.read())
    
    # Check database logs
    db_path = settings.SQLITE_URL
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\nDatabase Audit Log:")
    cursor.execute("""
        SELECT timestamp, user_id, operation, file_id, prev_hash, current_hash 
        FROM audit_log 
        ORDER BY timestamp
    """)
    
    for row in cursor.fetchall():
        print(f"Time: {row[0]}, User: {row[1]}, Operation: {row[2]}, File: {row[3]}")
        print(f"Hash Chain: {row[4]} -> {row[5]}\n")
    
    # Verify hash chain integrity
    cursor.execute("SELECT prev_hash, current_hash FROM audit_log ORDER BY timestamp")
    rows = cursor.fetchall()
    
    chain_valid = True
    for i in range(1, len(rows)):
        if rows[i][0] != rows[i-1][1]:
            chain_valid = False
            print(f"Hash chain broken at entry {i}")
    
    print(f"Hash Chain Integrity: {'Valid' if chain_valid else 'Invalid'}")

if __name__ == "__main__":
    verify_audit_log() 