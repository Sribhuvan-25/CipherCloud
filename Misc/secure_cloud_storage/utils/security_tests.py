import os
import json
import time
from ..core.database import DatabaseHandler
from ..core.crypto import compute_hash_chain

def test_audit_log_integrity(db_path):
    """Test if the audit log chain is intact"""
    db = DatabaseHandler(db_path)
    logs = []
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_log ORDER BY log_id')
        cols = [col[0] for col in cursor.description]
        
        for row in cursor.fetchall():
            logs.append(dict(zip(cols, row)))
    
    results = {
        'total_logs': len(logs),
        'integrity_intact': True,
        'failures': []
    }
    
    for i, log in enumerate(logs):
        # Skip first log (genesis)
        if i == 0 and log['prev_hash'] is None:
            continue
            
        # Create log data for hash verification
        log_data = {
            'timestamp': log['timestamp'],
            'user_id': log['user_id'],
            'file_id': log['file_id'],
            'operation': log['operation']
        }
        
        # Get previous hash
        prev_hash = logs[i-1]['current_hash'] if i > 0 else None
        
        # Calculate expected hash
        calculated_hash = compute_hash_chain(prev_hash, log_data)
        
        # Compare with stored hash
        if calculated_hash != log['current_hash']:
            results['integrity_intact'] = False
            results['failures'].append({
                'log_id': log['log_id'],
                'expected': calculated_hash,
                'actual': log['current_hash']
            })
    
    return results

def test_tamper_resistance(db_path):
    """Test system's ability to detect tampering"""
    # Create a copy of the database
    test_db = f"{db_path}.test"
    os.system(f"cp {db_path} {test_db}")
    
    db = DatabaseHandler(test_db)
    
    # Get a log entry to tamper with
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_log LIMIT 1 OFFSET 5')
        log = cursor.fetchone()
        log_id = log[0]
        
        # Tamper with the operation field
        cursor.execute(
            'UPDATE audit_log SET operation = ? WHERE log_id = ?',
            ('TAMPERED_OPERATION', log_id)
        )
        conn.commit()
    
    # Verify integrity
    results = test_audit_log_integrity(test_db)
    
    # Clean up
    os.remove(test_db)
    
    return {
        'tamper_detected': not results['integrity_intact'],
        'tampered_log_id': log_id,
        'detection_details': results['failures']
    }

def perform_security_evaluation():
    """Run comprehensive security evaluation"""
    results = {
        'audit_integrity': test_audit_log_integrity('storage/secure_storage.db'),
        'tamper_resistance': test_tamper_resistance('storage/secure_storage.db')
    }
    
    # Save results
    os.makedirs("security_results", exist_ok=True)
    with open("security_results/evaluation.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("Security evaluation complete. Results saved to security_results/")
    
    return results 