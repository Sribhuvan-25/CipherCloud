#!/usr/bin/env python3
"""
Standalone evaluation script that doesn't rely on other modules.
"""

import os
import time
import json
import sqlite3
import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests
from hashlib import sha256

# ================= Crypto Functions =================

def generate_data_encryption_key():
    """Generate a random 256-bit key for AES encryption."""
    return AESGCM.generate_key(bit_length=256)

def aes_encrypt(key, plaintext):
    """Encrypt data with AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        'nonce': nonce,
        'ciphertext': ciphertext
    }

def aes_decrypt(key, nonce, ciphertext):
    """Decrypt data with AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def load_private_key(key_path, password=None):
    """Load a private key from PEM format."""
    with open(key_path, 'rb') as f:
        key_data = f.read()
    
    if password:
        password = password.encode()
    return serialization.load_pem_private_key(key_data, password=password)

def compute_hash_chain(prev_hash, log_data):
    """Compute the next hash in the chain."""
    # Handle None values properly
    prev_hash = prev_hash or "0" * 64  # Use 64 zeros if prev_hash is None
    
    # If file_id is None, replace with empty string to match application behavior
    file_id = log_data['file_id'] if log_data['file_id'] is not None else ''
    
    # Test all possible orderings of fields to find the correct one
    if log_data.get('id') == 1:
        print("\nDEBUG: Testing hash formats against known first log entry")
        
        # Known values from first log entry
        known_prev_hash = "0" * 64
        known_timestamp = "2025-03-03T20:47:47.846134"
        known_user_id = "test_user"
        known_file_id = "66e21bc0-b55f-45d2-a13e-b34cea63c7ae"
        known_operation = "upload"
        known_hash = "3cea2098e67d8ba176fca7ad6dea007c7db7485b6d5bbeffc60f2342be57e11a"
        
        # Test all possible formats
        test_formats = []
        
        # Format 1: timestamp+operation+user+file (from app.utils.logging)
        data1 = f"{known_timestamp}{known_operation}{known_user_id}{known_file_id}"
        hash1 = sha256(f"{known_prev_hash}{data1}".encode()).hexdigest()
        test_formats.append((1, hash1, "timestamp+operation+user+file"))
        
        # Format 2: user+operation+timestamp+file
        data2 = f"{known_user_id}{known_operation}{known_timestamp}{known_file_id}"
        hash2 = sha256(f"{known_prev_hash}{data2}".encode()).hexdigest()
        test_formats.append((2, hash2, "user+operation+timestamp+file"))
        
        # Format 3: operation+user+file+timestamp
        data3 = f"{known_operation}{known_user_id}{known_file_id}{known_timestamp}"
        hash3 = sha256(f"{known_prev_hash}{data3}".encode()).hexdigest()
        test_formats.append((3, hash3, "operation+user+file+timestamp"))
        
        # Format 4: timestamp+user+file+operation
        data4 = f"{known_timestamp}{known_user_id}{known_file_id}{known_operation}"
        hash4 = sha256(f"{known_prev_hash}{data4}".encode()).hexdigest()
        test_formats.append((4, hash4, "timestamp+user+file+operation"))
        
        # Format 5: timestamp+user+operation+file
        data5 = f"{known_timestamp}{known_user_id}{known_operation}{known_file_id}"
        hash5 = sha256(f"{known_prev_hash}{data5}".encode()).hexdigest()
        test_formats.append((5, hash5, "timestamp+user+operation+file"))
        
        # Check all formats against known hash
        print(f"Expected hash: {known_hash}")
        matches_found = False
        
        for fmt_num, fmt_hash, fmt_desc in test_formats:
            match = "✓" if fmt_hash == known_hash else "✗"
            print(f"{match} Format {fmt_num}: {fmt_hash} - {fmt_desc}")
            if fmt_hash == known_hash:
                matches_found = True
                print(f"\nSUCCESS! Found matching format #{fmt_num}: {fmt_desc}")
        
        if not matches_found:
            print("\nWARNING: No exact matches found for the first log hash.")
    
    # Based on the app/utils/logging.py file, the format used is:
    # f"{timestamp}{operation}{user_id}{file_id or ''}"
    data = f"{log_data['timestamp']}{log_data['operation']}{log_data['user_id']}{file_id}"
    return sha256(f"{prev_hash}{data}".encode()).hexdigest()

# ================= Benchmarking Functions =================

def benchmark_encryption(sizes=[1, 5, 10, 20]):
    """Benchmark encryption performance for different file sizes (in MB)"""
    results = []
    
    for size in sizes:
        # Generate random data of specified size
        print(f"  Testing {size}MB file...")
        data = os.urandom(size * 1024 * 1024)
        key = generate_data_encryption_key()
        
        # Measure encryption time
        start_time = time.time()
        encrypted = aes_encrypt(key, data)
        enc_time = time.time() - start_time
        
        # Measure decryption time
        start_time = time.time()
        decrypted = aes_decrypt(key, encrypted['nonce'], encrypted['ciphertext'])
        dec_time = time.time() - start_time
        
        # Calculate overhead
        enc_size = len(encrypted['ciphertext'])
        overhead_pct = (enc_size / len(data) - 1) * 100
        
        results.append({
            'size_mb': size,
            'enc_time_s': enc_time,
            'dec_time_s': dec_time,
            'enc_throughput_mbps': size / enc_time,
            'dec_throughput_mbps': size / dec_time,
            'overhead_pct': overhead_pct
        })
        
        print(f"    Encryption: {enc_time:.3f}s, Decryption: {dec_time:.3f}s")
    
    return results

def plot_benchmark_results(results, metric_name, title, xlabel, ylabel):
    """Plot benchmark results"""
    os.makedirs("benchmark_results", exist_ok=True)
    
    sizes = [r['size_mb'] for r in results]
    values = [r[metric_name] for r in results]
    
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, values, 'o-', linewidth=2)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True)
    plt.savefig(f"benchmark_results/{metric_name}_benchmark.png")
    plt.close()
    
    print(f"  Plot saved to benchmark_results/{metric_name}_benchmark.png")

def test_audit_log_integrity(db_path):
    """Test if the audit log chain is intact"""
    # Connect to database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all audit logs
    cursor.execute('SELECT * FROM audit_log ORDER BY id')
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    if not logs:
        return {
            'total_logs': 0,
            'integrity_intact': True,
            'failures': []
        }
    
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
                'id': log['id'],
                'expected': calculated_hash,
                'actual': log['current_hash']
            })
    
    return results

def run_all_benchmarks():
    """Run comprehensive benchmarks and return results"""
    # Create output directory
    os.makedirs("benchmark_results", exist_ok=True)
    
    print("\n1. Running encryption benchmarks...")
    enc_results = benchmark_encryption()
    
    # Plot encryption results
    plot_benchmark_results(
        enc_results, 
        'enc_time_s', 
        'Encryption Time vs File Size', 
        'File Size (MB)', 
        'Encryption Time (s)'
    )
    
    plot_benchmark_results(
        enc_results, 
        'overhead_pct', 
        'Storage Overhead vs File Size', 
        'File Size (MB)', 
        'Overhead (%)'
    )
    
    plot_benchmark_results(
        enc_results, 
        'enc_throughput_mbps', 
        'Encryption Throughput vs File Size', 
        'File Size (MB)', 
        'Throughput (MB/s)'
    )
    
    # Save raw results
    with open("benchmark_results/encryption_results.txt", "w") as f:
        for r in enc_results:
            f.write(f"{r}\n")
    
    return {
        'encryption': enc_results
    }

def perform_security_evaluation(db_path='storage/secure_storage.db'):
    """Run comprehensive security evaluation"""
    os.makedirs("security_results", exist_ok=True)
    
    print("\n2. Testing audit log integrity...")
    integrity_results = test_audit_log_integrity(db_path)
    
    # Display results
    print(f"  Total logs analyzed: {integrity_results['total_logs']}")
    print(f"  Integrity intact: {'✓' if integrity_results['integrity_intact'] else '✗'}")
    
    if not integrity_results['integrity_intact']:
        print(f"  Found {len(integrity_results['failures'])} integrity failures")
        
    # Save results
    with open("security_results/evaluation.json", "w") as f:
        json.dump(integrity_results, f, indent=2)
        
    print("  Results saved to security_results/evaluation.json")
    
    return {
        'audit_integrity': integrity_results
    }

def main():
    print("=" * 50)
    print("SECURE CLOUD STORAGE EVALUATION")
    print("=" * 50)
    
    # Configuration
    db_path = input("Database path [storage/secure_storage.db]: ") or "storage/secure_storage.db"
    
    # Run performance benchmarks
    performance_results = run_all_benchmarks()
    
    # Run security evaluation
    security_results = perform_security_evaluation(db_path)
    
    # Print summary
    print("\n" + "=" * 50)
    print("EVALUATION SUMMARY")
    print("=" * 50)
    
    print("\n1. PERFORMANCE METRICS:")
    print("   Average Encryption Speed: {:.2f} MB/s".format(
        sum(r['enc_throughput_mbps'] for r in performance_results['encryption']) / 
        len(performance_results['encryption'])
    ))
    print("   Average Decryption Speed: {:.2f} MB/s".format(
        sum(r['dec_throughput_mbps'] for r in performance_results['encryption']) / 
        len(performance_results['encryption'])
    ))
    print("   Average Storage Overhead: {:.2f}%".format(
        sum(r['overhead_pct'] for r in performance_results['encryption']) / 
        len(performance_results['encryption'])
    ))
    
    print("\n2. SECURITY EVALUATION:")
    print("   Audit Log Integrity: {}".format(
        "✓ PASSED" if security_results['audit_integrity']['integrity_intact'] else "✗ FAILED"
    ))
    
    print("\nDetailed results and graphs saved to:")
    print("  - benchmark_results/")
    print("  - security_results/")
    
if __name__ == "__main__":
    main()