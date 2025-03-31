import os
import time
import matplotlib.pyplot as plt
import numpy as np
from ..core.crypto import generate_data_encryption_key, aes_encrypt, aes_decrypt
from ..client.client import SecureCloudClient

def benchmark_encryption(sizes=[1, 5, 10, 20, 50, 100]):
    """Benchmark encryption performance for different file sizes (in MB)"""
    results = []
    
    for size in sizes:
        # Generate random data of specified size
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
    
    return results

def benchmark_file_operations(server_url, user_id, private_key_path, 
                             sizes=[1, 5, 10, 20]):
    """Benchmark file upload and download operations"""
    results = []
    client = SecureCloudClient(server_url, user_id)
    client.load_private_key(private_key_path)
    
    for size in sizes:
        # Create test file
        test_file = f"test_file_{size}mb.dat"
        with open(test_file, 'wb') as f:
            f.write(os.urandom(size * 1024 * 1024))
        
        # Measure upload time
        start_time = time.time()
        upload_result = client.upload_file(test_file)
        upload_time = time.time() - start_time
        file_id = upload_result['file_id']
        
        # Measure download time
        start_time = time.time()
        client.download_file(file_id, f"downloaded_{size}mb.dat")
        download_time = time.time() - start_time
        
        results.append({
            'size_mb': size,
            'upload_time_s': upload_time,
            'download_time_s': download_time,
            'upload_throughput_mbps': size / upload_time,
            'download_throughput_mbps': size / download_time
        })
        
        # Clean up
        os.remove(test_file)
        os.remove(f"downloaded_{size}mb.dat")
    
    return results

def plot_benchmark_results(results, metric_name, title, xlabel, ylabel):
    """Plot benchmark results"""
    sizes = [r['size_mb'] for r in results]
    values = [r[metric_name] for r in results]
    
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, values, 'o-', linewidth=2)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True)
    plt.savefig(f"{metric_name}_benchmark.png")
    plt.close()

def run_all_benchmarks(server_url, user_id, private_key_path):
    """Run all benchmarks and generate reports"""
    # Create output directory
    os.makedirs("benchmark_results", exist_ok=True)
    
    # Run encryption benchmarks
    print("Running encryption benchmarks...")
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
    
    # Run file operation benchmarks
    print("Running file operation benchmarks...")
    file_results = benchmark_file_operations(
        server_url, user_id, private_key_path
    )
    
    # Plot file operation results
    plot_benchmark_results(
        file_results, 
        'upload_throughput_mbps', 
        'Upload Throughput vs File Size', 
        'File Size (MB)', 
        'Throughput (MB/s)'
    )
    
    # Save raw results
    with open("benchmark_results/encryption_results.txt", "w") as f:
        for r in enc_results:
            f.write(f"{r}\n")
            
    with open("benchmark_results/file_results.txt", "w") as f:
        for r in file_results:
            f.write(f"{r}\n")
            
    print("Benchmarks complete. Results saved to benchmark_results/")
    
    return {
        'encryption': enc_results,
        'file_operations': file_results
    } 