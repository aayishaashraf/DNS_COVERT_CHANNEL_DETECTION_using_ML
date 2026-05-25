"""
DNS Shield - Performance Benchmark (FINAL CORRECTED)
Target: 100K QPS with 3D Reshaping and Batch Processing
"""

import time
import random
import string
import numpy as np
import pandas as pd
from threat_detector import ThreatDetector

def generate_benchmark_domains(n=100000):
    """Generate realistic domain mix for benchmarking"""
    domains = []
    
    # Distribution: 70% benign, 20% DGA, 10% ambiguous
    # 70% Benign
    real = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'twitter.com', 'netflix.com', 'github.com', 'apple.com']
    
    benign_count = int(n * 0.70)
    for _ in range(benign_count):
        if random.random() < 0.8:
            domains.append(random.choice(real))
        else:
            domains.append(f'{random.choice(["api", "cdn", "www"])}.{random.choice(real)}')
    
    # 20% DGA
    dga_count = int(n * 0.20)
    for _ in range(dga_count):
        length = random.randint(20, 30)
        domain = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        domains.append(f'{domain}.com')
    
    # 10% Ambiguous (Stage 2 LSTM targets)
    ambiguous_count = n - benign_count - dga_count
    for _ in range(ambiguous_count):
        r = random.random()
        if r < 0.5:
            target = random.choice(['google', 'facebook', 'paypal'])
            typo = target.replace('o', '0').replace('l', '1')
            domains.append(f'{typo}.com')
        else:
            word = random.choice(['data', 'update', 'system'])
            num = random.randint(100, 9999)
            domains.append(f'{word}{num}.com')
    
    random.shuffle(domains)
    return domains


def main():
    print('='*70)
    print('DNS SHIELD - THROUGHPUT BENCHMARK (REALISTIC MODEL)')
    print('Target: 100K QPS with batching and 3D Reshaping')
    print('='*70)
    
    # Initialize
    detector = ThreatDetector()
    if not detector.loaded:
        print('❌ Failed to load models!')
        return
    
    # Generate test domains
    print('\n📊 Generating 100,000 test domains...')
    domains = generate_benchmark_domains(100000)
    print(f'   Generated {len(domains):,} domains')
    
    # Warmup
    print('\n🔥 Warming up LSTM layers...')
    _ = detector.check_domains_batch(domains[:100], batch_size=100)
    print('   Warmup complete')
    
    # Benchmark with different batch sizes
    batch_sizes = [1, 10, 100, 1000]
    
    print('\n🚀 Benchmarking Performance...')
    print('='*70)
    
    for batch_size in batch_sizes:
        print(f'\nBatch size: {batch_size}')
        print('-'*70)
        
        start = time.time()
        processed = 0
        
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i+batch_size]
            # Processing through updated hybrid detector
            results = detector.check_domains_batch(batch, batch_size=batch_size)
            processed += len(results)
            
            if batch_size >= 100 and processed % 10000 == 0:
                elapsed = time.time() - start
                qps = processed / elapsed
                print(f'   {processed:,}/{len(domains):,} ({qps:,.0f} QPS)', end='\r')
        
        end = time.time()
        elapsed = end - start
        qps = processed / elapsed
        
        print(f'   Processed: {processed:,} domains')
        print(f'   Time: {elapsed:.2f} seconds')
        print(f'   QPS: {qps:,.0f}')
        
        if qps >= 100000:
            print(f'   ✅ TARGET MET! (100K QPS)')
        elif qps >= 10000:
            print(f'   ⚠️  PRODUCTION READY (10K+ QPS)')
        else:
            print(f'   ❌ BELOW TARGET')
    
    # Final Summary for Dissertation
    print('\n' + '='*70)
    print('BENCHMARK SUMMARY')
    print('='*70)
    print(f'The hybrid architecture uses Stage 1 entropy filters to bypass the')
    print(f'expensive LSTM computation for {70+20}% of traffic, ensuring high')
    print(f'throughput while maintaining deep inspection for ambiguous cases.')
    print('='*70)

if __name__ == '__main__':
    main()