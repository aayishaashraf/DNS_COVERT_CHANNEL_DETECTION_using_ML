import sys
import os
import time

# Make it work from any directory
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.ibhh_detector import IBHHDetector

# Optional: full pipeline if you want to benchmark threat_detector too
# from threat_detector import ThreatDetector

# ────────────────────────────────────────────────
#  CONFIG
# ────────────────────────────────────────────────

N_QUERIES = 100_000              # change to 1_000_000 for serious test
print(f"Benchmarking {N_QUERIES:,} queries...")

# ────────────────────────────────────────────────
#  STAGE 0 ONLY (IBHH) – should be very fast
# ────────────────────────────────────────────────

detector = IBHHDetector(p=12)

start = time.perf_counter()

for i in range(N_QUERIES):
    domain = f"sub{i % 5000}.example.com"   # some repetition to simulate realistic traffic
    detector.process_query(domain)

elapsed = time.perf_counter() - start
qps = N_QUERIES / elapsed

print(f"\nIBHH Stage 0 only:")
print(f"  Processed {N_QUERIES:,} queries in {elapsed:.3f} seconds")
print(f"  Throughput: {qps:,.0f} queries/second")
print(f"  Per query time: {elapsed / N_QUERIES * 1_000_000:,.1f} μs")

# ────────────────────────────────────────────────
#  OPTIONAL: Full pipeline (IBHH + Entropy + LSTM)
# ────────────────────────────────────────────────
"""
detector_full = ThreatDetector()   # uncomment if you want full system benchmark

start_full = time.perf_counter()

for i in range(N_QUERIES):
    domain = f"sub{i % 5000}.example.com"
    detector_full.check_domain(domain)

elapsed_full = time.perf_counter() - start_full
qps_full = N_QUERIES / elapsed_full

print(f"\nFull pipeline:")
print(f"  Processed {N_QUERIES:,} queries in {elapsed_full:.3f} seconds")
print(f"  Throughput: {qps_full:,.0f} qps")
"""