#!/usr/bin/env python3
"""
cracking_demo.py — Password Hashing Security Demonstration
Information Security Semester Project

Demonstrates:
1. Why legacy hashes (MD5) are catastrophically vulnerable to dictionary/brute-force attacks.
2. Why modern memory-hard, salted algorithms (Argon2id) resist attacks.
3. The power of cryptographic salting: identical passwords yield completely distinct hashes.
4. Timing comparison: Hash rate of MD5 vs Argon2id.

Meets Module 1 Cryptographic Component Requirement:
"store passwords with a salted, slow hash (bcrypt, scrypt or Argon2), never plain text or MD5/SHA-1;
demonstrate why with a cracking test on weak versus strong hashes."
"""

import hashlib
import time
import sys

# Test wordlist
WORDLIST = [
    "password", "123456", "admin", "welcome", "secure2024",
    "letmein", "football", "monkey", "shadow", "superman",
    "infosec", "secret", "trustno1", "qwerty", "dragon"
]

TARGET_PASSWORD = "infosec"

def demo_md5_cracking():
    print("\n" + "="*70)
    print("PART 1: WEAK HASH ATTACK (MD5 - Fast, Unsalted)")
    print("="*70)
    
    # Generate MD5 of target password
    target_hash = hashlib.md5(TARGET_PASSWORD.encode()).hexdigest()
    print(f"Target plaintext password: '{TARGET_PASSWORD}'")
    print(f"Target MD5 digest        : {target_hash}")
    print(f"\nSimulating dictionary attack against target MD5 hash...")

    start_time = time.perf_counter()
    attempts = 0
    cracked = None

    for candidate in WORDLIST:
        attempts += 1
        candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
        if candidate_hash == target_hash:
            cracked = candidate
            break

    elapsed = time.perf_counter() - start_time
    rate = attempts / elapsed if elapsed > 0 else float("inf")

    print(f"\n[+] CRACKED!")
    print(f"    Password found: '{cracked}'")
    print(f"    Attempts      : {attempts}")
    print(f"    Time taken    : {elapsed*1000:.4f} ms")
    print(f"    Hash speed    : ~{rate:,.0f} attempts/second")
    print("\n[!] SECURITY ANALYSIS: MD5 is vulnerable. An attacker can compute billions")
    print("    of MD5 hashes per second on standard GPUs and use precomputed Rainbow Tables.")


def demo_argon2_security():
    print("\n" + "="*70)
    print("PART 2: MODERN SECURE HASH (Argon2id - Memory-hard, Salted)")
    print("="*70)

    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
    except ImportError:
        print("[!] argon2-cffi not installed. Running simulated slow hash...")
        return demo_simulated_slow_hash()

    ph = PasswordHasher(
        time_cost=2,        # 2 iterations
        memory_cost=65536,  # 64 MB RAM
        parallelism=2,
        hash_len=32,
        salt_len=16
    )

    print("Hashing target password using Argon2id with 64MB memory cost & 16-byte salt...")
    hash1 = ph.hash(TARGET_PASSWORD)
    hash2 = ph.hash(TARGET_PASSWORD)

    print(f"\nGenerated Hash 1:\n  {hash1}")
    print(f"\nGenerated Hash 2 (same password '{TARGET_PASSWORD}'):\n  {hash2}")
    
    print("\n[✓] CRYPTOGRAPHIC SALTING DEMONSTRATION:")
    print("    Notice how both hashes are completely different despite having the same input.")
    print("    Argon2 automatically generates a fresh 16-byte cryptographically secure salt.")
    print("    This renders precomputed Rainbow Tables completely useless.")

    print(f"\nAttempting dictionary attack against Argon2id hash...")
    start_time = time.perf_counter()
    attempts = 0
    cracked = None

    for candidate in WORDLIST:
        attempts += 1
        try:
            if ph.verify(hash1, candidate):
                cracked = candidate
                break
        except VerifyMismatchError:
            continue

    elapsed = time.perf_counter() - start_time
    rate = attempts / elapsed if elapsed > 0 else 0

    print(f"\n[+] Verified password: '{cracked}'")
    print(f"    Attempts evaluated: {attempts}")
    print(f"    Time taken        : {elapsed:.3f} seconds ({elapsed*1000/attempts:.1f} ms/attempt)")
    print(f"    Hash rate         : {rate:.2f} attempts/second")
    print("\n[✓] SECURITY ANALYSIS: Argon2id deliberately forces high computational and")
    print("    memory costs. At ~20-50ms per attempt, brute-forcing an 8-character complex")
    print("    password would take centuries on modern hardware.")


def demo_simulated_slow_hash():
    import hmac
    print("Demonstrating PBKDF2-HMAC-SHA256 (100,000 iterations)...")
    salt = b"random_lab_salt_1234"
    start = time.perf_counter()
    key = hashlib.pbkdf2_hmac("sha256", TARGET_PASSWORD.encode(), salt, 100000)
    elapsed = time.perf_counter() - start
    print(f"Time for 1 hash: {elapsed*1000:.2f} ms")


def main():
    print("======================================================================")
    print("  INFOSEC SEMESTER PROJECT: PASSWORD CRACKING & HASHING COMPARISON")
    print("======================================================================")
    demo_md5_cracking()
    demo_argon2_security()
    print("\n" + "="*70)
    print("SUMMARY COMPARISON TABLE:")
    print("="*70)
    print(f"{'Algorithm':<12} | {'Salted?':<8} | {'Speed / Throughput':<22} | {'Attack Resistance'}")
    print("-" * 70)
    print(f"{'MD5':<12} | {'No':<8} | {'> 1,000,000,000 / sec':<22} | {'BROKEN (Rainbow Tables, GPU)'}")
    print(f"{'SHA-1':<12} | {'No':<8} | {'> 500,000,000 / sec':<22} | {'BROKEN (Collision attacks)'}")
    print(f"{'Argon2id':<12} | {'Yes (auto)':<8} | {'~ 20 - 50 / sec':<22} | {'HIGH (Memory-hard, winner of PHC)'}")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()

