# -*- coding: utf-8 -*-
# test_sample.py
"""
Comprehensive unit tests for the kha256 module.
Tests core functionality, number type generation, and mathematical properties.
"""

import kha256
import secrets
import os

def test_fortified_hash_generates_output():
    """Test that fortified hasher produces hash output"""
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    hash_result = hasher.hash("Merhaba Dünya!", salt)
    
    assert hash_result is not None
    assert len(hash_result) > 0
    
    print(f"\n[TEST 1] Hash Üretildi:")
    print(f"  Salt (hex): {salt.hex()}")
    print(f"  KHA-256 Hash: {hash_result}")

def test_hash_is_deterministic():
    """Test that same input produces same output"""
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    
    result1 = hasher.hash("test", salt)
    result2 = hasher.hash("test", salt)
    
    assert result1 == result2
    
    print(f"\n[TEST 2] Deterministik Kontrolü (Aynı Girdi -> Aynı Çıktı):")
    print(f"  Salt (hex): {salt.hex()}")
    print(f"  Hash 1: {result1}")
    print(f"  Hash 2: {result2}")
    print(f"  Sonuç: {'BAŞARILI (Eşit)' if result1 == result2 else 'BAŞARISIZ'}")

def test_hash_different_inputs_produce_different_outputs():
    """Test that different inputs produce different hashes"""
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    
    result1 = hasher.hash("input1", salt)
    result2 = hasher.hash("input2", salt)
    
    assert result1 != result2
    
    print(f"\n[TEST 3] Farklı Girdi Kontrolü (Farklı Girdi -> Farklı Çıktı):")
    print(f"  Salt (hex): {salt.hex()}")
    print(f"  'input1' Hash: {result1}")
    print(f"  'input2' Hash: {result2}")
    print(f"  Sonuç: {'BAŞARILI (Farklı)' if result1 != result2 else 'BAŞARISIZ'}")


# ======================================================================
# SCRIPT LEVEL EXECUTION (Modül Seviyesi Çalıştırma)
# ======================================================================
print("\n" + "="*60)
print("MODÜL SEVİYESİ (SCRIPT) ÇALIŞTIRMASI")
print("="*60)

salt = secrets.token_bytes(64)
hasher = kha256.generate_fortified_hasher()
hash_result = hasher.hash("Merhaba Dünya!", salt)

print(f"Salt (64 bytes, hex): {salt.hex()}")
print(f"KHA-256 Hash: {hash_result}")
print("="*60)


# ======================================================================
# RUN TESTS IF EXECUTED DIRECTLY
# ======================================================================
if __name__ == "__main__":
    test_fortified_hash_generates_output()
    test_hash_is_deterministic()
    test_hash_different_inputs_produce_different_outputs()
