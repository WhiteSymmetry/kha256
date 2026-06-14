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
    print(f"KHA-256 Hash: {hash_result}")

def test_hash_is_deterministic():
    """Test that same input produces same output"""
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    
    result1 = hasher.hash("test", salt)
    result2 = hasher.hash("test", salt)
    
    assert result1 == result2

def test_hash_different_inputs_produce_different_outputs():
    """Test that different inputs produce different hashes"""
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    
    result1 = hasher.hash("input1", salt)
    result2 = hasher.hash("input2", salt)
    
    assert result1 != result2

#salt = os.urandom(16)
salt = secrets.token_bytes(64)

# Basit test
hasher = kha256.generate_fortified_hasher()
hash_result = hasher.hash("Merhaba Dünya!", salt)
print(f"KHA-256 Hash: {hash_result}")
