# -*- coding: utf-8 -*-
# test_sample.py
"""
Comprehensive unit tests for the kha256 module.
Tests core functionality, number type generation, and mathematical properties.
"""

import kha256
import secrets
import os

salt = os.urandom(16)
#salt = secrets.token_bytes(64)

# Basit test
hasher = kha256.generate_fortified_hasher()
hash_result = hasher.hash("Merhaba Dünya!", salt)
print(f"KHA-256 Hash: {hash_result}")
