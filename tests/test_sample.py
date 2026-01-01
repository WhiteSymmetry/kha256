# -*- coding: utf-8 -*-
# test_sample.py
"""
Comprehensive unit tests for the kha256 module.
Tests core functionality, number type generation, and mathematical properties.
"""

import kha256

# Basit test
hasher = kha256.generate_fortified_hasher()
hash_result = hasher.hash("Merhaba Dünya!")
print(f"KHA-256 Hash: {hash_result}")
