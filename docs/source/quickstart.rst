Quick Start Guide
=================

Get started with KHA-256 in 5 minutes.

Basic Hashing
-------------

Import and Hash
^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import quick_hash
   
   # Hash a string
   hash_result = quick_hash("Hello KHA-256!")
   print(f"Hash: {hash_result}")
   
   # Hash binary data
   binary_data = b"\x00\x01\x02\x03"
   hash_binary = quick_hash(binary_data)
   print(f"Binary Hash: {hash_binary}")

Expected Output:

.. code-block:: text

   Hash: 8f3a2b1c5d7e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5
   Binary Hash: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0

Password Hashing
----------------

Secure Password Storage
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import hash_password
   import secrets
   
   # Hash password with auto-generated salt
   password = "MySecurePassword123!"
   hashed = hash_password(password)
   print(f"Hashed Password: {hashed[:80]}...")
   
   # With custom salt
   custom_salt = secrets.token_bytes(32)
   hashed_custom = hash_password(password, salt=custom_salt)
   print(f"Custom Salt Hash: {hashed_custom[:80]}...")

Password Verification
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   def verify_password(stored_hash, password):
       """Verify password against stored hash."""
       # Extract salt from stored hash format: "KHA256$salt$hash"
       parts = stored_hash.split('$')
       if len(parts) != 3:
           return False
       
       salt_hex, stored_hash_value = parts[1], parts[2]
       salt = bytes.fromhex(salt_hex)
       
       # Re-hash with extracted salt
       from kha256 import FortifiedKhaHash256
       hasher = FortifiedKhaHash256()
       new_hash = hasher.hash(password, salt)
       
       return new_hash == stored_hash_value
   
   # Usage
   stored = hash_password("password123")
   is_valid = verify_password(stored, "password123")  # True
   is_invalid = verify_password(stored, "wrongpass")   # False

Command Line Interface
----------------------

Basic Commands
^^^^^^^^^^^^^^

.. code-block:: bash

   # Display version
   python -m kha256 --version
   
   # Hash text
   python -m kha256 --hash "Hello World"
   
   # Run demo
   python -m kha256 --demo
   
   # Run comprehensive tests
   python -m kha256 --test
   
   # Benchmark performance
   python -m kha256 --benchmark

Advanced CLI Usage
^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Hash file content
   python -m kha256 --hash "$(cat file.txt)"
   
   # Hash with custom salt
   python -c "from kha256 import quick_hash; import secrets; 
              print(quick_hash('data', salt=secrets.token_bytes(32)))"
   
   # Batch processing
   echo -e "data1\ndata2\ndata3" | xargs -I {} python -m kha256 --hash "{}"

Custom Hasher Configuration
---------------------------

Basic Configuration
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import FortifiedKhaHash256, FortifiedConfig
   
   # Create custom configuration
   config = FortifiedConfig(
       iterations=16,           # More iterations for security
       shuffle_layers=12,       # More mixing layers
       salt_length=64,          # Longer salt
       double_hashing=True,     # Enable double hashing
       enable_quantum_resistance=True  # Quantum-resistant features
   )
   
   # Create hasher with custom config
   hasher = FortifiedKhaHash256(config)
   
   # Use the hasher
   result = hasher.hash("Important data", salt=b"custom_salt_32_bytes")
   print(f"Custom Hash: {result}")

Performance vs Security Modes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import FortifiedConfig
   
   # Fast mode (less secure, faster)
   fast_config = FortifiedConfig(
       iterations=8,
       shuffle_layers=6,
       components_per_hash=12,
       enable_quantum_resistance=False,
       double_hashing=False
   )
   
   # Secure mode (maximum security)
   secure_config = FortifiedConfig(
       iterations=24,
       shuffle_layers=20,
       components_per_hash=32,
       enable_quantum_resistance=True,
       double_hashing=True,
       triple_compression=True
   )
   
   # Balanced mode (default)
   balanced_config = FortifiedConfig()  # Uses default values

Batch Processing
----------------

Multiple Items
^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import FortifiedKhaHash256
   
   hasher = FortifiedKhaHash256()
   
   # List of items to hash
   items = ["item1", "item2", "item3", "item4"]
   
   # Hash all items
   hashes = [hasher.hash(item) for item in items]
   
   # Display results
   for item, hash_val in zip(items, hashes):
       print(f"{item}: {hash_val[:16]}...")

File Hashing
^^^^^^^^^^^^

.. code-block:: python

   def hash_file(filepath, chunk_size=8192):
       """Hash a file efficiently."""
       from kha256 import FortifiedKhaHash256
       import hashlib
       
       hasher = FortifiedKhaHash256()
       file_hash = hashlib.sha256()
       
       with open(filepath, 'rb') as f:
           while chunk := f.read(chunk_size):
               # Hash chunk with KHA-256
               chunk_hash = hasher.hash(chunk)
               file_hash.update(chunk_hash.encode())
       
       return file_hash.hexdigest()
   
   # Usage
   file_hash = hash_file("large_file.bin")
   print(f"File Hash: {file_hash}")

Security Testing
----------------

Avalanche Test
^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import FortifiedKhaHash256
   
   hasher = FortifiedKhaHash256()
   
   # Run avalanche test
   results = hasher.test_avalanche_effect(samples=50)
   
   print(f"Average Bit Change: {results['avg_bit_change_percent']:.2f}%")
   print(f"In Ideal Range: {results['in_ideal_range']}")
   print(f"Status: {results['status']}")
   
   # Interpretation
   if results['status'] in ['EXCELLENT', 'GOOD']:
       print("✅ Strong avalanche effect detected")
   else:
       print("⚠️  Avalanche effect needs improvement")

Collision Test
^^^^^^^^^^^^^^

.. code-block:: python

   # Test collision resistance
   collision_results = hasher.test_collision_resistance(samples=1000)
   
   print(f"Collisions Found: {collision_results['collisions']}")
   print(f"Collision Rate: {collision_results['collision_rate_percent']:.4f}%")
   print(f"Status: {collision_results['status']}")

Comprehensive Testing
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import run_comprehensive_test
   
   # Run all tests
   print("Running comprehensive tests...")
   hasher = run_comprehensive_test()
   
   # Get statistics
   stats = hasher.get_stats()
   print(f"Total Hashes: {stats['hash_count']}")
   print(f"Average Time: {stats.get('avg_time_ms', 0):.2f}ms")
   print(f"KHA Success Rate: {stats.get('kha_success_rate', 0):.1f}%")

Common Use Cases
----------------

Password Storage
^^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import hash_password
   import secrets
   
   class PasswordManager:
       def __init__(self):
           self.storage = {}
       
       def add_user(self, username, password):
           """Add user with hashed password."""
           hashed = hash_password(password)
           self.storage[username] = hashed
           return hashed
       
       def verify_user(self, username, password):
           """Verify user password."""
           if username not in self.storage:
               return False
           
           stored = self.storage[username]
           return verify_password(stored, password)  # Use function from earlier
   
   # Usage
   pm = PasswordManager()
   pm.add_user("alice", "AlicePassword123")
   valid = pm.verify_user("alice", "AlicePassword123")  # True

Data Integrity Verification
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from kha256 import quick_hash
   
   class DataIntegrityChecker:
       def __init__(self):
           self.checksums = {}
       
       def add_data(self, data_id, data):
           """Add data with its hash."""
           data_hash = quick_hash(data)
           self.checksums[data_id] = data_hash
           return data_hash
       
       def verify_data(self, data_id, data):
           """Verify data integrity."""
           if data_id not in self.checksums:
               return False
           
           current_hash = quick_hash(data)
           return current_hash == self.checksums[data_id]
       
       def detect_tampering(self, data_id, data):
           """Check if data has been tampered with."""
           if data_id not in self.checksums:
               return True  # No record exists
           
           current_hash = quick_hash(data)
           original_hash = self.checksums[data_id]
           
           if current_hash != original_hash:
               # Calculate bit difference
               diff = bin(int(current_hash, 16) ^ int(original_hash, 16)).count('1')
               return diff
           return 0
   
   # Usage
   checker = DataIntegrityChecker()
   data = "Important configuration"
   hash_val = checker.add_data("config_v1", data)
   
   # Later verification
   is_valid = checker.verify_data("config_v1", data)  # True
   
   # Tampered data
   tampered = "Important configuratiox"  # One character changed
   tamper_score = checker.detect_tampering("config_v1", tampered)
   print(f"Tamper score: {tamper_score} bits changed")

Performance Benchmarking
------------------------

Simple Benchmark
^^^^^^^^^^^^^^^^

.. code-block:: python

   import time
   from kha256 import quick_hash
   
   def benchmark(size_kb=1, iterations=100):
       """Benchmark hashing performance."""
       data = b"x" * (size_kb * 1024
