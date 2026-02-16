"""KHA-256 (Keçeci Hash Algorithm) - A cryptographic hash algorithm.

================================================================
KEÇECİ HASH ALGORITHM (KEÇECİ HASH ALGORİTMASI), KHA-256
================================================================
Security-maximized version with performance trade-offs for maximum security.
Performanstan fedakarlık edilerek güvenlik maksimize edilmiş versiyondur.
================================================================
"""

from __future__ import annotations

__version__ = "0.2.4"
__author__ = "Mehmet Keçeci"
__license__ = "AGPL-3.0-or-later"
__copyright__ = "Copyright 2025-2026 Mehmet Keçeci"
__email__ = "mkececi@yaani.com"
__certificate__ = "KHA256-PA-2025-001"

import warnings
from typing import List, Optional, Union, Any, Dict, Tuple, Callable

# ======================================================================
# PUBLIC API - Core classes and functions exposed to package users
# ======================================================================

# Main hash classes and engines
from .kha256 import (
    KHA256,
    KHA256b,
    FortifiedKhaHash256,
    OptimizedKhaHash256,
    SecureKhaHash256,
    HybridKhaHash256,
    SimpleKhaHasher,
    Shake256Hasher,
    TrueMemoryHardHasher,
)

# Core engines and configurations
from .kha256 import (
    CoreEngine,
    CoreHash,
    DeterministicEngine,
    DeterministicHash,
    MemoryHardEngine,
    MemoryHardHash,
    FortifiedKhaCore,
    PerformanceOptimizedKhaCore,
    MockCore,
    StreamingKHA256,
)

# Security and configuration classes
from .kha256 import (
    FortifiedConfig,
    OptimizedFortifiedConfig,
    MemoryHardConfig,
    TrueMemoryHardConfig,
    SecurityConstants,
    SecurityLayers,
    MathematicalSecurityBases,
    ByteDistributionOptimizer,
    TransformFunctions,
)

# Hardware security and identification
from .kha256 import (
    HardwareSecurityID,
    HardwareSecurityID2,
    KHAcache,
    KHA256Utils,
    KHAUtils,
    Kha256SecureStorage,
    KHA256UnicodeHasher,
)

# Rate limiting and authentication systems
from .kha256 import (
    SimpleRateLimiter,
    RateLimiterDemoUI,
    SecureLoginSystem,
    MockAuthSystem,
    MemoryHardDemo,
)

# Utility functions - Hashing and passwords
from .kha256 import (
    secure_hash_password,
    safe_hash_password,
    hash_password,
    hash_password_str,
    verify_password,
    batch_hash_secure,
    batch_hash_xxh64,
    quick_hash,
    quick_hash_raw,
    quick_hash_sha256,
    quick_hash_blake3,
    quick_hash_128,
    safe_quick_hash,
    quick_hash_cached,
    ultra_fast_hash,
    ultra_fast_hash_hex,
    ultra_fast_hash_int_to_hex,
    fast_hash_int,
    fastest_cache_key,
    xxh64_hash,
    fnv1a_64,
    djb2_optimized,
)

# Hash functions
from .kha256 import (
    shake256_hash,
    shake256_128,
    shake256_256,
    shake256_512,
    gizli_turkce_hash,
    fixed_gfh_password,
    hash_argon2id,
    hash_bcrypt,
    hash_pbkdf2,
    hwid_hash,
    hwid_hash_cached,
    generate_hwid,
    generate_compact_hwid,
    generate_secure_hwid,
    simple_hmac,
)

# Testing and benchmarking functions
from .kha256 import (
    run_all_tests,
    run_cli_demo,
    run_comprehensive_test,
    run_comprehensive_test_suite,
    performance_comparison,
    economic_analysis,
    secure_password_hashing,
    show_rate_limiter_info,
    MemoryHardDemo,
    db,
    test_shake256,
    test_kha256_main,
    test_kha256b,
    test_khautils,
    test_basic_functionality,
    test_core_hash,
    test_deterministic_hash,
    test_memory_hard_engine,
    test_memory_hard_hash,
    test_memory_hard_real,
    test_memory_hardness,
    test_true_memory_hard,
    test_true_memory_hard_direct,
    test_fortified_hashers,
    test_fortified_memory_hard,
    test_fortified_memory_hard2,
    test_fortified_memory_hard_fixed,
    test_hmac,
    test2_hmac,
    test_streaming,
    test2_streaming,
    test_avalanche,
    test2_avalanche,
    test_edge_cases,
    test_parameter_impact,
    test_performance_scenarios,
    test_real_world_scenarios,
    test_security_scenarios,
    avalanche_test,
    comprehensive_avalanche_test,
    detailed_avalanche_test,
    cig_test,
    gpu_resistance_test,
    min_entropy_test,
    diagnose_memory_hardness,
    benchmark_real_cost,
    plot_avalanche_distribution,
    safe_heatmap_plot,
    plot_avalanche_simple,
)

# Utility functions
from .kha256 import (
    HKDF,
    secure_compare,
    xor_bytes,
    bytes_to_int,
    int_to_bytes,
    cal_bit_difference,
    calculate_bit_difference,
    chacha_avalanche_mix,
    secure_avalanche_mix,
    _balloon_expand,
    _balloon_mix,
    _memory_hard_fill,
    _sequential_memory_fill,
    _true_memory_hard_fill,
    _validate_blake2_params,
    expose_kha256_bug,
    generate_fortified_hasher,
    generate_fortified_hasher_fast,
    generate_fortified_hasher_secure,
    generate_fortified_hasher_password,
    get_hasher_config,
    measure_hash,
    measure_time,
    debug_configs,
    getcontext,
    lru_cache,
    print_error,
    print_header,
    print_info,
    print_results_table,
    print_subheader,
    print_success,
    print_warning,
    kha_rastgele_sayi,
    rastgele_sayi,
    kha256_fortified_random,
    kha256_password_random,
    kha256_memory_hard_random,
    kha256_hard_random,
    true_memory_hard_random,
    memory_hard_hash_random,
    memory_hard_engine_random,
    fortified_kha_random,
    kha256b_random,
    scrypt_random,
    gscrypt_random,
    bscrypt_random,
    scrypt_dual_output,
    is_jupyter,
    silent_kn,
)

# Constants
from .kha256 import (
    KHA_AVAILABLE,
    TYPE_NAMES,
    WORKING_TYPES,
    Colors,
)

# Re-export version information
from .kha256 import __version__, __author__, __license__, __certificate__

# ======================================================================
# PUBLIC API EXPORTS - Everything listed here is part of the public API
# ======================================================================

__all__: List[str] = [
    # Version information
    "__version__",
    "__author__",
    "__license__",
    "__copyright__",
    "__email__",
    "__certificate__",
    
    # Main hash classes
    "KHA256",
    "KHA256b",
    "FortifiedKhaHash256",
    "OptimizedKhaHash256",
    "SecureKhaHash256",
    "HybridKhaHash256",
    "SimpleKhaHasher",
    "Shake256Hasher",
    "TrueMemoryHardHasher",
    
    # Core engines
    "CoreEngine",
    "CoreHash",
    "DeterministicEngine",
    "DeterministicHash",
    "MemoryHardEngine",
    "MemoryHardHash",
    "FortifiedKhaCore",
    "PerformanceOptimizedKhaCore",
    "MockCore",
    "StreamingKHA256",
    
    # Configuration classes
    "FortifiedConfig",
    "OptimizedFortifiedConfig",
    "MemoryHardConfig",
    "TrueMemoryHardConfig",
    "SecurityConstants",
    "SecurityLayers",
    "MathematicalSecurityBases",
    "ByteDistributionOptimizer",
    "TransformFunctions",
    
    # Hardware security
    "HardwareSecurityID",
    "HardwareSecurityID2",
    "KHAcache",
    "KHA256Utils",
    "KHAUtils",
    "Kha256SecureStorage",
    "KHA256UnicodeHasher",
    
    # Rate limiting and authentication
    "SimpleRateLimiter",
    "RateLimiterDemoUI",
    "SecureLoginSystem",
    "MockAuthSystem",
    "MemoryHardDemo",
    
    # Password hashing functions
    "secure_hash_password",
    "safe_hash_password",
    "hash_password",
    "hash_password_str",
    "verify_password",
    "batch_hash_secure",
    "batch_hash_xxh64",
    
    # Quick hash functions
    "quick_hash",
    "quick_hash_raw",
    "quick_hash_sha256",
    "quick_hash_blake3",
    "quick_hash_128",
    "safe_quick_hash",
    "quick_hash_cached",
    "ultra_fast_hash",
    "ultra_fast_hash_hex",
    "ultra_fast_hash_int_to_hex",
    "fast_hash_int",
    "fastest_cache_key",
    
    # Non-cryptographic hash functions
    "xxh64_hash",
    "fnv1a_64",
    "djb2_optimized",
    
    # Hash function variants
    "shake256_hash",
    "shake256_128",
    "shake256_256",
    "shake256_512",
    "gizli_turkce_hash",
    "fixed_gfh_password",
    "hash_argon2id",
    "hash_bcrypt",
    "hash_pbkdf2",
    "hwid_hash",
    "hwid_hash_cached",
    "generate_hwid",
    "generate_compact_hwid",
    "generate_secure_hwid",
    "simple_hmac",
    
    # Testing and demonstration
    "run_all_tests",
    "run_cli_demo",
    "run_comprehensive_test",
    "run_comprehensive_test_suite",
    "performance_comparison",
    "economic_analysis",
    "secure_password_hashing",
    "show_rate_limiter_info",
    "db",
    
    # Test functions
    "test_shake256",
    "test_kha256_main",
    "test_kha256b",
    "test_khautils",
    "test_basic_functionality",
    "test_core_hash",
    "test_deterministic_hash",
    "test_memory_hard_engine",
    "test_memory_hard_hash",
    "test_memory_hard_real",
    "test_memory_hardness",
    "test_true_memory_hard",
    "test_true_memory_hard_direct",
    "test_fortified_hashers",
    "test_fortified_memory_hard",
    "test_fortified_memory_hard2",
    "test_fortified_memory_hard_fixed",
    "test_hmac",
    "test2_hmac",
    "test_streaming",
    "test2_streaming",
    "test_avalanche",
    "test2_avalanche",
    "test_edge_cases",
    "test_parameter_impact",
    "test_performance_scenarios",
    "test_real_world_scenarios",
    "test_security_scenarios",
    
    # Security testing functions
    "avalanche_test",
    "comprehensive_avalanche_test",
    "detailed_avalanche_test",
    "cig_test",
    "gpu_resistance_test",
    "min_entropy_test",
    "diagnose_memory_hardness",
    "benchmark_real_cost",
    
    # Visualization
    "plot_avalanche_distribution",
    "safe_heatmap_plot",
    "plot_avalanche_simple",
    
    # Utility functions
    "HKDF",
    "secure_compare",
    "xor_bytes",
    "bytes_to_int",
    "int_to_bytes",
    "cal_bit_difference",
    "calculate_bit_difference",
    "chacha_avalanche_mix",
    "secure_avalanche_mix",
    "kha_rastgele_sayi",
    "rastgele_sayi",
    "kha256_fortified_random",
    "kha256_password_random",
    "kha256_memory_hard_random",
    "kha256_hard_random",
    "true_memory_hard_random",
    "memory_hard_hash_random",
    "memory_hard_engine_random",
    "fortified_kha_random",
    "kha256b_random",
    "scrypt_random",
    "gscrypt_random",
    "bscrypt_random",
    "scrypt_dual_output",
    
    # Internal functions (exposed for advanced use)
    "_balloon_expand",
    "_balloon_mix",
    "_memory_hard_fill",
    "_sequential_memory_fill",
    "_true_memory_hard_fill",
    "_validate_blake2_params",
    
    # Debug and introspection
    "expose_kha256_bug",
    "generate_fortified_hasher",
    "generate_fortified_hasher_fast",
    "generate_fortified_hasher_secure",
    "generate_fortified_hasher_password",
    "get_hasher_config",
    "measure_hash",
    "measure_time",
    "debug_configs",
    "getcontext",
    "lru_cache",
    
    # Constants
    "KHA_AVAILABLE",
    "TYPE_NAMES",
    "WORKING_TYPES",
    "Colors",
    
    # Print utilities
    "print_error",
    "print_header",
    "print_info",
    "print_results_table",
    "print_subheader",
    "print_success",
    "print_warning",
]

# ======================================================================
# DEPRECATED FUNCTIONS - Will be removed in future versions
# ======================================================================

def legacy_function() -> None:
    """Legacy function scheduled for removal.
    
    This function is deprecated and will be removed in a future version.
    Please use alternative functions from the public API.
    
    KHA-256 is compatible with Python 3.11-3.15.
    
    Raises:
        DeprecationWarning: Always raised when this function is called.
    """
    warnings.warn(
        "legacy_function() is deprecated and will be removed in a future version. "
        "Please use the alternative functions provided in the public API. "
        "KHA-256 is compatible with Python 3.11-3.15.",
        category=DeprecationWarning,
        stacklevel=2,
    )

# Add legacy_function to __all__ for backward compatibility
__all__.append("legacy_function")
