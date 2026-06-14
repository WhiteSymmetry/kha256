# -*- coding: utf-8 -*-
# __init__.py

"""
===============================
KHA-256 (Keçeci Hash Algorithm)
===============================
KEÇECİ HASH ALGORITHM (KEÇECİ HASH ALGORİTMASI), KHA-256
- A cryptographic hash algorithm.

Security-maximized version with performance trade-offs for maximum security.
Performanstan fedakarlık edilerek güvenlik maksimize edilmiş versiyondur.

A next-generation cryptographic hash algorithm based on Keçeci Numbers 
and mathematical constants.

:author: Mehmet Keçeci
:license: AGPL-3.0-or-later
:copyright: Copyright 2025-2026 Mehmet Keçeci
"""

from __future__ import annotations

import logging
import warnings
import functools
from typing import TYPE_CHECKING, Any, Callable, List

# ======================================================================
# METADATA & VERSIONING (Modern Approach)
# ======================================================================

# Try to read metadata from the installed package (pyproject.toml / setup.py)
try:
    from importlib.metadata import version as _pkg_version, metadata as _pkg_metadata
    
    __version__ = _pkg_version("kha256")
    _meta = _pkg_metadata("kha256")
    __author__ = _meta.get("Author-email", "Mehmet Keçeci <mkececi@yaani.com>")
    __license__ = _meta.get("License", "AGPL-3.0-or-later")
except Exception:
    # Fallback for development or if metadata is not available
    __version__ = "0.3.4"
    __author__ = "Mehmet Keçeci"
    __license__ = "AGPL-3.0-or-later"

__copyright__ = "Copyright 2025-2026 Mehmet Keçeci"
__email__ = "mkececi@yaani.com"
__certificate__ = "KHA256-PA-2025-001"

_log = logging.getLogger(__name__)

# BibTeX citation for academic use
__bibtex__ = r"""@misc{kececi_2026_18156885,
  author       = {Keçeci, Mehmet},
  title        = {KHA-256: A Next-Generation Cryptographic Hash
                   Function Based on Keçeci Numbers and Mathematical
                   Constants},
  journal      = {Open Science Articles (OSAs)},
  month        = jan,
  year         = 2026,
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.18156885},
  url          = {https://doi.org/10.5281/zenodo.18156885},
  pages        = {30},
  volume       = {2},
  number       = {1},
  abstract     = {KHA-256 (Keçeci Hash Algorithm-256) is a novel 
  cryptographic hash function that departs from conventional 
  bit-level constructions by leveraging mathematical constants 
  (e.g., π, e, φ) and the multidimensional algebraic structures 
  of Keçeci Numbers—encompassing real, complex, quaternion, 
  octonion, and neutrosophic representations.}
}"""

# ======================================================================
# TYPE CHECKING (Only for IDEs and type checkers like mypy)
# ======================================================================
if TYPE_CHECKING:
    from typing import Literal
    LogLevel = int | str 

# ======================================================================
# PUBLIC API IMPORTS
# ======================================================================

# Import everything from the core module in a single, organized block
from .kha256 import (
    # Main hash classes and engines
    KHA256, KHA256b, FortifiedKhaHash256, OptimizedKhaHash256,
    SecureKhaHash256, HybridKhaHash256, SimpleKhaHasher, Shake256Hasher,
    TrueMemoryHardHasher,
    
    # Core engines and configurations
    CoreEngine, CoreHash, DeterministicEngine, DeterministicHash,
    MemoryHardEngine, MemoryHardHash, FortifiedKhaCore,
    PerformanceOptimizedKhaCore, MockCore, StreamingKHA256,
    
    # Security and configuration classes
    FortifiedConfig, OptimizedFortifiedConfig, MemoryHardConfig,
    TrueMemoryHardConfig, SecurityConstants, SecurityLayers,
    MathematicalSecurityBases, ByteDistributionOptimizer, TransformFunctions,
    
    # Hardware security and identification
    HardwareSecurityID, HardwareSecurityID2, KHAcache, KHA256Utils, KHAUtils,
    Kha256SecureStorage, KHA256UnicodeHasher,
    
    # Rate limiting and authentication systems
    SimpleRateLimiter, RateLimiterDemoUI, SecureLoginSystem, MockAuthSystem,
    MemoryHardDemo,
    
    # Utility functions - Hashing and passwords
    secure_hash_password, safe_hash_password, hash_password, hash_password_str,
    verify_password, batch_hash_secure, batch_hash_xxh64, quick_hash,
    quick_hash_raw, quick_hash_sha256, quick_hash_blake3, quick_hash_128,
    safe_quick_hash, quick_hash_cached, ultra_fast_hash, ultra_fast_hash_hex,
    ultra_fast_hash_int_to_hex, fast_hash_int, fastest_cache_key, xxh64_hash,
    fnv1a_64, djb2_optimized,
    
    # Hash functions
    shake256_hash, shake256_128, shake256_256, shake256_512, gizli_turkce_hash,
    fixed_gfh_password, hash_argon2id, hash_bcrypt, hash_pbkdf2, hwid_hash,
    hwid_hash_cached, generate_hwid, generate_compact_hwid, generate_secure_hwid,
    simple_hmac, image_signature,
    
    # Testing and benchmarking functions
    run_all_tests, run_cli_demo, run_comprehensive_test,
    run_comprehensive_test_suite, performance_comparison, economic_analysis,
    secure_password_hashing, show_rate_limiter_info, db, test_shake256,
    test_kha256_main, test_kha256b, test_khautils, test_basic_functionality,
    test_core_hash, test_deterministic_hash, test_memory_hard_engine,
    test_memory_hard_hash, test_memory_hard_real, test_memory_hardness,
    test_true_memory_hard, test_true_memory_hard_direct, test_fortified_hashers,
    test_fortified_memory_hard, test_fortified_memory_hard2,
    test_fortified_memory_hard_fixed, test_hmac, test2_hmac, test_streaming,
    test2_streaming, test_avalanche, test2_avalanche, test_edge_cases,
    test_parameter_impact, test_performance_scenarios, test_real_world_scenarios,
    test_security_scenarios, avalanche_test, comprehensive_avalanche_test,
    detailed_avalanche_test, cig_test, gpu_resistance_test, min_entropy_test,
    diagnose_memory_hardness, benchmark_real_cost, plot_avalanche_distribution,
    safe_heatmap_plot, plot_avalanche_simple,
    
    # Utility functions
    HKDF, secure_compare, xor_bytes, bytes_to_int, int_to_bytes,
    cal_bit_difference, calculate_bit_difference, chacha_avalanche_mix,
    secure_avalanche_mix, _balloon_expand, _balloon_mix, _memory_hard_fill,
    _sequential_memory_fill, _true_memory_hard_fill, _validate_blake2_params,
    expose_kha256_bug, generate_fortified_hasher, generate_fortified_hasher_fast,
    generate_fortified_hasher_secure, generate_fortified_hasher_password,
    get_hasher_config, measure_hash, measure_time, debug_configs, getcontext,
    lru_cache, print_error, print_header, print_info, print_results_table,
    print_subheader, print_success, print_warning, kha_rastgele_sayi,
    rastgele_sayi, kha256_fortified_random, kha256_password_random,
    kha256_memory_hard_random, kha256_hard_random, true_memory_hard_random,
    memory_hard_hash_random, memory_hard_engine_random, fortified_kha_random,
    kha256b_random, scrypt_random, gscrypt_random, bscrypt_random,
    scrypt_dual_output, is_jupyter, silent_kn,
    
    # Constants
    KHA_AVAILABLE, TYPE_NAMES, WORKING_TYPES, Colors,
)

# ======================================================================
# DYNAMIC __all__ GENERATION
# ======================================================================

# Automatically generate __all__ to include all public API imports.
# This avoids manual maintenance of a huge list and prevents errors.
__all__ = [
    name for name in globals()
    if not name.startswith('_') 
    and name not in ('annotations', 'namedtuple', 'logging', 'warnings', 
                     'functools', 'TYPE_CHECKING', 'Any', 'List', 'Callable')
    and isinstance(globals()[name], (type, type(lambda: None), int, str, float, dict, list, tuple, set))
]

# Ensure metadata is explicitly included in __all__
__all__.extend([
    "__version__", "__author__", "__license__", "__copyright__", 
    "__email__", "__certificate__", "__bibtex__"
])

# ======================================================================
# DEPRECATION UTILITIES
# ======================================================================

def deprecated(reason: str) -> Callable:
    """Decorator to mark functions as deprecated."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            warnings.warn(
                f"{func.__name__}() is deprecated and will be removed in a future version. {reason}",
                category=DeprecationWarning,
                stacklevel=2,
            )
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ======================================================================
# DEPRECATED FUNCTIONS
# ======================================================================

@deprecated("Please use the alternative functions provided in the public API. KHA-256 is compatible with Python 3.11-3.15.")
def legacy_function() -> None:
    """Legacy function scheduled for removal."""
    pass

__all__.append("legacy_function")
