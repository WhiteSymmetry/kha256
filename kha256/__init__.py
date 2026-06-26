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

import functools
import logging
import warnings
from typing import TYPE_CHECKING, Any, Callable, List

# ======================================================================
# METADATA & VERSIONING (Modern Approach)
# ======================================================================
# Try to read metadata from the installed package (pyproject.toml / setup.py)
"""
Standalone version info – no package imports, so circular imports are avoided.
"""
try:
    from importlib.metadata import version as _pkg_version
    from importlib.metadata import metadata as _pkg_metadata

    __version__ = _pkg_version("kha256")
    _meta = _pkg_metadata("kha256")

    # PackageMetadata does not have a .get() method, convert to dict
    _meta_dict = dict(_meta.items())
    __author__ = _meta_dict.get("Author-email", "Mehmet Keçeci <mkececi@yaani.com>")
    __license__ = _meta_dict.get("License", "AGPL-3.0-or-later")

except Exception:
    # Fallback for development or missing metadata
    __version__ = "0.4.1"
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


from .kha256 import (  # Main hash classes and engines; Core engines and configurations; Security and configuration classes; Hardware security and identification; Rate limiting and authentication systems; Utility functions - Hashing and passwords; Hash functions; Testing and benchmarking functions; Utility functions; Constants; quantum
    ANUQRNG,
    HKDF,
    KHA256,
    KHA_AVAILABLE,
    LFDQRNG,
    QCIQRNG,
    QRANDOMQRNG,
    TYPE_NAMES,
    WORKING_TYPES,
    ANULegacyQRNG,
    ANUTokenQRNG,
    BaseQRNG,
    ByteDistributionOptimizer,
    Colors,
    CoreEngine,
    CoreHash,
    DeterministicEngine,
    DeterministicHash,
    FortifiedConfig,
    FortifiedKhaCore,
    FortifiedKhaHash256,
    HardwareSecurityID,
    HardwareSecurityID2,
    HybridKhaHash256,
    HybridQRNGManager,
    KHA256b,
    Kha256SecureStorage,
    KHA256UnicodeHasher,
    KHA256Utils,
    KHAcache,
    KHAUtils,
    MathematicalSecurityBases,
    MemoryHardConfig,
    MemoryHardDemo,
    MemoryHardEngine,
    MemoryHardHash,
    MockAuthSystem,
    MockCore,
    OptimizedFortifiedConfig,
    OptimizedKhaHash256,
    OutshiftQRNG,
    PerformanceOptimizedKhaCore,
    QRNGConfig,
    RateLimiterDemoUI,
    SecureKhaHash256,
    SecureLoginSystem,
    SecurityConstants,
    SecurityLayers,
    Shake256Hasher,
    SimpleKhaHasher,
    SimpleRateLimiter,
    StreamingKHA256,
    TransformFunctions,
    TrueMemoryHardConfig,
    TrueMemoryHardHasher,
    _balloon_expand,
    _balloon_mix,
    _fallback_bytes,
    _memory_hard_fill,
    _qrng_manager,
    _sequential_memory_fill,
    _true_memory_hard_fill,
    _validate_blake2_params,
    avalanche_test,
    batch_hash_secure,
    batch_hash_xxh64,
    benchmark_real_cost,
    bscrypt_random,
    bytes_to_int,
    cal_bit_difference,
    calculate_bit_difference,
    chacha_avalanche_mix,
    cig_test,
    comprehensive_avalanche_test,
    db,
    debug_anu_apis,
    debug_configs,
    detailed_avalanche_test,
    diagnose_memory_hardness,
    diagnose_quantum_apis,
    djb2_optimized,
    economic_analysis,
    expose_kha256_bug,
    fast_hash_int,
    fastest_cache_key,
    fixed_gfh_password,
    fnv1a_64,
    fortified_kha_random,
    generate_compact_hwid,
    generate_fortified_hasher,
    generate_fortified_hasher_fast,
    generate_fortified_hasher_password,
    generate_fortified_hasher_secure,
    generate_hwid,
    generate_secure_hwid,
    get_api_status,
    get_hasher_config,
    get_mquantum_bytes,
    get_quantum_bytes,
    get_quantum_stats,
    getcontext,
    gizli_turkce_hash,
    gpu_resistance_test,
    gscrypt_random,
    hash_argon2id,
    hash_bcrypt,
    hash_password,
    hash_password_str,
    hash_pbkdf2,
    hwid_hash,
    hwid_hash_cached,
    image_signature,
    int_to_bytes,
    is_jupyter,
    kha256_fortified_random,
    kha256_hard_random,
    kha256_memory_hard_random,
    kha256_password_random,
    kha256b_random,
    kha_rastgele_sayi,
    lru_cache,
    measure_hash,
    measure_time,
    memory_hard_engine_random,
    memory_hard_hash_random,
    min_entropy_test,
    mqKHA256,
    performance_comparison,
    plot_avalanche_distribution,
    plot_avalanche_simple,
    print_error,
    print_header,
    print_info,
    print_results_table,
    print_subheader,
    print_success,
    print_warning,
    qKHA256,
    quick_hash,
    quick_hash_128,
    quick_hash_blake3,
    quick_hash_cached,
    quick_hash_raw,
    quick_hash_sha256,
    rastgele_sayi,
    run_all_tests,
    run_cli_demo,
    run_comprehensive_test,
    run_comprehensive_test_suite,
    safe_hash_password,
    safe_heatmap_plot,
    safe_quick_hash,
    scrypt_dual_output,
    scrypt_random,
    secure_avalanche_mix,
    secure_compare,
    secure_hash_password,
    secure_password_hashing,
    shake256_128,
    shake256_256,
    shake256_512,
    shake256_hash,
    show_rate_limiter_info,
    silent_kn,
    simple_hmac,
    test2_avalanche,
    test2_hmac,
    test2_streaming,
    test_all_quantum_apis,
    test_avalanche,
    test_basic_functionality,
    test_core_hash,
    test_deterministic_hash,
    test_edge_cases,
    test_fortified_hashers,
    test_fortified_memory_hard,
    test_fortified_memory_hard2,
    test_fortified_memory_hard_fixed,
    test_hmac,
    test_kha256_main,
    test_kha256b,
    test_khautils,
    test_memory_hard_engine,
    test_memory_hard_hash,
    test_memory_hard_real,
    test_memory_hardness,
    test_parameter_impact,
    test_performance_scenarios,
    test_quantum_quality,
    test_real_world_scenarios,
    test_security_scenarios,
    test_shake256,
    test_streaming,
    test_true_memory_hard,
    test_true_memory_hard_direct,
    true_memory_hard_random,
    ultra_fast_hash,
    ultra_fast_hash_hex,
    ultra_fast_hash_int_to_hex,
    verify_password,
    xor_bytes,
    xxh64_hash,
)

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

# ======================================================================
# DYNAMIC __all__ GENERATION
# ======================================================================

# Automatically generate __all__ to include all public API imports.
# This avoids manual maintenance of a huge list and prevents errors.
__all__ = [
    name
    for name in globals()
    if not name.startswith("_")
    and name
    not in (
        "annotations",
        "namedtuple",
        "logging",
        "warnings",
        "functools",
        "TYPE_CHECKING",
        "Any",
        "List",
        "Callable",
    )
    and isinstance(
        globals()[name],
        (type, type(lambda: None), int, str, float, dict, list, tuple, set),
    )
]

# Ensure metadata is explicitly included in __all__
__all__.extend(
    [
        "__version__",
        "__author__",
        "__license__",
        "__copyright__",
        "__email__",
        "__certificate__",
        "__bibtex__",
    ]
)

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


@deprecated(
    "Please use the alternative functions provided in the public API. KHA-256 is compatible with Python 3.11-3.15."
)
def legacy_function() -> None:
    """Legacy function scheduled for removal."""
    pass


__all__.append("legacy_function")
