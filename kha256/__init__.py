# -*- coding: utf-8 -*-
# __init__.py

"""
================================================================
KEÇECİ HASH ALGORITHM (KEÇECİ HASH ALGORİTMASI), KHA-256
Keçeci Hash Algorithm (Keçeci Hash Algoritması), KHA-256
================================================================
Performanstan fedakarlık edilerek güvenlik maksimize edilmiş versiyondur.
It is the version with security maximized at the sacrifice of performance.
================================================================
"""

from __future__ import annotations
import inspect
import importlib
import os
import warnings

# if os.getenv("DEVELOPMENT") == "true":
    # importlib.reload(kha256) # F821 undefined name 'kha256'

# Paket sürüm numarası
__version__ = "0.2.1"
__author__ = "Mehmet Keçeci"
__license__ = "AGPL-3.0-or-later"
__copyright__ = "Copyright 2025-2026 Mehmet Keçeci"
__email__ = "mkececi@yaani.com"
__certificate__ = "KHA256-PA-2025-001"

# Public API exposed to users of the 'kha256' package.
# Dışa aktarılacak içerikleri belirle
__all__ = [
    # Ana sınıflar
    "ByteDistributionOptimizer",
    "FortifiedConfig",
    "FortifiedKhaCore",
    "FortifiedKhaHash256",
    "HKDF",
    "HardwareSecurityID",
    "HardwareSecurityID2",
    "KHAcache",
    "MathematicalSecurityBases",
    "MemoryHardConfig",
    "MockCore",
    "OptimizedFortifiedConfig",
    "OptimizedKhaHash256",
    "PerformanceOptimizedKhaCore",
    "SecureKhaHash256",
    "secure_hash_password",
    "SecurityConstants",
    "SecurityLayers",
    "TrueMemoryHardConfig",
    "TrueMemoryHardHasher",
    "HybridKhaHash256",
    "SimpleKhaHasher",
    "Shake256Hasher",
    "shake256_hash",
    "shake256_128",
    "shake256_256",
    "shake256_512",
    "test_shake256",
    "ultra_fast_hash",
    "ultra_fast_hash_hex",
    "ultra_fast_hash_int_to_hex",
    "show_rate_limiter_info",
    "run_cli_demo",
    "RateLimiterDemoUI",
    "SecureLoginSystem",
    "MockAuthSystem",
    "SimpleRateLimiter",
    "MemoryHardDemo",
    "db",
    "performance_comparison",
    "economic_analysis",
    "secure_password_hashing",
]

# ============================================================
# MODÜL İÇE AKTARMALARI
# ============================================================
from .kha256 import (
    ByteDistributionOptimizer,
    FortifiedConfig,
    FortifiedKhaCore,
    FortifiedKhaHash256,
    HKDF,
    HardwareSecurityID,
    HardwareSecurityID2,
    KHAcache,
    MathematicalSecurityBases,
    MemoryHardConfig,
    MockCore,
    OptimizedFortifiedConfig,
    OptimizedKhaHash256,
    PerformanceOptimizedKhaCore,
    SecureKhaHash256,
    SecurityConstants,
    SecurityLayers,
    TrueMemoryHardConfig,
    TrueMemoryHardHasher,
    Colors,
    _balloon_expand,
    _balloon_mix,
    _memory_hard_fill,
    #_quantum_avalanche_mix,
    _sequential_memory_fill,
    _true_memory_hard_fill,
    _validate_blake2_params,
    batch_hash_secure,
    batch_hash_xxh64,
    benchmark_real_cost,
    chacha_avalanche_mix,
    debug_configs,
    diagnose_memory_hardness,
    djb2_optimized,
    expose_kha256_bug,
    fast_hash_int,
    fastest_cache_key,
    fnv1a_64,
    generate_compact_hwid,
    generate_fortified_hasher,
    generate_fortified_hasher_fast,
    generate_fortified_hasher_password,
    generate_fortified_hasher_secure,
    generate_hwid,
    generate_secure_hwid,
    get_hasher_config,
    getcontext,
    gpu_resistance_test,
    hash_argon2id,
    hash_bcrypt,
    hash_password,
    hash_password_str,
    hash_pbkdf2,
    hwid_hash,
    hwid_hash_cached,
    lru_cache,
    measure_hash,
    measure_time,
    min_entropy_test,
    print_results_table,
    quick_hash,
    quick_hash_128,
    quick_hash_blake3,
    quick_hash_cached,
    quick_hash_raw,
    quick_hash_sha256,
    run_comprehensive_test,
    secure_avalanche_mix,
    secure_hash_password,
    test_fortified_hashers,
    test_memory_hardness,
    test_parameter_impact,
    ultra_fast_hash,
    ultra_fast_hash_hex,
    ultra_fast_hash_int_to_hex,
    verify_password,
    xxh64_hash,
    HybridKhaHash256,
    SimpleKhaHasher,
    Shake256Hasher,
    shake256_hash,
    shake256_128,
    shake256_256,
    shake256_512,
    test_shake256,
    show_rate_limiter_info,
    run_cli_demo,
    RateLimiterDemoUI,
    SecureLoginSystem,
    MockAuthSystem,
    SimpleRateLimiter,
    MemoryHardDemo,
    db,
    performance_comparison,
    economic_analysis,
    secure_password_hashing,
    print_header,
    print_subheader,
    print_success,
    print_error,
    print_warning,
    print_info,
    safe_hash_password,
    safe_quick_hash,
    calculate_bit_difference,
    cal_bit_difference,
    test_basic_functionality,
    test_performance_scenarios,
    test_security_scenarios,
    test_real_world_scenarios,
    test_edge_cases,
    run_comprehensive_test_suite,
    fixed_gfh_password,
    test_memory_hard_real,
    test_true_memory_hard_direct,
    test_fortified_memory_hard,
    test_fortified_memory_hard_fixed,
    test_fortified_memory_hard2,
    test_true_memory_hard,
    test_memory_hard_engine,
    test_memory_hard_hash,
    Kha256SecureStorage,
    avalanche_test,
    detailed_avalanche_test,
    plot_avalanche_distribution,
    comprehensive_avalanche_test,
    safe_heatmap_plot,
    KHA256UnicodeHasher,
    gizli_turkce_hash,
    test_avalanche,
    test_streaming,
    test_hmac,
    StreamingKHA256,
    KHA256,
    CoreHash,
    MemoryHardHash,
    DeterministicHash,
    KHAUtils,
    TransformFunctions,
    KHA256Utils,
    DeterministicEngine,
    MemoryHardEngine,
    CoreEngine,
    KHA256b,
    cig_test,
    test2_hmac,
    test2_avalanche,
    test2_streaming,
    test_kha256b,
    test_kha256_main,
    test_deterministic_hash,
    test_core_hash,
    test_khautils,
    simple_hmac,
    secure_compare,
    int_to_bytes,
    bytes_to_int,
    xor_bytes,
    Colors,
    print_header,
    print_subheader,
    print_success,
    print_error,
    print_warning,
    print_info,

    # Sabitler ve durum değişkenleri
    KHA_AVAILABLE,
    WORKING_TYPES,
    TYPE_NAMES,
    
    # Versiyon bilgisi
    __version__,
    __author__,
    __license__,
    __certificate__,
)

# Eski bir fonksiyonun yer tutucusu - gelecekte kaldırılacak
def eski_fonksiyon():
    """
    Kaldırılması planlanan eski bir fonksiyondur.
    Lütfen alternatif fonksiyonları kullanın.
    """
    warnings.warn(
        "eski_fonksiyon() artık kullanılmamaktadır ve gelecekte kaldırılacaktır. "
        "Lütfen yeni alternatif fonksiyonları kullanın. "
        "KHA-256; Python 3.11-3.15 sürümlerinde sorunsuz çalışmalıdır.",
        category=DeprecationWarning,
        stacklevel=2
    )
