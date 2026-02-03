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
__version__ = "0.1.4"
__author__ = "Mehmet Keçeci"
__license__ = "AGPL-3.0"
__copyright__ = "Copyright 2025 Mehmet Keçeci"
__email__ = "mkececi@yaani.com"

# Public API exposed to users of the 'kha256' package.
__all__ = [
    # Ana sınıflar
    "FortifiedKhaHash256",
    "FortifiedConfig",
    "FortifiedKhaCore",
    "OptimizedKhaHash256",
    "OptimizedFortifiedConfig",
    
    # Kolay kullanım fonksiyonları
    "generate_fortified_hasher",
    "quick_hash",
    "hash_password",
    "PerformanceOptimizedKhaCore",
    "ByteDistributionOptimizer",
    "get_hasher_config",
    
    # Test fonksiyonları
    #"run_comprehensive_security_test",
    "run_comprehensive_test",
    #"benchmark_hash",
    
    # Yardımcı sınıflar
    "MathematicalSecurityBases",
    "SecurityConstants",
    "SecurityLayers",
    
    # Sabitler
    "KHA_AVAILABLE",
    "WORKING_TYPES",
    "TYPE_NAMES",
    
    # Versiyon bilgisi
    "__version__",
    "__author__",
    "__license__",
]

# ============================================================
# MODÜL İÇE AKTARMALARI
# ============================================================
from .kha256 import *
try:
    
    # Temel modül
    from .kha256 import (
        # Ana sınıflar
        FortifiedKhaHash256,
        FortifiedConfig,
        FortifiedKhaCore,
        OptimizedKhaHash256,
        OptimizedFortifiedConfig,
        HardwareSecurityID,
        
        # Yardımcı sınıflar
        MathematicalSecurityBases,
        SecurityConstants,
        SecurityLayers,
        
        # Kolay kullanım fonksiyonları
        generate_fortified_hasher,
        quick_hash,
        hash_password,
        PerformanceOptimizedKhaCore,
        ByteDistributionOptimizer,
        get_hasher_config,
        
        # Test fonksiyonları
        run_comprehensive_test,
        #benchmark_hash,
        
        # Sabitler ve durum değişkenleri
        KHA_AVAILABLE,
        WORKING_TYPES,
        TYPE_NAMES,
        
        # Versiyon bilgisi
        __version__,
        __author__,
        __license__,
    )

except ImportError as e:
    warnings.warn(f"Gerekli modül yüklenemedi: {e}", ImportWarning)

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
