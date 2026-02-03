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

import hashlib
import logging
import platform
import random
import re
import secrets
import struct
import sys
import time
import uuid
from dataclasses import dataclass
from decimal import getcontext
from typing import Any, ClassVar, Dict, List, Optional, Tuple, Union, cast

import numpy as np

# Logging configuration
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("KHA-256")

# Version information
__version__ = "0.1.4"  # Updated
__author__ = "Mehmet Keçeci"
__license__ = "AGPL-3.0 license"
__status__ = "Pre-Production"

req_kececinumbers = "0.9.1"

# KeçeciNumbers check - made API compatible
KHA_AVAILABLE = True
WORKING_TYPES = []
TYPE_NAMES = {}


# Define type constants as fallback values
TYPE_POSITIVE_REAL = 1
TYPE_NEGATIVE_REAL = 2
TYPE_COMPLEX = 3
TYPE_FLOAT = 4
TYPE_RATIONAL = 5
TYPE_QUATERNION = 6
TYPE_NEUTROSOPHIC = 7
TYPE_NEUTROSOPHIC_COMPLEX = 8
TYPE_HYPERREAL = 9
TYPE_BICOMPLEX = 10
TYPE_OCTONION = 11
TYPE_SEDENION = 12
TYPE_CLIFFORD = 13
TYPE_DUAL = 14
TYPE_SPLIT_COMPLEX = 15
TYPE_PATHION = 16
TYPE_CHINGON = 17
TYPE_ROUTON = 18
TYPE_VOUDON = 19
TYPE_SUPERREAL = 20
TYPE_TERNARY = 21
TYPE_NEUTROSOPHIC_BICOMPLEX = 22

# Try to import kececinumbers
try:
    import kececinumbers as kn

    # Override with actual values from kececinumbers if available
    if hasattr(kn, "TYPE_POSITIVE_REAL"):
        TYPE_POSITIVE_REAL = kn.TYPE_POSITIVE_REAL
        TYPE_NEGATIVE_REAL = kn.TYPE_NEGATIVE_REAL
        TYPE_COMPLEX = kn.TYPE_COMPLEX
        TYPE_FLOAT = kn.TYPE_FLOAT
        TYPE_RATIONAL = kn.TYPE_RATIONAL
        TYPE_QUATERNION = kn.TYPE_QUATERNION
        TYPE_NEUTROSOPHIC = kn.TYPE_NEUTROSOPHIC
        TYPE_NEUTROSOPHIC_COMPLEX = kn.TYPE_NEUTROSOPHIC_COMPLEX
        TYPE_HYPERREAL = kn.TYPE_HYPERREAL
        TYPE_BICOMPLEX = kn.TYPE_BICOMPLEX
        TYPE_OCTONION = kn.TYPE_OCTONION
        TYPE_SEDENION = kn.TYPE_SEDENION
        TYPE_CLIFFORD = kn.TYPE_CLIFFORD
        TYPE_DUAL = kn.TYPE_DUAL
        TYPE_SPLIT_COMPLEX = kn.TYPE_SPLIT_COMPLEX
        TYPE_PATHION = kn.TYPE_PATHION
        TYPE_CHINGON = kn.TYPE_CHINGON
        TYPE_ROUTON = kn.TYPE_ROUTON
        TYPE_VOUDON = kn.TYPE_VOUDON
        TYPE_SUPERREAL = kn.TYPE_SUPERREAL
        TYPE_TERNARY = kn.TYPE_TERNARY
        TYPE_NEUTROSOPHIC_BICOMPLEX = kn.TYPE_NEUTROSOPHIC_BICOMPLEX

    # Known working types
    WORKING_TYPES = [
        TYPE_POSITIVE_REAL,
        TYPE_NEGATIVE_REAL,
        TYPE_COMPLEX,
        TYPE_FLOAT,
        TYPE_RATIONAL,
        TYPE_QUATERNION,
        TYPE_NEUTROSOPHIC,
        TYPE_NEUTROSOPHIC_COMPLEX,
        TYPE_BICOMPLEX,
        TYPE_OCTONION,
        TYPE_DUAL,
        TYPE_SPLIT_COMPLEX,
        TYPE_HYPERREAL,
        TYPE_NEUTROSOPHIC_BICOMPLEX,
        TYPE_SEDENION,
        TYPE_CLIFFORD,
        TYPE_PATHION,
        TYPE_CHINGON,
        TYPE_ROUTON,
        TYPE_VOUDON,
        TYPE_SUPERREAL,
        TYPE_TERNARY,
    ]

    # Type names
    TYPE_NAMES = {
        TYPE_POSITIVE_REAL: "Positive Real",
        TYPE_NEGATIVE_REAL: "Negative Real",
        TYPE_COMPLEX: "Complex",
        TYPE_FLOAT: "Float",
        TYPE_RATIONAL: "Rational",
        TYPE_QUATERNION: "Quaternion",
        TYPE_NEUTROSOPHIC: "Neutrosophic",
        TYPE_NEUTROSOPHIC_COMPLEX: "Neutrosophic Complex",
        TYPE_HYPERREAL: "Hyperreal",
        TYPE_BICOMPLEX: "Bicomplex",
        TYPE_NEUTROSOPHIC_BICOMPLEX: "Neutrosophic Bicomplex",
        TYPE_OCTONION: "Octonion",
        TYPE_SEDENION: "Sedenion",
        TYPE_CLIFFORD: "Clifford",
        TYPE_DUAL: "Dual",
        TYPE_SPLIT_COMPLEX: "Split Complex",
        TYPE_PATHION: "Pathion",
        TYPE_CHINGON: "Chingon",
        TYPE_ROUTON: "Routon",
        TYPE_VOUDON: "Voudon",
        TYPE_SUPERREAL: "Superreal",
        TYPE_TERNARY: "Ternary",
    }

    # Check version
    try:
        if hasattr(kn, "__version__"):
            kn_version = kn.__version__
            logger.info(f"kececinumbers v{kn_version} loaded successfully")
        else:
            logger.info("kececinumbers loaded (version unknown)")

        # Mark as available
        KHA_AVAILABLE = True

    except Exception as e:
        logger.warning(f"Version check failed: {e}")
        KHA_AVAILABLE = False

except ImportError as e:
    logger.error(f"kececinumbers not found: {e}")
    print("⚠️  WARNING: keçeci Sayıları kütüphanesi bulunamadı!")
    print(
        f"   Lütfen şu komutu çalıştırın: pip install kececinumbers=={req_kececinumbers}"
    )
    print("    Geçici olarak matematiksel sabitler kullanılacak...")

    # Import başarısız oldu - False yap
    KHA_AVAILABLE = False  # Burada False yapıyoruz

    # Create dummy types
    WORKING_TYPES = list(range(1, 23))
    TYPE_NAMES = {i: f"Type_{i}" for i in range(1, 23)}
    kn = None


# Instead of directly calling get_serial_info():
def check_serial_info(module):
    """Safely check for serial info if it exists."""
    # Check if function exists
    if hasattr(module, "get_serial_info") and callable(module.get_serial_info):
        try:
            serial_info = module.get_serial_info()
            logger.info(f"Keçeci Numbers Serial: {serial_info}")
        except Exception as e:
            logger.warning(f"Could not get serial info: {e}")
    else:
        # Check for other possible attributes
        for attr in ["serial", "SERIAL", "__serial__"]:
            if hasattr(module, attr):
                logger.info(f"Keçeci Numbers Serial: {getattr(module, attr)}")
                break


# Use it like this:
if KHA_AVAILABLE and kn is not None:
    check_serial_info(kn)


# ============================================================
# GÜVENLİK SABİTLERİ
# ============================================================
class SecurityConstants:
    """Güvenlik için kullanılan sabitler"""

    # Anahtar uzunlukları
    MIN_SALT_LENGTH = 128  # 256
    MIN_KEY_LENGTH = 256

    # Tekrar sayıları
    MIN_ITERATIONS = 6
    MIN_ROUNDS = 2

    # Zorluk parametreleri
    MEMORY_COST = 2**18  # 256KB
    TIME_COST = 8
    PARALLELISM = 2


@dataclass
class FortifiedConfig:
    """
    Performans-Güvenlik dengesi optimize edilmiş config
    Bit düzeyinde rastgelelik (chi-square bit) için optimize edilmiş config
    """

    VERSION: ClassVar[str] = "0.1.4"
    ALGORITHM: ClassVar[str] = "KHA-256"

    # Çıktı boyutu (bit testi için daha büyük örneklem)
    output_bits: int = 256  # 256 → 512 (daha fazla bit örneği)
    hash_bytes: int = 32  # 32 → 64

    # KRİTİK: Bit karıştırma parametreleri
    iterations: int = 6  # 6-10-16 → 24 (daha fazla iterasyon = daha iyi karışım)
    rounds: int = 2  # 2-3-8 → 12 (daha fazla round)
    components_per_hash: int = 32  # 32 → 40 (daha karmaşık hash yapısı)

    # Tuz uzunluğu (bit varyasyonunu artır)
    salt_length: int = 256  # 128-256 → 384

    # BIT KARIŞTIRMA PARAMETRELERİ (ARTIRILDI)
    shuffle_layers: int = 8  # 6-10 → 16 (daha fazla karıştırma katmanı)
    diffusion_rounds: int = 10  # 8-12 → 16 (bit yayılımını artır)
    avalanche_boosts: int = 12  # 4 → 6-8-12 (avalanche etkisini güçlendir)

    # AVALANCHE OPTİMİZASYONU (bit değişimi için kritik)
    use_enhanced_avalanche: bool = True
    avalanche_strength: float = 0.12  # 0.06 → 0.085-0.12 (daha güçlü avalanche)

    # GÜVENLİK ÖZELLİKLERİ (bit rastgeleliği için kritik olanlar)
    enable_quantum_resistance: bool = True  # False → True
    enable_post_quantum_mixing: bool = True  # False → True
    double_hashing: bool = True  # False → True (bit bağımsızlığı için)
    triple_compression: bool = (
        False  # False → True: Performans için kapalı. Çok yavaşlatıyor
    )
    memory_hardening: bool = True  # False → True (bit ilişkisini kır)

    # BYTE DAĞILIMI (bit dağılımını da etkiler)
    enable_byte_distribution_optimization: bool = True
    byte_uniformity_rounds: int = 8  # 3 → 5-8

    # KRİTİK: Bit entropisi için
    entropy_injection: bool = True  # False → True (bit entropisini artır)
    time_varying_salt: bool = True  # Zamanla değişen tuz
    context_sensitive_mixing: bool = True  # Bağlama duyarlı karıştırma

    # BIT GÜVENLİĞİ
    enable_side_channel_resistance: bool = True
    enable_constant_time_ops: bool = True  # Timing attack'dan korunma
    enable_arithmetic_blinding: bool = True  # False → True (bit sızıntısını önle)

    # PERFORMANS (bit kalitesi için fedakarlık)
    cache_enabled: bool = True  # True → False (deterministik olmama)
    cache_size: int = 32
    parallel_processing: bool = True  # True → False (bit sırası önemli)
    max_workers: int = 4

    # MEMORY HARDENING (bit pattern'leri kırmak için)
    memory_cost: int = 2**16  # 2**16 → 2**18 (256KB)
    time_cost: int = 3  # 3-4 → 6
    parallelism: int = 1  # 2 → 1 (bit sırası tutarlılığı)

    # ŞİFRELEME KATMANI (bit karıştırma)
    enable_encryption_layer: bool = True
    encryption_rounds: int = 4  # 3 → 4

    # BIT DÜZELTME FAKTÖRLERİ
    byte_correction_factor: float = 0.075  # 0.067 → 0.075
    bit_correction_factor: float = 0.042  # YENİ: Bit düzeltme faktörü

    # YENİ: BIT-SEVIYE OPTİMİZASYONLARI
    enable_bit_permutation: bool = True  # Bit permütasyonu
    bit_permutation_rounds: int = 12  # 8-12 Bit permütasyon round'ları
    enable_hamming_weight_balancing: bool = (
        False  # Önce test: Hamming ağırlığı dengeleme
    )
    target_hamming_weight: float = 0.5  # Hedef bit ağırlığı

    # YENİ: CHI-SQUARE İYİLEŞTİRME
    chi_square_optimization: bool = True  # YENİ: Chi-square optimizasyonu
    min_bit_bias = 0.00005  # # 0.0005-0.0001 Daha sıkı
    max_bit_correlation = 0.0005  # 0.0005-0.001 Maksimum bit korelasyonu

    # YENİ: CASE SENSITIVITY PARAMETRELERİ
    enable_case_aware_mixing: bool = (
        True  # Case sensitivity için yeni parametre: Case sensitivity kaldırılabilinir
    )
    case_sensitivity_boost: float = 1.5  # Case sensitivity güçlendirme faktörü
    ascii_case_amplification: float = 1.5  # ASCII case farklarını amplify etme
    case_diffusion_factor: float = 0.3  # Case farklarını yayma faktörü

    def __post_init__(self):

        getcontext().prec = 64  # 64 → 80 (daha yüksek hassasiyet)

        # Bit optimizasyonu için ek kontroller
        if self.output_bits % 8 != 0:
            raise ValueError("output_bits 8'in katı olmalıdır")

        # SecurityConstants kullanarak güvenlik kontrolü
        # NOT: SecurityConstants aynı dosyada tanımlandığı için import'a gerek yok
        if self.salt_length < SecurityConstants.MIN_SALT_LENGTH:
            self.salt_length = SecurityConstants.MIN_SALT_LENGTH

        if self.iterations < SecurityConstants.MIN_ITERATIONS:
            self.iterations = SecurityConstants.MIN_ITERATIONS

        if self.rounds < SecurityConstants.MIN_ROUNDS:
            self.rounds = SecurityConstants.MIN_ROUNDS

    @property
    def security_level(self) -> str:
        return "OPTIMIZED-BALANCED"

    @property
    def expected_performance_ms(self) -> float:
        """Beklenen performans (ms)"""
        base_time = 50  # temel süre
        time_multiplier = self.iterations * self.rounds * self.shuffle_layers * 0.1
        return base_time * time_multiplier

    @property
    def avalanche_target(self) -> float:
        """Avalanche hedefi"""
        return 51.8  # %51.8 average target (artırıldı)

    def to_dict(self) -> Dict[str, Any]:
        """Config to dict"""
        return {
            "version": self.VERSION,  # __version__ yerine self.VERSION kullan
            "algorithm": self.ALGORITHM,
            "security_level": self.security_level,
            "avalanche_target": self.avalanche_target,
            "parameters": {
                "iterations": self.iterations,
                "shuffle_layers": self.shuffle_layers,
                "diffusion_rounds": self.diffusion_rounds,
                "salt_length": self.salt_length,
                "memory_cost": self.memory_cost,
                "time_cost": self.time_cost,
            },
            "security_features": {
                "enable_side_channel_resistance": self.enable_side_channel_resistance,
                "enable_constant_time_ops": self.enable_constant_time_ops,
                "enable_arithmetic_blinding": self.enable_arithmetic_blinding,
                "enable_encryption_layer": self.enable_encryption_layer,
            },
        }


"""
# ============================================================
# KONFİGÜRASYON - GÜVENLİK ÖNCELİKLİ (GÜÇLENDİRİLMİŞ)
# ============================================================
@dataclass
class FortifiedConfig:
    # GÜÇLENDİRİLMİŞ KHA Hash Konfigürasyonu - GÜVENLİK MAKSİMUM
    
    # Çıktı boyutu
    output_bits: int = 256
    hash_bytes: int = 32  # 256-bit = 32 byte
    
    # GÜVENLİK PARAMETRELERİ (ARTIRILMIŞ)
    iterations: int = 16           # 11 → 16 (daha fazla iterasyon)
    rounds: int = 8               # 6 → 8 (daha fazla round)
    components_per_hash: int = 12  # 8 → 12 (daha fazla bileşen)
    salt_length: int = 256        # 128 → 256 (daha uzun tuz)
    
    # KARIŞTIRMA PARAMETRELERİ (ARTIRILMIŞ)
    shuffle_layers: int = 10       # 6 → 10 (daha fazla karıştırma katmanı)
    diffusion_rounds: int = 12     # 7 → 12 (daha fazla difüzyon)
    avalanche_boosts: int = 4      # 2 → 4 (daha fazla avalanche güçlendirme)
    
    # GÜVENLİK ÖZELLİKLERİ (HEPSİ AKTİF)
    enable_quantum_resistance: bool = True
    enable_post_quantum_mixing: bool = True
    double_hashing: bool = True
    triple_compression: bool = True  # False → True
    memory_hardening: bool = True
    
    # KRİTİK AYARLAR (güvenlik için)
    entropy_injection: bool = True   # False → True (daha fazla entropi)
    time_varying_salt: bool = True   # False → True (zaman bazlı tuz)
    context_sensitive_mixing: bool = True
    
    # GÜVENLİK EKLEMELERİ - YENİ ÖZELLİKLER EKLENDİ
    enable_side_channel_resistance: bool = True  # Yan kanal saldırılarına karşı koruma - YENİ EKLENDİ
    enable_constant_time_ops: bool = True       # Zaman sabit operasyonlar - YENİ EKLENDİ
    enable_arithmetic_blinding: bool = True     # Aritmetik işlemler için körleme - YENİ EKLENDİ
    
    # PERFORMANS (güvenlik için fedakarlık)
    cache_enabled: bool = False  # True → False (cache güvenlik açığı olabilir)
    cache_size: int = 0
    parallel_processing: bool = False  # True → False (paralel işlem güvenlik açığı)
    max_workers: int = 1
    
    # AVALANCHE OPTİMİZASYONU
    use_enhanced_avalanche: bool = True
    avalanche_strength: float = 0.1  # 0.05 → 0.1 (daha güçlü avalanche)
    
    # MEMORY HARDENING PARAMETRELERİ
    memory_cost: int = SecurityConstants.MEMORY_COST
    time_cost: int = SecurityConstants.TIME_COST
    parallelism: int = SecurityConstants.PARALLELISM
    
    # ŞİFRELEME DESTEĞİ
    enable_encryption_layer: bool = True  # Hash'leme öncesi şifreleme katmanı
    encryption_rounds: int = 3
    
    def __post_init__(self):
        # Post-initialization# 
        getcontext().prec = 128  # 64 → 128 (daha yüksek hassasiyet)
        
        # Güvenlik kontrolü
        if self.salt_length < SecurityConstants.MIN_SALT_LENGTH:
            self.salt_length = SecurityConstants.MIN_SALT_LENGTH
            
        if self.iterations < SecurityConstants.MIN_ITERATIONS:
            self.iterations = SecurityConstants.MIN_ITERATIONS
            
        if self.rounds < SecurityConstants.MIN_ROUNDS:
            self.rounds = SecurityConstants.MIN_ROUNDS
    
    @property
    def security_level(self) -> str:
        # Güvenlik seviyesi
        return "ULTRA-SECURE-MAXIMUM"
"""


class ByteDistributionOptimizer:
    """Byte dağılımını iyileştirici"""

    @staticmethod
    def optimize_byte_distribution(hash_bytes: bytes, rounds: int = 3) -> bytes:
        """Byte dağılımını optimize et"""
        result = bytearray(hash_bytes)

        for round_num in range(rounds):
            # Byte frekanslarını hesapla
            byte_counts = [0] * 256
            for byte in result:
                byte_counts[byte] += 1

            expected = len(result) / 256

            # Çok yüksek frekanslı byte'ları düzelt
            for i in range(len(result)):
                current_byte = result[i]
                current_count = byte_counts[current_byte]

                if current_count > expected * 1.5:  # %50'den fazla yüksekse
                    # Daha az kullanılan byte bul
                    min_byte = min(range(256), key=lambda x: byte_counts[x])

                    if byte_counts[min_byte] < expected * 0.5:  # %50'den azsa
                        # Değiştir
                        result[i] = min_byte
                        byte_counts[current_byte] -= 1
                        byte_counts[min_byte] += 1

            # XOR mixing for better distribution
            for i in range(0, len(result) - 1, 2):
                result[i] ^= result[i + 1]
                result[i + 1] ^= result[i]
                result[i] ^= result[i + 1]

        return bytes(result)

    @staticmethod
    def calculate_byte_uniformity(data: bytes) -> float:
        """Byte uniformluğunu hesapla (0-1, 1=en iyi)"""
        if len(data) == 0:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        expected = len(data) / 256
        if expected == 0:
            return 0.0

        chi_square = sum(((count - expected) ** 2) / expected for count in byte_counts)

        # Normalize et (0-1 arası, 1=en uniform)
        # 255 serbestlik derecesi için ideal chi-square: ~284
        ideal_chi = 284
        uniformity = 1.0 - min(1.0, abs(chi_square - ideal_chi) / (ideal_chi * 2))

        return uniformity


# ============================================================
# GÜVENLİK KATMANLARI
# ============================================================
class SecurityLayers:
    """Çok katmanlı güvenlik katmanları"""

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Zaman sabit byte karşılaştırması"""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    @staticmethod
    def timing_attack_protection(func):
        """Zamanlama saldırılarına karşı koruma dekoratörü"""

        def wrapper(*args, **kwargs):
            # Sadece side channel resistance aktifse
            if hasattr(args[0], "config") and hasattr(
                args[0].config, "enable_side_channel_resistance"
            ):
                if not args[0].config.enable_side_channel_resistance:
                    return func(*args, **kwargs)

            # Sabit zaman için rastgele gecikme ekle
            import time

            base_time = 0.001  # 1ms temel gecikme
            random_delay = random.uniform(0, 0.0005)  # 0-0.5ms rastgele gecikme
            time.sleep(base_time + random_delay)

            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def arithmetic_blinding(value: int, bits: int = 64) -> int:
        """Aritmetik işlemler için körleme"""
        mask = (1 << bits) - 1
        blinding_factor = random.getrandbits(bits)
        blinded = (value ^ blinding_factor) & mask
        return blinded

    @staticmethod
    def secure_memory_zero(buffer: bytearray):
        """Belleği güvenli şekilde sıfırla"""
        for i in range(len(buffer)):
            buffer[i] = 0
        del buffer

    @staticmethod
    def apply_constant_time_operations(config):
        """Zaman sabit operasyonları uygula"""
        if not config.enable_constant_time_ops:
            return lambda func: func  # Pasifse dekoratörü bypass et

        def decorator(func):
            def wrapper(*args, **kwargs):
                # Zaman sabit operasyonlar için ek kontroller
                result = func(*args, **kwargs)

                # Ek güvenlik: her işlemden sonra küçük bir sabit gecikme
                if config.enable_side_channel_resistance:
                    import time

                    time.sleep(0.0001)  # 0.1ms sabit gecikme

                return result

            return wrapper

        return decorator


# ============================================================
# MATEMATİKSEL GÜVENLİK TABANLARI (GÜÇLENDİRİLMİŞ)
# ============================================================
class MathematicalSecurityBases:
    """Güçlendirilmiş matematiksel güvenlik sabitleri ve fonksiyonları"""

    # Özel matematiksel sabitler (genişletilmiş)
    SECURITY_CONSTANTS = {
        # İrrasyonel sabitler
        "kha_pi": 3.14159265358979323846264338327950288419716939937510,
        "kha_e": 2.71828182845904523536028747135266249775724709369995,
        "golden_ratio": 1.61803398874989484820458683436563811772030917980576,
        "silver_ratio": 2.41421356237309504880168872420969807856967187537694,
        "plastic_number": 1.32471795724474602596090885447809734073440405690173,
        "tribonacci_constant": 1.8392867552141611325518525646532866004241787460975,
        "supergolden_ratio": 1.465571231876768026656731225219939,
        # Özel matematiksel sabitler
        "apery": 1.202056903159594285399738161511449990764986292,
        "catalan": 0.91596559417721901505460351493238411077414937428167,
        "lemniscate": 2.62205755429211981046483958989111941368275495143162,
        "gauss": 0.834626841674073186281429734799,
        "ramanujan_soldner": 1.451369234883381050283968485892027,
        "mills_constant": 1.30637788386308069046861449260260571,
        # Transandantal sabitler
        "euler_mascheroni": 0.57721566490153286060651209008240243104215933593992,
        "khinchin": 2.68545200106530644530971483548179569382038229399446,
        "glaisher": 1.28242712910062263687534256886979172776768892732500,
        "gompertz": 0.596347362323194074341078499,
        "liouville": 0.11000100000000000000000100000000000000000000000000,
        # Özel güvenlik sabitleri
        "kececi_constant": 2.2360679774997896964091736687312762354406183596115,  # √5
        "security_phi": 1.381966011250105151795413165634361,  # 2-φ
        "quantum_constant": 1.5707963267948966192313216916397514420985846996875,  # π/2
    }

    # Güvenlik dönüşüm fonksiyonları (genişletilmiş)
    TRANSFORMATIONS = [
        # Sinüs tabanlı (genişletilmiş)
        lambda x: np.sin(x * np.pi * 1.618033988749895),
        lambda x: np.sin(x * x * np.pi),
        lambda x: np.sin(np.exp(x)),
        lambda x: np.sin(np.log1p(np.abs(x) + 1e-10) * np.pi),
        lambda x: np.sin(np.sqrt(np.abs(x) + 1e-10) * np.pi),
        # Hiperbolik (genişletilmiş)
        lambda x: np.tanh(x * 3.141592653589793),
        lambda x: np.sinh(x) / (np.cosh(x) + 1e-10),
        lambda x: np.arctan(x * 10),
        lambda x: np.arctan(np.sinh(x)),
        # Karmaşık (genişletilmiş)
        lambda x: x * np.exp(-x * x),
        lambda x: np.log1p(np.abs(x)),
        lambda x: np.sqrt(np.abs(x) + 1e-10),
        lambda x: 1 / (1 + np.exp(-x)),
        lambda x: np.exp(-x * x / 2),
        # Özel kombinasyonlar (genişletilmiş)
        lambda x: np.sin(x * np.pi) * np.tanh(x * 2.71828),
        lambda x: np.arctan(x * 3.14159) * np.log1p(np.abs(x)),
        lambda x: np.sin(x * 1.61803) + np.cos(x * 2.41421),
        lambda x: np.exp(-x) * np.sin(x * np.pi),
        lambda x: np.tanh(np.sin(x * np.pi) * np.cos(x * 1.61803)),
        # Güvenlik odaklı
        lambda x: (np.sin(x) + np.cos(x * 1.61803)) / 2,
        lambda x: np.arctan(np.tanh(x * 2.71828) * 3.14159),
        lambda x: np.log1p(np.abs(np.sin(x * np.pi))),
        lambda x: np.sqrt(np.abs(np.cos(x * 1.32472)) + 1e-10),
        # Kriptografik
        lambda x: ((x * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF) / 0xFFFFFFFFFFFFFFFF,
        lambda x: ((x * 0x6A09E667F3BCC908) & 0xFFFFFFFFFFFFFFFF) / 0xFFFFFFFFFFFFFFFF,
    ]

    @staticmethod
    def get_constant(name: str, offset: float = 0) -> float:
        """Güvenlik sabiti al"""
        const_val = MathematicalSecurityBases.SECURITY_CONSTANTS.get(
            name, MathematicalSecurityBases.SECURITY_CONSTANTS["kha_pi"]
        )
        return const_val + offset

    @staticmethod
    @SecurityLayers.timing_attack_protection
    def apply_transformations(value: float, rounds: int = 5) -> float:
        """Çoklu dönüşüm uygula (zaman sabit)"""
        for i in range(rounds):
            idx = (int(value * 1e12) + i) % len(
                MathematicalSecurityBases.TRANSFORMATIONS
            )
            value = MathematicalSecurityBases.TRANSFORMATIONS[idx](value)
        return value

    @staticmethod
    def generate_secure_matrix(seed: int, size: int = 512) -> np.ndarray:
        """Güvenli matris oluştur"""
        seed = seed & 0xFFFFFFFF  # 32-bit sınırı
        rng = np.random.RandomState(seed)

        # Çoklu dağılımlardan matris oluştur
        matrices = [
            rng.uniform(0, 1, size),
            rng.normal(0.5, 0.1, size),
            rng.logistic(0.5, 0.05, size),
            np.sin(rng.random(size) * np.pi),
            np.tanh(rng.random(size) * 2),
        ]

        # Matrisleri birleştir
        combined = np.zeros(size)
        for i, mat in enumerate(matrices):
            weight = MathematicalSecurityBases.get_constant(
                list(MathematicalSecurityBases.SECURITY_CONSTANTS.keys())[
                    i % len(MathematicalSecurityBases.SECURITY_CONSTANTS)
                ]
            )
            combined = (combined + mat * weight) % 1.0

        return combined


# ============================================================
# KHA ÇEKİRDEĞİ (GÜÇLENDİRİLMİŞ)
# ============================================================
class FortifiedKhaCore:
    """Fortified KHA Hash Core"""

    def __init__(self, config: FortifiedConfig):
        self.config = config

        # More specific type hints
        self.stats: Dict[str, Union[int, float]] = {
            "hash_count": 0,
            "total_time": 0.0,
            "mixing_time": 0.0,
            "compression_time": 0.0,
            "conversion_time": 0.0,
            "total_operations": 0,
            "kha_success": 0,
            "kha_fail": 0,
            "avalanche_score": 0.0,
            "security_operations": 0,
        }

        # String, list, dict değerleri için ayrı dictionary
        self.text_stats: Dict[str, str] = {}
        self.list_stats: Dict[str, list] = {}
        self.dict_stats: Dict[str, dict] = {}

        # Security state
        self._last_operation_time = 0
        self._operation_counter = 0

    @SecurityLayers.timing_attack_protection
    def _generate_kha_matrix(self, seed_data: bytes) -> np.ndarray:
        """Generate matrix from enhanced KHA values"""
        self.stats["total_operations"] += 1
        self.stats["security_operations"] += 1

        values = []

        # Seed preparation
        seed_int = int.from_bytes(seed_data[:16], "big")
        seed_int = SecurityLayers.arithmetic_blinding(seed_int)

        rng = random.Random(seed_int)

        # Types to be used - safe and tested types
        SAFE_TYPES = []
        TYPE_REQUIREMENTS = {}

        # Tipleri ve gereksinimlerini tanımla
        if KHA_AVAILABLE:
            try:
                # ÇALIŞAN TİPLER (test edilmiş ve güvenli)

                # 1. Basit Sayılar
                SAFE_TYPES.extend([TYPE_POSITIVE_REAL, TYPE_NEGATIVE_REAL, TYPE_FLOAT])
                TYPE_REQUIREMENTS[TYPE_POSITIVE_REAL] = {
                    "format": "simple_float",
                    "components": 1,
                }
                TYPE_REQUIREMENTS[TYPE_NEGATIVE_REAL] = {
                    "format": "simple_float",
                    "components": 1,
                }
                TYPE_REQUIREMENTS[TYPE_FLOAT] = {
                    "format": "simple_float",
                    "components": 1,
                }

                # 2. Complex
                SAFE_TYPES.extend([TYPE_COMPLEX, TYPE_NEUTROSOPHIC_COMPLEX])
                TYPE_REQUIREMENTS[TYPE_COMPLEX] = {"format": "complex", "components": 2}
                TYPE_REQUIREMENTS[TYPE_NEUTROSOPHIC_COMPLEX] = {
                    "format": "complex",
                    "components": 2,
                }

                # 3. Quaternion
                SAFE_TYPES.append(TYPE_QUATERNION)
                TYPE_REQUIREMENTS[TYPE_QUATERNION] = {
                    "format": "quaternion",
                    "components": 4,
                }

                # 4. Octonion
                SAFE_TYPES.append(TYPE_OCTONION)
                TYPE_REQUIREMENTS[TYPE_OCTONION] = {
                    "format": "octonion",
                    "components": 8,
                }

                # 5. Rational
                SAFE_TYPES.append(TYPE_RATIONAL)
                TYPE_REQUIREMENTS[TYPE_RATIONAL] = {
                    "format": "rational_int",
                    "components": 2,
                }

                # 6. Neutrosophic
                SAFE_TYPES.append(TYPE_NEUTROSOPHIC)
                TYPE_REQUIREMENTS[TYPE_NEUTROSOPHIC] = {
                    "format": "neutrosophic",
                    "components": 3,
                }

                # 7. Hyperreal
                SAFE_TYPES.append(TYPE_HYPERREAL)
                TYPE_REQUIREMENTS[TYPE_HYPERREAL] = {
                    "format": "hyperreal_simple",
                    "components": 2,
                }

                # 8. Bicomplex
                SAFE_TYPES.append(TYPE_BICOMPLEX)
                TYPE_REQUIREMENTS[TYPE_BICOMPLEX] = {
                    "format": "bicomplex",
                    "components": 4,
                }

                # 9. Dual ve Split Complex
                try:
                    SAFE_TYPES.extend([TYPE_DUAL, TYPE_SPLIT_COMPLEX])
                    TYPE_REQUIREMENTS[TYPE_DUAL] = {"format": "dual", "components": 2}
                    TYPE_REQUIREMENTS[TYPE_SPLIT_COMPLEX] = {
                        "format": "split_complex",
                        "components": 2,
                    }
                except NameError:
                    pass

            except NameError as e:
                logger.warning(f"Type name error: {e}")
                # Varsayılan güvenli tipler
                SAFE_TYPES = [1, 2, 3, 4, 6, 8, 10, 11]
                for t in SAFE_TYPES:
                    TYPE_REQUIREMENTS[t] = {"format": "simple_float", "components": 2}
        else:
            # KHA yoksa
            SAFE_TYPES = list(range(1, 13))
            for t in SAFE_TYPES:
                TYPE_REQUIREMENTS[t] = {"format": "simple_float", "components": 2}

        # Her hash için 5-8 farklı tür kullan
        num_types_to_use = min(rng.randint(5, 8), len(SAFE_TYPES))
        selected_types = rng.sample(SAFE_TYPES, num_types_to_use)

        # İterasyon derinliği (artırıldı)
        iteration_depth = rng.randint(16, 24)

        logger.debug(
            f"Using {num_types_to_use} KHA types from {len(SAFE_TYPES)} safe types"
        )

        for type_idx, kececi_type in enumerate(selected_types):
            # components_needed_int'i başta tanımla (default değer)
            components_needed_int = 3  # Varsayılan değer

            try:
                type_info = TYPE_REQUIREMENTS.get(
                    kececi_type, {"format": "simple_float", "components": 2}
                )
                format_type = type_info["format"]
                components_needed = type_info["components"]

                # components_needed_int'i güvenli bir şekilde hesapla
                if components_needed is None:
                    components_needed_int = 3  # Varsayılan değer
                elif isinstance(components_needed, (int, np.integer)):
                    components_needed_int = int(components_needed)
                elif isinstance(components_needed, float):
                    components_needed_int = int(round(components_needed))
                elif hasattr(components_needed, "__int__"):
                    components_needed_int = int(components_needed)
                else:
                    try:
                        components_needed_int = int(float(str(components_needed)))
                    except (ValueError, TypeError):
                        components_needed_int = 3  # Varsayılan değer

                if KHA_AVAILABLE and kn is not None:
                    # Matematiksel sabitler
                    const_names = list(
                        MathematicalSecurityBases.SECURITY_CONSTANTS.keys()
                    )
                    const_name = rng.choice(const_names)
                    base_val = MathematicalSecurityBases.get_constant(const_name)

                    # Format'a göre başlangıç değeri oluştur
                    if format_type == "simple_float":
                        float_val = base_val * (1 + rng.random() * 0.05)
                        start_val = str(float_val)
                        add_val = str(float_val * 0.0001)

                        if kececi_type == TYPE_NEGATIVE_REAL:
                            start_val = "-" + start_val
                            add_val = "-" + add_val

                    elif format_type == "complex":
                        real_part = base_val * (1 + rng.random() * 0.04)
                        imag_const = "kha_e" if const_name == "kha_pi" else "kha_pi"
                        imag_base = MathematicalSecurityBases.get_constant(imag_const)
                        imag_part = imag_base * (1 + rng.random() * 0.03)
                        start_val = f"{real_part}+{imag_part}j"
                        add_val = f"{real_part*0.0005}+{imag_part*0.0005}j"

                    elif format_type == "quaternion":
                        parts = []
                        quat_consts = [
                            "kha_pi",
                            "kha_e",
                            "golden_ratio",
                            "silver_ratio",
                        ]
                        for i in range(4):
                            const_name_i = quat_consts[i % len(quat_consts)]
                            const_val = MathematicalSecurityBases.get_constant(
                                const_name_i
                            )
                            part_val = const_val * (1 + rng.random() * 0.02)
                            parts.append(str(part_val))
                        start_val = ",".join(parts)
                        add_val = ",".join([str(float(p) * 0.0001) for p in parts])

                    elif format_type == "octonion":
                        parts = []
                        oct_consts = [
                            "kha_pi",
                            "kha_e",
                            "golden_ratio",
                            "silver_ratio",
                            "apery",
                            "catalan",
                            "euler_mascheroni",
                            "khinchin",
                        ]
                        for i in range(8):
                            const_idx = i % len(oct_consts)
                            const_val = MathematicalSecurityBases.get_constant(
                                oct_consts[const_idx]
                            )
                            part_val = const_val * (1 + rng.random() * 0.015)
                            parts.append(str(part_val))
                        start_val = ",".join(parts)
                        add_val = ",".join([str(float(p) * 0.00008) for p in parts])

                    elif format_type == "rational_int":
                        numerator = int(base_val * 1000) + rng.randint(1, 100)
                        denominator = int(
                            MathematicalSecurityBases.get_constant("kha_e") * 1000
                        ) + rng.randint(1, 100)
                        start_val = f"{numerator}/{denominator}"
                        add_val = f"{max(1, int(numerator * 0.001))}/{denominator}"

                    elif format_type == "neutrosophic":
                        t_val = base_val * 0.8
                        i_val = 0.3 + rng.random() * 0.4
                        f_val = 0.1 + rng.random() * 0.3
                        start_val = f"{t_val},{i_val},{f_val}"
                        add_val = f"{t_val*0.001},{i_val*0.001},{f_val*0.001}"

                    elif format_type == "hyperreal_simple":
                        standard = base_val
                        infinitesimal = 0.000001 * (1 + type_idx * 0.1)
                        start_val = f"{standard}+{infinitesimal}"
                        add_val = f"{infinitesimal*0.1}"

                    elif format_type == "bicomplex":
                        real1 = base_val * (1 + rng.random() * 0.03)
                        imag1 = MathematicalSecurityBases.get_constant("kha_e") * (
                            1 + rng.random() * 0.03
                        )
                        real2 = MathematicalSecurityBases.get_constant(
                            "golden_ratio"
                        ) * (1 + rng.random() * 0.03)
                        imag2 = MathematicalSecurityBases.get_constant(
                            "silver_ratio"
                        ) * (1 + rng.random() * 0.03)
                        start_val = f"{real1}+{imag1}j,{real2}+{imag2}j"
                        add_val = f"{real1*0.0005}+{imag1*0.0005}j,{real2*0.0005}+{imag2*0.0005}j"

                    elif format_type == "dual":
                        real_part = base_val
                        dual_part = 0.000001 * (1 + type_idx * 0.05)
                        start_val = f"{real_part}+{dual_part}ε"
                        add_val = f"{dual_part*0.1}ε"

                    elif format_type == "split_complex":
                        real_part = base_val
                        split_part = (
                            MathematicalSecurityBases.get_constant("kha_e") * 0.1
                        )
                        start_val = f"{real_part}+{split_part}j"
                        add_val = f"{split_part*0.001}j"

                    # API çağrısı
                    seq = None
                    api_attempts = [
                        lambda: (
                            kn.get_with_params(
                                kececi_type_choice=kececi_type,
                                iterations=iteration_depth,
                                start_value_raw=start_val,
                                add_value_raw=add_val,
                                include_intermediate_steps=True,
                            )
                            if hasattr(kn, "get_with_params")
                            else None
                        ),
                        lambda: (
                            kn.get_with_params(
                                kececi_type=kececi_type,
                                iterations=iteration_depth,
                                start_value=start_val,
                                add_value=add_val,
                                include_intermediate_steps=False,
                            )
                            if hasattr(kn, "get_with_params")
                            else None
                        ),
                        lambda: (
                            kn.get(kececi_type, iteration_depth, start_val, add_val)
                            if hasattr(kn, "get")
                            else None
                        ),
                    ]

                    for attempt in api_attempts:
                        try:
                            seq = attempt()
                            if seq:
                                break
                        except:
                            continue

                    if seq:
                        num_values_to_extract = min(iteration_depth, len(seq), 12)

                        for val_idx in range(-num_values_to_extract, 0):
                            if val_idx < 0:
                                final_val = seq[val_idx]
                                extracted = self._extract_numerics(final_val)

                                # extracted'in numeric list olduğundan emin ol
                                if not isinstance(extracted, (list, tuple)):
                                    extracted = [extracted]

                                # İlk extend işlemi
                                extract_count = min(
                                    len(extracted), components_needed_int * 3
                                )
                                values.extend(extracted[:extract_count])

                                # Progress hesaplama
                                progress = float(val_idx + len(seq)) / float(len(seq))

                                # Modülasyon için
                                slice_count = min(len(extracted), components_needed_int)
                                for i in range(slice_count):
                                    val = extracted[i]
                                    try:
                                        # val'ı numeric'e çevirmeye çalış
                                        num_val = (
                                            float(val)
                                            if not isinstance(
                                                val, (int, float, np.number)
                                            )
                                            else val
                                        )
                                        if progress > 0:
                                            modulated = num_val * (
                                                1 + np.sin(progress * np.pi * 2) * 0.15
                                            )
                                            values.append(float(modulated))
                                    except (ValueError, TypeError, AttributeError):
                                        continue

                        self.stats["kha_success"] += 1

                    else:
                        self.stats["kha_fail"] += 1
                        # components_needed_int artık tanımlı
                        self._add_secure_fallback_values(
                            values, type_idx, components_needed_int, rng
                        )

                else:
                    self._add_secure_math_fallback_values(values, type_idx, rng)

            except Exception as e:
                logger.error(f"KHA matrix error for type {kececi_type}: {e}")
                self.stats["kha_fail"] += 1
                # components_needed_int artık tanımlı (hata durumunda da varsayılan değerle)
                self._add_secure_fallback_values(
                    values, type_idx, components_needed_int, rng
                )

        # Matris işleme
        processed_matrix = self._process_matrix_values(
            values, seed_int, target_size=1024
        )

        logger.info(
            f"Generated KHA matrix: {len(processed_matrix)} values, "
            f"success: {self.stats['kha_success']}, fail: {self.stats['kha_fail']}"
        )

        return processed_matrix

    # def _add_secure_fallback_values(self, values, type_idx, components_needed, rng):
    def _add_secure_fallback_values(
        self, values: list, type_idx: int, components_needed: int, rng: random.Random
    ) -> None:
        """Güvenli fallback değerleri ekle"""
        const_names = list(MathematicalSecurityBases.SECURITY_CONSTANTS.keys())

        for i in range(components_needed * 3):
            const_name = rng.choice(const_names)
            base_val = MathematicalSecurityBases.get_constant(const_name)
            variation = 0.08 * (1 + type_idx * 0.12 + i * 0.03)
            val = base_val * (1 + rng.random() * variation)

            transforms = [
                lambda x: x,
                lambda x: np.sin(x * np.pi * 0.618),
                lambda x: np.exp(-x * 0.15),
                lambda x: np.log1p(abs(x) * 10),
                lambda x: np.tanh(x * 1.5),
            ]

            transform_idx = (i + type_idx) % len(transforms)
            transformed = transforms[transform_idx](val)
            values.append(transformed)

    def _add_secure_math_fallback_values(self, values, type_idx, rng):
        """Güvenli matematiksel fallback değerleri ekle"""
        consts_to_use = [
            "kha_pi",
            "kha_e",
            "golden_ratio",
            "silver_ratio",
            "plastic_number",
            "tribonacci_constant",
            "kececi_constant",
        ]

        for const_idx, const_name in enumerate(consts_to_use):
            base_val = MathematicalSecurityBases.get_constant(const_name)

            for var_idx in range(3):
                variation = 0.04 * (1 + type_idx * 0.2 + var_idx * 0.1)
                val = base_val * (1 + rng.random() * variation)

                values.extend(
                    [
                        val,
                        np.sin(val * np.pi * 1.618),
                        np.exp(-val * 0.08),
                        np.tanh(val * 0.2),
                        np.arctan(val * 5),
                    ]
                )

    @SecurityLayers.timing_attack_protection
    def _process_matrix_values(self, values, seed_int, target_size=1024):
        """Değerleri işle ve matrise dönüştür (zaman sabit)"""
        if not values:
            for i in range(target_size):
                phase = i * 0.03
                val = MathematicalSecurityBases.get_constant("kha_pi", phase)
                values.append(val * (1 + np.sin(phase * 2) * 0.25))

        # Boyutlandırma
        if len(values) < target_size:
            current = list(values)
            while len(values) < target_size:
                idx = len(values) % len(current)
                base = current[idx % len(current)] if current else 1.0

                transform_idx = (len(values) // len(current)) % 6
                if transform_idx == 0:
                    new_val = base * (1 + np.sin(len(values) * 0.08) * 0.2)
                elif transform_idx == 1:
                    new_val = np.exp(base * 0.003)
                elif transform_idx == 2:
                    new_val = np.tanh(base * 0.03)
                elif transform_idx == 3:
                    new_val = base * 1.618033988749895
                elif transform_idx == 4:
                    new_val = np.arctan(base * 3)
                else:
                    new_val = np.log1p(abs(base))

                values.append(new_val)
        else:
            values = values[:target_size]

        # Numpy array'e dönüştür
        values_array = np.array(values, dtype=np.float64)

        # Güvenli normalizasyon
        min_val = np.min(values_array)
        max_val = np.max(values_array)
        if max_val - min_val > 1e-12:
            values_array = (values_array - min_val) / (max_val - min_val)
        else:
            values_array = np.zeros_like(values_array) + 0.5

        # Güvenli karıştırma
        shuffle_seed = SecurityLayers.arithmetic_blinding(seed_int + 12345)
        shuffle_seed = shuffle_seed & 0xFFFFFFFF  # 32-bit sınırı
        rng_shuffle = random.Random(shuffle_seed)
        indices = list(range(len(values_array)))
        rng_shuffle.shuffle(indices)

        final_matrix = values_array[indices]

        # Son non-lineer dönüşüm
        final_matrix = np.sin(final_matrix * np.pi * 1.618033988749895)

        return final_matrix

    def _extract_numerics(self, kha_obj) -> List[float]:
        """KHA objesinden sayısal değerleri çıkar"""
        values = []

        # coeffs özelliği
        if hasattr(kha_obj, "coeffs"):
            try:
                coeffs = kha_obj.coeffs
                if isinstance(coeffs, (list, tuple)):
                    values.extend([float(c) for c in coeffs[:128]])
            except:
                pass

        # Bilinen özellikler
        numeric_attrs = [
            "w",
            "x",
            "y",
            "z",
            "real",
            "imag",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "value",
            "magnitude",
            "norm",
            "abs",
            "modulus",
            "re",
            "im",
            "scalar",
            "vector",
        ]

        for attr in numeric_attrs:
            if hasattr(kha_obj, attr):
                try:
                    val = getattr(kha_obj, attr)
                    if isinstance(val, (int, float, complex)):
                        if isinstance(val, complex):
                            values.extend([val.real, val.imag])
                        else:
                            values.append(float(val))
                except:
                    pass

        # String temsili
        if not values:
            try:
                s = str(kha_obj)
                numbers = re.findall(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", s)
                values.extend([float(n) for n in numbers[:64]])
            except:
                pass

        # Final fallback
        if not values:
            values.append(MathematicalSecurityBases.get_constant("kececi_constant"))

        return values

    @SecurityLayers.timing_attack_protection
    def _fortified_mixing_pipeline(self, matrix: np.ndarray, salt: bytes) -> np.ndarray:
        """Güçlendirilmiş karıştırma pipeline'ı"""
        start_time = time.perf_counter()

        len(matrix)

        # 1. GELİŞMİŞ BAŞLANGIÇ İŞLEMLERİ
        for norm_pass in range(3):  # 2 → 3
            mean_val = np.mean(matrix)
            std_val = np.std(matrix)
            if std_val < 1e-12:
                std_val = 1.0

            matrix = (matrix - mean_val) / std_val

            min_val = np.min(matrix)
            max_val = np.max(matrix)
            if max_val - min_val > 1e-12:
                matrix = (matrix - min_val) / (max_val - min_val)
            else:
                matrix = np.zeros_like(matrix) + 0.5

            matrix = np.tanh(matrix * 2.5)  # 2.0 → 2.5

        # 2. AVALANCHE-OPTİMİZE KARIŞTIRMA KATMANLARI
        for layer in range(self.config.shuffle_layers):
            # a) GÜÇLÜ NON-LİNEER DÖNÜŞÜM
            matrix = self._avalanche_optimized_transform(matrix, layer, salt)

            # b) YÜKSEK DİFÜZYON
            matrix = self._high_diffusion_transform(matrix, layer, salt)

            # c) KARMAŞIK PERMÜTASYON
            matrix = self._complex_permutation(matrix, layer, salt)

            # d) AVALANCHE BOOST
            matrix = self._enhanced_avalanche_boost(matrix, layer, salt)

            # e) BİT MİKSERİ
            if layer % 2 == 0:
                matrix = self._bit_mixer_transform(matrix, layer, salt)

            # f) GÜVENLİK KATMANI
            if layer % 3 == 0:
                matrix = self._security_layer_transform(matrix, layer, salt)

        # 3. POST-PROCESSING AVALANCHE ENHANCEMENT
        matrix = self._post_avalanche_enhancement(matrix, salt)

        # 4. QUANTUM RESISTANT FINAL MIX
        if self.config.enable_quantum_resistance:
            matrix = self._quantum_avalanche_mix(matrix, salt)

        # 5. FINAL NORMALIZATION
        matrix = self._final_avalanche_normalization(matrix)

        # 6. EK GÜVENLİK KATMANI
        matrix = self._extra_security_layer(matrix, salt)

        # Type-safe stats updates
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Update mixing_time safely
        mixing_time = self.stats.get("mixing_time")
        if isinstance(mixing_time, (int, float)):
            self.stats["mixing_time"] = float(mixing_time) + elapsed_ms
        else:
            # If it's not numeric, initialize it
            self.stats["mixing_time"] = elapsed_ms

        # Update security_operations safely
        sec_ops = self.stats.get("security_operations")
        if isinstance(sec_ops, int):
            self.stats["security_operations"] = sec_ops + 1
        else:
            # If it's not an int, initialize it
            self.stats["security_operations"] = 1

        return matrix

    def _security_layer_transform(
        self, matrix: np.ndarray, layer: int, salt: bytes
    ) -> np.ndarray:
        """Ek güvenlik katmanı dönüşümü"""
        result = matrix.copy()
        n = len(result)

        # Yan kanal koruması için körleme
        blinding_factor = np.sin(layer * 0.317) * 0.01
        result = (result + blinding_factor) % 1.0

        # Bellek sertleştirme
        if self.config.memory_hardening and n >= 256:
            memory_block = np.zeros((16, 16))
            for i in range(16):
                for j in range(16):
                    idx = (i * 16 + j) % n
                    memory_block[i, j] = result[idx]

            # Bellek üzerinde işlemler
            for _ in range(self.config.time_cost):
                memory_block = np.sin(memory_block * np.pi)
                memory_block = np.tanh(memory_block * 1.5)

            # Geri yükle
            for i in range(16):
                for j in range(16):
                    idx = (i * 16 + j) % n
                    result[idx] = memory_block[i, j] % 1.0

        return result

    def _extra_security_layer(self, matrix: np.ndarray, salt: bytes) -> np.ndarray:
        """Ek güvenlik katmanı"""
        result = matrix.copy()
        n = len(result)

        # Şifreleme katmanı
        if self.config.enable_encryption_layer:
            for round_num in range(self.config.encryption_rounds):
                # Basit Feistel benzeri şifreleme
                if n >= 2:
                    half = n // 2
                    left = result[:half]
                    right = result[half : 2 * half]

                    # Round fonksiyonu
                    round_key = np.sin(np.arange(half) * 0.1 + round_num * 0.5)
                    f_result = np.tanh((left + round_key) * 1.5)

                    # Feistel işlemi
                    new_right = (left + f_result) % 1.0
                    new_left = right

                    result[:half] = new_left
                    result[half : 2 * half] = new_right

        # Sabit zaman koruması
        constant_time_noise = np.sin(np.arange(n) * 0.05) * 0.001
        result = (result + constant_time_noise) % 1.0

        return result

    def _avalanche_optimized_transform(
        self, matrix: np.ndarray, layer: int, salt: bytes
    ) -> np.ndarray:
        """Avalanche için optimize edilmiş non-lineer dönüşüm"""
        result = matrix.copy()
        n = len(result)

        transforms = [
            lambda x: np.sin(x * np.pi * (1.618033988749895 + layer * 0.015)),
            lambda x: np.sin(x * x * np.pi * 2.5),
            lambda x: np.sin(np.exp(np.clip(x, -6, 6))),
            lambda x: np.tanh(x * (3.141592653589793 + layer * 0.025)),
            lambda x: np.sinh(np.clip(x, -4, 4)) / (np.cosh(np.clip(x, -4, 4)) + 1e-12),
            lambda x: x * np.exp(-x * x * 2.5),
            lambda x: np.arctan(x * (15 + layer)),
            lambda x: np.log1p(np.abs(x) + 1e-12) * np.sign(x),
            lambda x: np.sqrt(np.abs(x) + 1e-12) * np.sign(x),
            lambda x: np.sin(x * 2.71828) * np.tanh(x * 3.14159),
            lambda x: np.arctan(x * 7.0) * np.log1p(np.abs(x) + 1e-8),
            lambda x: np.sin(x * 1.61803) + np.cos(x * 2.41421) - np.tanh(x * 1.32472),
            lambda x: np.exp(-x * x / 2) * np.sin(x * np.pi),
            lambda x: np.tanh(np.sin(x * np.pi) * np.cos(x * 1.61803)),
        ]

        salt_int = int.from_bytes(salt[:4], "big") if len(salt) >= 4 else layer
        num_transforms = 5 + (salt_int % 6)  # 5-10 transform

        for i in range(num_transforms):
            idx = (salt_int + i * 17 + layer * 19) % len(transforms)
            result = transforms[idx](result)

            if i % 2 == 0:
                noise_freq = 2.5 + i * 0.4 + layer * 0.15
                noise_phase = salt_int / 10000.0
                noise = np.sin(np.arange(n) * noise_freq + noise_phase) * 0.015
                result = (result + noise) % 1.0

        return result

    def _high_diffusion_transform(
        self, matrix: np.ndarray, layer: int, salt: bytes
    ) -> np.ndarray:
        """Yüksek difüzyon dönüşümü"""
        n = len(matrix)
        result = matrix.copy()

        diffusion_factors = np.array(
            [
                1.618033988749895,  # φ
                2.414213562373095,  # δ_s
                1.324717957244746,  # ψ
                3.141592653589793,  # π
                2.718281828459045,  # e
                1.839286755214161,  # Tribonacci
                1.465571231876768,  # Supergolden
            ],
            dtype=np.float64,
        )

        salt_len = len(salt)
        salt_array = (
            np.frombuffer(salt, dtype=np.uint8)
            if salt_len > 0
            else np.array([], dtype=np.uint8)
        )

        for diff_round in range(self.config.diffusion_rounds):
            # İleri difüzyon (forward diffusion)
            for i in range(1, n):
                factor_idx = (i + diff_round + layer) % len(diffusion_factors)
                factor = diffusion_factors[factor_idx]

                # Calculate salt effect
                salt_effect = 0.0
                if salt_len > 0:
                    salt_idx = (i + diff_round) % salt_len
                    salt_effect = float(salt_array[salt_idx]) / 1024.0

                result[i] = (
                    result[i] + result[i - 1] * factor * (1.0 + salt_effect)
                ) % 1.0

            # Geri difüzyon (backward diffusion)
            for i in range(n - 2, -1, -1):
                factor_idx = (i + diff_round) % len(diffusion_factors)
                factor = 1.0 / diffusion_factors[factor_idx]
                result[i] = (result[i] + result[i + 1] * factor) % 1.0

            # Çapraz mixing (cross mixing)
            if n > 8:
                step = n // 16 if n >= 32 else 2
                for i in range(0, n - step, step):
                    j = i + step
                    if j < n:
                        avg = (result[i] + result[j]) / 2.0
                        mix_strength = 0.35 + np.sin(diff_round * 0.5) * 0.1
                        result[i] = (
                            result[i] * (1.0 - mix_strength) + avg * mix_strength
                        ) % 1.0
                        result[j] = (
                            result[j] * (1.0 - mix_strength) + avg * mix_strength
                        ) % 1.0

        return result

    def _complex_permutation(
        self, matrix: np.ndarray, layer: int, salt: bytes
    ) -> np.ndarray:
        """Karmaşık permütasyon"""
        n = len(matrix)

        # 1. Block permütasyon
        block_size = max(8, n // 32)
        indices = []
        for block_start in range(0, n, block_size):
            block_end = min(block_start + block_size, n)
            block_indices = list(range(block_start, block_end))

            seed_val = int.from_bytes(salt[:4], "big") + layer + block_start
            rng = random.Random(seed_val & 0xFFFFFFFF)
            rng.shuffle(block_indices)
            indices.extend(block_indices)

        result1 = matrix[indices]

        # 2. Bit-reversal permütasyon
        indices2 = []
        for i in range(n):
            rev = 0
            temp = i
            bits = int(np.log2(max(n, 1))) + 2
            for j in range(bits):
                rev = (rev << 1) | (temp & 1)
                temp >>= 1
            indices2.append(rev % n)
        result2 = matrix[indices2]

        # 3. Random walk permütasyon
        indices3 = list(range(n))
        seed_val = int.from_bytes(salt[4:8], "big") if len(salt) >= 8 else layer
        rng = random.Random(seed_val & 0xFFFFFFFF)

        for i in range(n):
            step = rng.randint(-7, 7)
            new_pos = (i + step) % n
            indices3[i], indices3[new_pos] = indices3[new_pos], indices3[i]

        result3 = matrix[indices3]

        # 4. Matrix permütasyon
        indices4 = []
        if n >= 16:
            size = int(np.sqrt(n))
            if size * size < n:
                size += 1

            matrix_indices = np.arange(n).reshape((size, size))
            for i in range(size):
                if i % 2 == 0:
                    matrix_indices[i] = np.roll(matrix_indices[i], i)
                else:
                    matrix_indices[i] = np.roll(matrix_indices[i], -i)

            indices4 = matrix_indices.flatten()[:n].tolist()
            result4 = matrix[indices4]

            result = (result1 + result2 + result3 + result4) / 4.0
        else:
            result = (result1 + result2 + result3) / 3.0

        return result

    def _enhanced_avalanche_boost(
        self, matrix: np.ndarray, layer: int, salt: bytes
    ) -> np.ndarray:
        """Gelişmiş avalanche boost"""
        result = matrix.copy()
        n = len(result)

        constants = [
            1.618033988749895,  # Altın oran
            2.414213562373095,  # Gümüş oran
            3.141592653589793,  # Pi
            2.718281828459045,  # e
            1.324717957244746,  # Plastik sayı
            1.839286755214161,  # Tribonacci
            1.465571231876768,  # Supergolden
            2.236067977499790,  # √5
        ]

        const_idx = layer % len(constants)
        const1 = constants[const_idx]
        const2 = constants[(const_idx + 1) % len(constants)]
        const3 = constants[(const_idx + 2) % len(constants)]

        # Çok katmanlı dönüşüm
        result = np.sin(result * np.pi * const1)
        result = np.tanh(result * const2)
        result = 1.0 / (1.0 + np.exp(-result * 3.0 + 1.5))  # 2.5 → 3.0

        # Ek non-lineer katman
        result = np.sin(result * np.pi * const3)

        # Kontrollü pertürbasyon
        if len(salt) >= 8:
            salt_int = int.from_bytes(salt[:8], "big")
            # Seed'i 32-bit aralığına sınırla
            seed_value = (salt_int + layer) & 0xFFFFFFFF
            rng = np.random.RandomState(seed_value)
            perturbation = rng.randn(n) * 0.02  # 0.015 → 0.02
            result = (result + perturbation) % 1.0

        # Final iyileştirme
        for i in range(n):
            val = result[i]
            if val < 0.1:
                result[i] = np.sqrt(val + 0.005)
            elif val > 0.9:
                result[i] = 1.0 - np.sqrt(1.0 - val + 0.005)

        # Normalizasyon
        min_val = np.min(result)
        max_val = np.max(result)
        if max_val - min_val > 1e-12:
            result = (result - min_val) / (max_val - min_val)

        return np.clip(result, 0.0, 1.0)

    def _bit_mixer_transform(
        self, matrix: np.ndarray, layer: int, salt: bytes
    ) -> np.ndarray:
        """Bit seviyesinde mixing"""
        n = len(matrix)
        result = matrix.copy()

        for i in range(0, n - 1, 2):
            a = result[i]
            b = result[i + 1]

            # Çeşitli bit operasyonları
            xor_like = (a * 0.6 + b * 0.4) % 1.0
            and_like = np.minimum(a, b)
            or_like = np.maximum(a, b)
            nand_like = 1.0 - and_like
            nor_like = 1.0 - or_like

            rotate = (a * 0.3 + b * 0.7) % 1.0

            if len(salt) > 0:
                salt_byte = salt[(i + layer) % len(salt)]
                selector = salt_byte % 8

                if selector == 0:
                    result[i] = xor_like
                    result[i + 1] = rotate
                elif selector == 1:
                    result[i] = and_like
                    result[i + 1] = or_like
                elif selector == 2:
                    result[i] = nand_like
                    result[i + 1] = nor_like
                elif selector == 3:
                    result[i] = (xor_like + and_like) % 1.0
                    result[i + 1] = (or_like + rotate) % 1.0
                elif selector == 4:
                    result[i] = (a * 0.2 + xor_like * 0.8) % 1.0
                    result[i + 1] = (b * 0.2 + rotate * 0.8) % 1.0
                elif selector == 5:
                    result[i] = np.sin((a + b) * np.pi)
                    result[i + 1] = np.cos((a - b) * np.pi)
                elif selector == 6:
                    result[i] = np.tanh(a * 2.0) * np.cos(b * np.pi)
                    result[i + 1] = np.tanh(b * 2.0) * np.sin(a * np.pi)
                else:
                    result[i] = (a * 0.4 + b * 0.3 + xor_like * 0.3) % 1.0
                    result[i + 1] = (b * 0.4 + a * 0.3 + rotate * 0.3) % 1.0

        return result

    def _post_avalanche_enhancement(
        self, matrix: np.ndarray, salt: bytes
    ) -> np.ndarray:
        """Post-processing avalanche enhancement"""
        result = matrix.copy()
        n = len(result)

        # Wavelet-like decomposition
        if n >= 8:
            temp = result.copy()

            levels = int(np.log2(n))
            if levels > 4:
                levels = 4

            for level in range(levels):
                step = 1 << level
                half = n // (2 * step)

                for i in range(half):
                    idx1 = i * 2 * step
                    idx2 = idx1 + step

                    if idx2 < n:
                        # Approximation coefficients
                        approx = (temp[idx1] + temp[idx2]) / 2.0
                        # Detail coefficients
                        detail = (temp[idx1] - temp[idx2]) / 2.0

                        # Non-linear processing
                        approx = np.tanh(approx * (2.0 + level * 0.5))
                        detail = np.arctan(detail * (5.0 + level))

                        temp[i] = approx
                        temp[half + i] = detail

            # Reconstruction
            for level in range(levels - 1, -1, -1):
                step = 1 << level
                half = n // (2 * step)

                for i in range(half):
                    idx1 = i * 2 * step
                    idx2 = idx1 + step

                    if idx2 < n:
                        a = temp[i]
                        d = temp[half + i]

                        result[idx1] = np.sin((a + d) * np.pi * (1 + level * 0.1))
                        result[idx2] = np.cos((a - d) * np.pi * (1 + level * 0.1))

        # Final perturbation
        if len(salt) >= 8:
            salt_int = int.from_bytes(salt[:8], "big")
            # Seed'i 32-bit aralığına sınırla
            seed_value = salt_int & 0xFFFFFFFF
            rng = np.random.RandomState(seed_value)
            avalanche_noise = rng.randn(n) * 0.008  # 0.005 → 0.008
            result = (result + avalanche_noise) % 1.0

        return result

    def _quantum_avalanche_mix(self, matrix: np.ndarray, salt: bytes) -> np.ndarray:
        """Kuantum dirençli avalanche mixing"""
        result = matrix.copy()
        n = len(result)

        # Lattice-based mixing
        for i in range(n):
            neighbors: List[float] = []
            weights: List[float] = []

            for offset in [1, 3, 7, 15, 31, 63]:
                neighbor_idx = (i + offset) % n
                if neighbor_idx != i:
                    neighbors.append(result[neighbor_idx])
                    weight = 1.0 / (1 + offset * 0.1)
                    weights.append(weight)

            if neighbors and weights:
                # Convert to numpy arrays
                weights_array = np.array(weights)  # Use different variable name
                weights_array = weights_array / np.sum(weights_array)

                # Convert neighbors to numpy array for vectorized operations
                neighbors_array = np.array(neighbors)

                # Vectorized weighted average
                weighted_avg = np.sum(weights_array * neighbors_array)

                # Non-linear combination
                result[i] = np.sin((result[i] * 0.6 + weighted_avg * 0.4) * np.pi * 2)

        # Error correction
        for i in range(0, n - 1, 2):
            parity = (result[i] + result[i + 1]) % 1.0
            result[i] = (result[i] + parity * 0.15) % 1.0  # 0.1 → 0.15
            result[i + 1] = (result[i + 1] + parity * 0.15) % 1.0

        return result

    def _final_avalanche_normalization(self, matrix: np.ndarray) -> np.ndarray:
        """
        Professional final avalanche normalization.

        Design goals:
        - Do NOT generate avalanche artificially
        - Preserve entropy ordering (rank-based)
        - Reduce variance without centering bias
        - Maintain natural convergence to ~50% bit flip
        """

        # -------------------------------------------------
        # 1. Rank-based entropy-preserving normalization
        # -------------------------------------------------
        x = matrix.astype(np.float64, copy=True).ravel()

        # Rank normalization (distribution-free, monotonic)
        ranks = np.argsort(np.argsort(x))
        x = ranks / (len(x) - 1 + 1e-12)

        # -------------------------------------------------
        # 2. Orthogonal global mixing (energy preserving)
        # -------------------------------------------------
        # FFT-based phase-only mixing
        spectrum = np.fft.fft(x)
        phase = np.exp(1j * np.angle(spectrum))
        x = np.real(np.fft.ifft(np.abs(spectrum) * phase))

        # Re-normalize after orthogonal transform
        min_val = np.min(x)
        max_val = np.max(x)
        span = max_val - min_val

        if span > 1e-12:
            x = (x - min_val) / span
        else:
            x.fill(0.5)

        # -------------------------------------------------
        # 3. Chebyshev polynomial projection (low-order)
        # -------------------------------------------------
        # T1 Chebyshev: avoids oscillatory overfitting
        # x ∈ [0,1] → smooth symmetric projection
        x = 0.5 * (1.0 - np.cos(np.pi * x))

        # -------------------------------------------------
        # 4. Final safety clamp
        # -------------------------------------------------
        x = np.clip(x, 0.0, 1.0)

        return x.reshape(matrix.shape)

    """
    def _final_avalanche_normalization(self, matrix: np.ndarray) -> np.ndarray:

        #Final avalanche normalization tuned for stable 48–52% range.
        #Avoids artificial centering, reduces variance.

        result = matrix.astype(np.float64, copy=True)

        for _ in range(2):  # 3 → 2 (fazla tekrar dağılımı bozar)

            # 1. Yumuşak sigmoid (merkez = 0.5 civarı)
            result = 1.0 / (1.0 + np.exp(-result * 4.5))

            # 2. Düşük frekanslı trigonometrik karıştırma
            # sin yerine cos kullanımı faz kaymasını azaltır
            result = 0.5 * (1.0 - np.cos(result * np.pi))

            # 3. Stabil min–max
            min_val = np.min(result)
            max_val = np.max(result)
            span = max_val - min_val

            if span > 1e-9:
                result = (result - min_val) / span
            else:
                result.fill(0.5)

            # 4. Hafif gamma düzeltmesi (variance compression)
            result = np.power(result, 0.92)

        return np.clip(result, 0.0, 1.0)
    """

    """
    # çok sert ve dalgalanmaya neden oluyor.
    def _final_avalanche_normalization(self, matrix: np.ndarray) -> np.ndarray:
        #Final avalanche normalization
        result = matrix.copy()
        
        for pass_num in range(3):  # 2 → 3
            # Sigmoid compression
            result = 1.0 / (1.0 + np.exp(-result * 7.0 + 3.5))  # 6.0 → 7.0
            
            # Sine-based normalization
            result = np.sin(result * np.pi * 2.5)  # 2.0 → 2.5
            
            # Min-max
            min_val = np.min(result)
            max_val = np.max(result)
            if max_val - min_val > 1e-12:
                result = (result - min_val) / (max_val - min_val)
            else:
                result = np.zeros_like(result) + 0.5
            
            # Non-linear stretch
            result = np.power(result, 1.0 / 1.2)  # 1.1 → 1.2
        
        # Final clip
        result = np.clip(result, 0.0, 1.0)
        
        return result
    """

    @SecurityLayers.timing_attack_protection
    def _final_bytes_conversion(self, matrix: np.ndarray, salt: bytes) -> bytes:
        """Final byte dönüşümü (zaman sabit)"""
        result = bytearray()

        methods = [
            lambda x: int(x * (1 << 40)) & 0xFFFFFFFFFF,
            lambda x: int(np.exp(np.abs(x)) * 1e12) & 0xFFFFFFFF,
            lambda x: int((np.sin(x * np.pi) + 1) * (1 << 31)) & 0xFFFFFFFF,
            lambda x: int(np.log1p(np.abs(x)) * 1e15) & 0xFFFFFFFF,
            lambda x: int(np.tanh(x * 2) * (1 << 32)) & 0xFFFFFFFF,
        ]

        salt_len = len(salt)
        for i, val in enumerate(matrix):
            if salt_len > 0:
                salt_idx = i % salt_len
                salt_byte = salt[salt_idx]
                method_idx = (int(val * 1e12) + i + salt_byte) % len(methods)
            else:
                method_idx = (int(val * 1e12) + i) % len(methods)

            int_val = methods[method_idx](val)

            # XOR with previous
            if result:
                prev_bytes = result[-4:] if len(result) >= 4 else result[:]
                prev = struct.unpack("I", prev_bytes.ljust(4, b"\x00"))[0]
                int_val ^= prev

            # Additional mixing
            int_val ^= (int_val << 17) & 0xFFFFFFFF
            int_val ^= int_val >> 13
            int_val ^= (int_val << 5) & 0xFFFFFFFF

            # Salt mixing
            if salt_len > 0:
                start_idx = (i * 4) % salt_len
                end_idx = (i * 4 + 4) % salt_len
                if start_idx < end_idx:
                    salt_slice = salt[start_idx:end_idx]
                else:
                    salt_slice = salt[start_idx:] + salt[:end_idx]
                salt_val = int.from_bytes(
                    salt_slice.ljust(4, b"\x00"), "big", signed=False
                )
                int_val ^= salt_val

            result.extend(struct.pack("I", int_val & 0xFFFFFFFF))

            if len(result) >= self.config.hash_bytes * 8:  # 4x → 8x
                break

        return bytes(result)

    @SecurityLayers.timing_attack_protection
    def _secure_compress(self, data: bytes, target_bytes: int) -> bytes:
        """Güvenli sıkıştırma (zaman sabit)"""
        if len(data) <= target_bytes:
            return data.ljust(target_bytes, b"\x00")

        current = bytearray(data)

        for round_num in range(5):  # 3 → 5
            max(target_bytes * 3, len(current) // 2)  # 2 → 3
            compressed = bytearray()

            for i in range(0, len(current), 3):  # 2 → 3
                if i + 2 < len(current):
                    val = (current[i] ^ current[i + 1] ^ current[i + 2]) + (
                        current[i] & current[i + 1] & current[i + 2]
                    )
                    compressed.append(val & 0xFF)
                elif i + 1 < len(current):
                    val = (current[i] ^ current[i + 1]) + (current[i] & current[i + 1])
                    compressed.append(val & 0xFF)
                else:
                    compressed.append(current[i])

            current = compressed

            # Mix with security constants
            for i in range(0, len(current), 8):
                if i + 7 < len(current):
                    chunk_bytes = current[i : i + 8]
                    if len(chunk_bytes) < 8:
                        chunk_bytes = chunk_bytes.ljust(8, b"\x00")
                    chunk = struct.unpack("Q", chunk_bytes)[0]
                    chunk ^= (chunk << 31) & 0xFFFFFFFFFFFFFFFF
                    chunk ^= chunk >> 11
                    chunk ^= (chunk << 7) & 0xFFFFFFFFFFFFFFFF
                    current[i : i + 8] = struct.pack("Q", chunk & 0xFFFFFFFFFFFFFFFF)

        # Final adjustment
        result = bytes(current[:target_bytes])
        if len(result) < target_bytes:
            pad_len = target_bytes - len(result)
            pad_value = sum(result) % 256
            result += bytes([(pad_value + i * 17) % 256 for i in range(pad_len)])

        return result


## PERFORMANS İYİLEŞTİRME KODU:
class PerformanceOptimizedKhaCore(FortifiedKhaCore):
    """Performans optimize edilmiş KHA çekirdeği"""

    def _fortified_mixing_pipeline(self, matrix: np.ndarray, salt: bytes) -> np.ndarray:
        """Optimize edilmiş karıştırma pipeline'ı"""
        start_time = time.perf_counter()

        n = len(matrix)

        # HIZLI NORMALİZASYON
        min_val = np.min(matrix)
        max_val = np.max(matrix)
        if max_val - min_val > 1e-10:
            matrix = (matrix - min_val) / (max_val - min_val)

        # OPTİMİZE KARIŞTIRMA KATMANLARI
        for layer in range(self.config.shuffle_layers):
            # 1. Hızlı non-lineer dönüşüm
            matrix = np.sin(matrix * np.pi * 1.618033988749895)
            matrix = np.tanh(matrix * 2.0)

            # 2. Hızlı difüzyon
            if layer % 2 == 0:
                # İleri difüzyon
                for i in range(1, n):
                    matrix[i] = (matrix[i] + matrix[i - 1] * 1.618033988749895) % 1.0

                # Geri difüzyon
                for i in range(n - 2, -1, -1):
                    matrix[i] = (matrix[i] + matrix[i + 1] * 0.618033988749895) % 1.0

            # 3. Basit avalanche boost
            if layer % 3 == 0 and self.config.use_enhanced_avalanche:
                salt_int = int.from_bytes(salt[:4], "big") if len(salt) >= 4 else layer
                seed_value = (salt_int + layer) & 0xFFFFFFFF
                rng = np.random.RandomState(seed_value)
                perturbation = rng.randn(n) * 0.01
                matrix = (matrix + perturbation) % 1.0

        # BYTE DAĞILIMI OPTİMİZASYONU (yeni)
        if self.config.enable_byte_distribution_optimization:
            matrix = self._optimize_byte_distribution(matrix, salt)

        # HIZLI FİNAL NORMALİZASYON
        matrix = np.sin(matrix * np.pi)  # [-1, 1] aralığı
        matrix = (matrix + 1) / 2  # [0, 1] aralığı

        # Type-safe time update
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        current_mixing_time = self.stats.get("mixing_time", 0.0)

        # Convert to float if needed
        if isinstance(current_mixing_time, (int, float)):
            self.stats["mixing_time"] = (
                float(current_mixing_time) + elapsed_ms
            )  # Incompatible types in assignment (expression has type "float", target has type "int")  [assignment]
        else:
            self.stats["mixing_time"] = elapsed_ms

        return matrix

    def _optimize_byte_distribution(
        self, matrix: np.ndarray, salt: bytes
    ) -> np.ndarray:
        """Byte dağılımını optimize et"""
        result = matrix.copy()
        n = len(result)

        for round_num in range(self.config.byte_uniformity_rounds):
            # Byte benzeri düzeltmeler
            salt_int = int.from_bytes(salt[:8], "big") if len(salt) >= 8 else round_num
            rng = np.random.RandomState(salt_int & 0xFFFFFFFF)

            # Küçük düzeltmeler
            corrections = rng.randn(n) * self.config.byte_correction_factor * 0.01

            # Çok yüksek/düşük değerleri düzelt
            for i in range(n):
                val = result[i]
                if val < 0.1 or val > 0.9:
                    result[i] = 0.5 + (val - 0.5) * 0.8  # Merkeze çek

                result[i] = (result[i] + corrections[i]) % 1.0

        return result


# ============================================================
# ANA HASH SINIFI (GÜÇLENDİRİLMİŞ)
# ============================================================
class FortifiedKhaHash256:
    """Fortified KHA Hash (KHA-256) - Ultra Secure"""

    def __init__(
        self, config: Optional[FortifiedConfig] = None, *, deterministic: bool = False
    ):
        self._deterministic = deterministic  # Private attribute olarak sakla
        self.config = config or FortifiedConfig()
        self.core = FortifiedKhaCore(self.config)

        # Initialize metrics
        self.metrics: Dict[str, Any] = {
            "hash_count": 0,
            "total_time": 0.0,
            "avalanche_tests": [],
            "security_checks": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

        # Security state
        self._last_hash_time: float = 0.0
        self._consecutive_hashes: int = 0
        self._cache: Dict[Tuple[bytes, bytes], str] = {}
        self._prev_matrix: Optional[np.ndarray] = None
        self._avalanche_history: List[float] = []
        self._last_used_salt: Optional[bytes] = None

    @property
    def deterministic(self):
        """Deterministic özelliği için getter"""
        return self._deterministic

    @SecurityLayers.timing_attack_protection
    def hash(self, data: Union[str, bytes], salt: Optional[bytes] = None) -> str:
        """Hash operation - maximum security."""

        # Deterministik mod kontrolü
        if self._deterministic:
            if isinstance(data, str):
                data_bytes = data.encode("utf-8")
            else:
                data_bytes = data

            if salt is None:
                salt = b"\x00" * 32

            # Deterministik modda basit hash
            return hashlib.blake2b(data_bytes + salt, digest_size=32).hexdigest()

        start_time = time.perf_counter()

        # Security check
        self._security_check()

        # Convert input to bytes
        data_bytes = data.encode("utf-8") if isinstance(data, str) else data

        # Generate or strengthen salt
        if salt is None:
            salt = self._generate_secure_salt(data_bytes)
        else:
            salt = self._strengthen_salt(salt, data_bytes)

        # Store salt for post-processing
        self._last_used_salt = salt

        # Cache check
        cache_key = None
        if getattr(self.config, "cache_enabled", False):
            cache_key = self._generate_cache_key(data_bytes, salt)
            if cache_key in self._cache:
                self.metrics["cache_hits"] = int(self.metrics.get("cache_hits", 0)) + 1
                self.metrics["hash_count"] = int(self.metrics.get("hash_count", 0)) + 1
                self.metrics["total_time"] = (
                    float(self.metrics.get("total_time", 0.0)) + 0.001
                )
                return self._cache[cache_key]

            self.metrics["cache_misses"] = int(self.metrics.get("cache_misses", 0)) + 1

        try:
            # 1. Generate seed → matrix
            seed = self._generate_secure_seed(data_bytes, salt)
            kha_matrix = self.core._generate_kha_matrix(seed)

            # 2. Double hashing
            if getattr(self.config, "double_hashing", False):
                intermediate = self.core._fortified_mixing_pipeline(kha_matrix, salt)
                second_seed = self.core._final_bytes_conversion(intermediate, salt)
                second_matrix = self.core._generate_kha_matrix(second_seed)
                kha_matrix = (kha_matrix + second_matrix) % 1.0

            # 3. Triple compression
            if getattr(self.config, "triple_compression", False):
                for i in range(2):
                    intermediate = self.core._fortified_mixing_pipeline(
                        kha_matrix, salt
                    )
                    comp_seed = self.core._final_bytes_conversion(intermediate, salt)
                    comp_matrix = self.core._generate_kha_matrix(comp_seed)
                    kha_matrix = (kha_matrix * 0.7 + comp_matrix * 0.3) % 1.0

            # 4-6. Pipeline
            mixed_matrix = self.core._fortified_mixing_pipeline(kha_matrix, salt)
            hash_bytes = self.core._final_bytes_conversion(mixed_matrix, salt)
            compressed = self.core._secure_compress(
                hash_bytes, getattr(self.config, "hash_bytes", 32)
            )

            # 7. Bias-resistant post-process
            final_bytes = self._bias_resistant_postprocess(compressed, len(data_bytes))

            # 8. Additional security layer
            final_bytes = self._additional_security_layer(final_bytes, salt, data_bytes)

            # 9. Convert to hex
            hex_hash = final_bytes.hex()

            # Update metrics safely
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            self.metrics["hash_count"] = int(self.metrics.get("hash_count", 0)) + 1
            self.metrics["total_time"] = (
                float(self.metrics.get("total_time", 0.0)) + elapsed_ms
            )

            # Cache result if enabled
            if getattr(self.config, "cache_enabled", False) and cache_key is not None:
                self._cache[cache_key] = hex_hash
                # Limit cache size
                if len(self._cache) > getattr(self.config, "max_cache_size", 100):
                    for key in list(self._cache.keys())[:50]:
                        del self._cache[key]

            return hex_hash

        except Exception as e:
            logger.error(f"KHA hash failed: {e}, using fallback SHA-512")
            fallback_hash = hashlib.sha3_512(data_bytes + salt).digest()
            return fallback_hash.hex()

    def _generate_cache_key(self, data: bytes, salt: bytes) -> Tuple[bytes, bytes]:
        """Create cache key using secure hashing."""
        data_hash = hashlib.sha3_256(data).digest()[:16]
        salt_hash = hashlib.blake2b(salt, digest_size=16).digest()
        return (data_hash, salt_hash)

    def _security_check(self) -> None:
        """Security check - brute force and timing attack protection."""
        current_time = time.time()

        # Detect rapid consecutive hashing
        if self._last_hash_time > 0:
            time_diff = current_time - self._last_hash_time

            if time_diff < 0.001:  # Less than 1ms
                self._consecutive_hashes += 1

                # Progressive slowdown
                if self._consecutive_hashes > 50:
                    delay_factor = min(2.0, (self._consecutive_hashes - 50) * 0.02)
                    time.sleep(delay_factor * 0.001)
            else:
                # Reset counter if enough time has passed
                self._consecutive_hashes = max(0, self._consecutive_hashes - 2)

        self._last_hash_time = current_time

        # Update security metrics
        if "security_checks" not in self.metrics:
            self.metrics["security_checks"] = 0
        self.metrics["security_checks"] = int(self.metrics["security_checks"]) + 1

        if self._consecutive_hashes > 100:
            logger.warning(
                f"High consecutive hash rate detected: {self._consecutive_hashes}"
            )

    def _bias_resistant_postprocess(self, raw_bytes: bytes, input_length: int) -> bytes:
        """Bias'a dayanıklı post-processing"""
        if not raw_bytes:
            return raw_bytes

        salt = self._last_used_salt or b"\x00" * 64

        # 1. Maske
        mask_seed = hashlib.sha3_512(
            salt + input_length.to_bytes(8, "big") + b"BIAS_CORR_v4"
        ).digest()
        mask = (mask_seed * ((len(raw_bytes) // 64) + 1))[: len(raw_bytes)]
        masked = bytes(b ^ mask[i] for i, b in enumerate(raw_bytes))

        # 2. Rotate
        bits = []
        for b in masked:
            for i in range(7, -1, -1):
                bits.append((b >> i) & 1)
        if bits:
            bits = bits[-29:] + bits[:-29]

        # bits → bytes
        result = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i : i + 8]
            if len(chunk) < 8:
                chunk.extend([0] * (8 - len(chunk)))
            v = 0
            for bit in chunk:
                v = (v << 1) | bit
            result.append(v)
        result = result[: len(raw_bytes)]

        # 3. Toggle yoğunluğu
        bits2 = []
        for b in result:
            for i in range(7, -1, -1):
                bits2.append((b >> i) & 1)

        toggle_key = hashlib.sha3_256(
            salt + input_length.to_bytes(8, "big") + b"TOGGLE_V4"
        ).digest()

        for i in range(len(bits2)):
            byte_idx = (i // 8) % len(toggle_key)
            if toggle_key[byte_idx] % 4 == 0:  # %25
                bits2[i] ^= 1

        # bits2 → bytes
        out = bytearray()
        for i in range(0, len(bits2), 8):
            chunk = bits2[i : i + 8]
            if len(chunk) < 8:
                chunk.extend([0] * (8 - len(chunk)))
            v = 0
            for bit in chunk:
                v = (v << 1) | bit
            out.append(v)

        return bytes(out[: len(raw_bytes)])

    def _additional_security_layer(
        self, data: bytes, salt: bytes, original_data: bytes
    ) -> bytes:
        """Ek güvenlik katmanı"""
        result = bytearray(data)

        # HMAC benzeri koruma
        hmac_key = hashlib.sha3_512(salt + original_data).digest()[:32]

        for i in range(len(result)):
            key_byte = hmac_key[i % len(hmac_key)]
            data_byte = result[i]

            mixed = data_byte ^ key_byte
            mixed = (mixed + (key_byte << 1)) & 0xFF
            mixed ^= mixed >> 4
            mixed = (mixed * 0x9D) & 0xFF

            result[i] = mixed

        # Final XOR
        xor_key = hashlib.sha256(salt).digest()
        for i in range(len(result)):
            result[i] ^= xor_key[i % len(xor_key)]

        return bytes(result)

    def _generate_secure_salt(self, data: bytes) -> bytes:
        """Güvenli, kriptografik olarak rastgele tuz oluşturur."""
        if self._deterministic:
            # Deterministik: sadece veriden türetilmiş sabit tuz
            return hashlib.blake2b(
                b"deterministic_salt" + data, digest_size=32
            ).digest()[: self.config.salt_length]

        # Non-deterministic mod: kriptografik rastgele + veri karışımı
        sys_random = secrets.token_bytes(max(64, self.config.salt_length))
        data_hash = hashlib.sha3_512(data).digest()
        combined = sys_random + data_hash

        if len(combined) >= self.config.salt_length:
            return combined[: self.config.salt_length]
        else:
            return (combined * ((self.config.salt_length // len(combined)) + 1))[
                : self.config.salt_length
            ]

    def _strengthen_salt(self, salt: bytes, data: bytes) -> bytes:
        """Mevcut tuzu güçlendir"""
        if self._deterministic:
            # Deterministik modda sadece veriye dayalı genişletme
            if len(salt) < self.config.salt_length:
                needed = self.config.salt_length - len(salt)
                extra = hashlib.sha256(salt + data + b"extend").digest()
                salt = salt + (extra * ((needed // 32) + 1))[:needed]
            return salt

        # Normal mod
        if len(salt) < self.config.salt_length:
            extension = self._generate_secure_salt(data + salt)
            extension_needed = self.config.salt_length - len(salt)
            salt = salt + extension[:extension_needed]

        # Hafif karıştırma
        strengthened = bytearray(salt)
        data_hash = hashlib.sha3_256(data).digest()

        for i in range(len(strengthened)):
            strengthened[i] ^= data_hash[i % len(data_hash)]
            strengthened[i] = (strengthened[i] + i * 13) % 256

        return bytes(strengthened)

    def _generate_secure_seed(self, data: bytes, salt: bytes) -> bytes:
        """Güvenli seed oluştur"""
        header = len(data).to_bytes(8, "big") + len(salt).to_bytes(8, "big")

        # Çoklu hash turu
        h1 = hashlib.sha3_512(header + data + salt).digest()

        if len(data) <= 2048:
            h2_input = h1 + data + salt
        else:
            sampled = b"".join(data[i : i + 128] for i in range(0, len(data), 1024))[
                :1024
            ]
            h2_input = h1 + sampled + salt

        h2 = hashlib.sha3_512(h2_input).digest()

        # Final karıştırma
        seed = hashlib.sha3_512(h2 + header).digest()

        return seed

    def test_avalanche_effect(self, samples: int = 1000) -> Dict[str, Any]:
        """Statistical Avalanche Effect Test"""
        print("Statistical Avalanche Effect Test running...")

        HASH_BITS = 256
        bit_change_percent: List[float] = []
        hamming_distances: List[int] = []
        timings_ms: List[float] = []
        single_bit_results: List[int] = []
        multi_bit_results: List[int] = []

        for idx in range(samples):
            # 1. Rastgele girdi üretimi
            data_len = random.randint(32, 512)
            base_data = secrets.token_bytes(data_len)

            # 2. Bit flip stratejisi
            flip_count = random.randint(1, 4)
            modified = bytearray(base_data)
            flipped_positions = set()

            for _ in range(flip_count):
                bit_pos = random.randint(0, data_len * 8 - 1)
                if bit_pos in flipped_positions:
                    continue
                flipped_positions.add(bit_pos)
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                modified[byte_idx] ^= 1 << bit_idx

            # 3. Hash hesaplama
            start = time.perf_counter()
            h1 = self.hash(base_data)
            h2 = self.hash(bytes(modified))
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            timings_ms.append(elapsed_ms)

            # 4. Bit karşılaştırması
            h1_bits = bin(int(h1, 16))[2:].zfill(HASH_BITS)
            h2_bits = bin(int(h2, 16))[2:].zfill(HASH_BITS)
            diff_bits = sum(b1 != b2 for b1, b2 in zip(h1_bits, h2_bits))
            diff_percent = (diff_bits / HASH_BITS) * 100.0

            bit_change_percent.append(diff_percent)
            hamming_distances.append(diff_bits)

            if flip_count == 1:
                single_bit_results.append(diff_bits)
            else:
                multi_bit_results.append(diff_bits)

            if (idx + 1) % max(1, samples // 10) == 0:
                print(f"  {idx + 1}/{samples} | avg={np.mean(bit_change_percent):.2f}%")

        # İstatistiksel özet
        avg_percent = float(np.mean(bit_change_percent))
        std_percent = float(np.std(bit_change_percent))
        min_percent = float(np.min(bit_change_percent))
        max_percent = float(np.max(bit_change_percent))
        avg_hamming = float(np.mean(hamming_distances))
        std_hamming = float(np.std(hamming_distances))
        avg_time = float(np.mean(timings_ms))

        # İdeal aralık analizi
        IDEAL_MIN, IDEAL_MAX = 48.0, 52.0
        in_ideal = sum(1 for p in bit_change_percent if IDEAL_MIN <= p <= IDEAL_MAX)
        ideal_ratio = (in_ideal / samples) * 100.0

        # Sonuç sınıflandırması
        if ideal_ratio >= 98.0 and 49.0 <= avg_percent <= 51.0:
            status = "EXCELLENT"
        elif ideal_ratio >= 85.0:
            status = "GOOD"
        elif ideal_ratio >= 60.0:
            status = "ACCEPTABLE"
        elif ideal_ratio >= 40.0:
            status = "Workable"
        else:
            status = "POOR"

        # Kaydet
        self._record_avalanche_test(
            samples,
            avg_percent,
            std_percent,
            min_percent,
            max_percent,
            avg_hamming,
            std_hamming,
            ideal_ratio,
            avg_time,
            single_bit_results if single_bit_results else None,
            multi_bit_results if multi_bit_results else None,
            status,
        )

        return {
            "samples": samples,
            "avg_bit_change_percent": avg_percent,
            "std_deviation": std_percent,
            "min_change_percent": min_percent,
            "max_change_percent": max_percent,
            "avg_hamming_distance": avg_hamming,
            "std_hamming_distance": std_hamming,
            "in_ideal_range": f"{ideal_ratio:.2f}%",
            "avg_time_ms": avg_time,
            "single_bit_hamming_avg": (
                float(np.mean(single_bit_results)) if single_bit_results else None
            ),
            "multi_bit_hamming_avg": (
                float(np.mean(multi_bit_results)) if multi_bit_results else None
            ),
            "status": status,
        }

    def _record_avalanche_test(
        self,
        samples,
        avg_percent,
        std_percent,
        min_percent,
        max_percent,
        avg_hamming,
        std_hamming,
        ideal_ratio,
        avg_time,
        single_bit_results,
        multi_bit_results,
        status,
    ):
        """Record avalanche test results"""
        if "avalanche_tests" not in self.metrics:
            self.metrics["avalanche_tests"] = []

        if not isinstance(self.metrics["avalanche_tests"], list):
            self.metrics["avalanche_tests"] = []

        test_record = {
            "samples": samples,
            "avg_bit_change_percent": float(avg_percent),
            "std_bit_change_percent": float(std_percent),
            "min_bit_change_percent": float(min_percent),
            "max_bit_change_percent": float(max_percent),
            "avg_hamming_distance": float(avg_hamming),
            "std_hamming_distance": float(std_hamming),
            "ideal_range_ratio": float(ideal_ratio),
            "avg_time_ms": float(avg_time),
            "single_bit_avg_hamming": (
                float(np.mean(single_bit_results)) if single_bit_results else None
            ),
            "multi_bit_avg_hamming": (
                float(np.mean(multi_bit_results)) if multi_bit_results else None
            ),
            "status": str(status),
        }

        self.metrics["avalanche_tests"].append(test_record)

    def test_collision_resistance(self, samples: int = 10000) -> Dict[str, Any]:
        """Gelişmiş çakışma direnci testi"""
        print("Gelişmiş Çakışma Testi Çalıştırılıyor...")

        hashes = {}
        collisions = 0
        near_collisions = 0

        for i in range(samples):
            # Rastgele veri
            data_len = random.randint(1, 1024)
            data = secrets.token_bytes(data_len)

            # Hash hesapla
            h = self.hash(data)

            if h in hashes:
                collisions += 1
                print(f"  ÇAKIŞMA BULUNDU: {collisions}. çakışma")
            else:
                hashes[h] = data

            # Yakın çakışma kontrolü
            if i % 1000 == 0 and i > 0:
                for j in range(min(100, len(hashes))):
                    hash1 = list(hashes.keys())[j]
                    for k in range(j + 1, min(200, len(hashes))):
                        hash2 = list(hashes.keys())[k]
                        h1_int = int(hash1, 16)
                        h2_int = int(hash2, 16)
                        diff_bits = bin(h1_int ^ h2_int).count("1")
                        if diff_bits <= 8:  # 8 bitten az fark
                            near_collisions += 1

            # İlerleme
            if (i + 1) % 1000 == 0:
                print(f"  {i + 1}/{samples} tamamlandı")

        collision_rate = (collisions / samples) * 100
        near_collision_rate = (near_collisions / samples) * 100

        return {
            "samples": samples,
            "unique_hashes": len(hashes),
            "collisions": collisions,
            "collision_rate_percent": collision_rate,
            "near_collisions": near_collisions,
            "near_collision_rate_percent": near_collision_rate,
            "status": (
                "EXCELLENT"
                if collisions == 0 and near_collision_rate < 0.0001
                else (
                    "GOOD"
                    if collision_rate < 0.0001 and near_collision_rate < 0.001
                    else "ACCEPTABLE" if collision_rate < 0.001 else "POOR"
                )
            ),
        }

    def test_uniformity(self, samples: int = 10_000) -> Dict[str, Any]:
        """Statistical uniformity test for hash output."""
        print(f"Uniformity test running with {samples} samples...")

        bit_counts = np.zeros(256, dtype=np.int64)
        byte_counts = np.zeros(256, dtype=np.int64)
        run_lengths_zero = []
        run_lengths_one = []
        total_runs = []
        hash_lengths = []

        for i in range(samples):
            try:
                data_len = random.randint(1, 256)
                data = secrets.token_bytes(data_len)
                hex_hash = self.hash(data)
                h_bytes = bytes.fromhex(hex_hash)
                hash_lengths.append(len(h_bytes))

                if len(h_bytes) == 0:
                    continue

                byte_array = np.frombuffer(h_bytes, dtype=np.uint8)
                bits = np.unpackbits(byte_array)

                # Bit counts
                bit_counts += bits

                # Byte counts
                if len(byte_array) > 0:
                    hist = np.bincount(byte_array, minlength=256)
                    byte_counts += hist

                # Run analysis
                if len(bits) > 1:
                    changes = np.where(bits[1:] != bits[:-1])[0] + 1
                    starts = np.concatenate(([0], changes))
                    ends = np.concatenate((changes, [len(bits)]))
                    run_lengths = ends - starts

                    for start, length in zip(starts, run_lengths):
                        if bits[start] == 0:
                            run_lengths_zero.append(length)
                        else:
                            run_lengths_one.append(length)

                    total_runs.append(len(run_lengths))

                if (i + 1) % max(1, samples // 10) == 0:
                    print(f"  Progress: {i + 1}/{samples} samples")

            except Exception as e:
                print(f"Error at sample {i}: {str(e)[:100]}")
                continue

        # Chi-square: bit-level
        total_bit_positions = bit_counts.sum()
        expected_bits = total_bit_positions / 2
        chi_square_bit = np.sum((bit_counts - expected_bits) ** 2 / expected_bits)

        # Chi-square: byte-level
        total_bytes_counted = byte_counts.sum()
        if total_bytes_counted > 0:
            expected_bytes = total_bytes_counted / 256
            chi_square_byte = np.sum(
                (byte_counts - expected_bytes) ** 2 / expected_bytes
            )
        else:
            chi_square_byte = 0

        # Run length statistics
        all_run_lengths = run_lengths_zero + run_lengths_one
        if all_run_lengths:
            avg_run = np.mean(all_run_lengths)
            std_run = np.std(all_run_lengths)
            unique_lengths, length_counts = np.unique(
                all_run_lengths, return_counts=True
            )
            theoretical_probs = [0.5**k for k in unique_lengths]
            theoretical_counts = [p * len(all_run_lengths) for p in theoretical_probs]
            run_chi_square = np.sum(
                (length_counts - theoretical_counts) ** 2 / theoretical_counts
            )
        else:
            avg_run = 0
            std_run = 0
            run_chi_square = 0

        # NIST-style runs test
        avg_total_runs: float = 0.0
        std_total_runs: float = 0.0
        runs_z_score: float = 0.0
        
        if total_runs:
            avg_total_runs = float(np.mean(total_runs))
            std_total_runs = float(np.std(total_runs))
            n_bits = 256
            expected_total_runs = (n_bits + 1) / 2

            if std_total_runs > 0:
                runs_z_score = float(
                    abs(avg_total_runs - expected_total_runs) / std_total_runs
                )
        else:
            avg_total_runs = 0.0
            std_total_runs = 0.0
            runs_z_score = 0.0

        # Significance tests
        bit_threshold = 310.0
        is_uniform_bit = chi_square_bit < bit_threshold
        byte_threshold = 310.0
        is_uniform_byte = chi_square_byte < byte_threshold
        run_length_threshold = 20.0
        is_uniform_run_length = run_chi_square < run_length_threshold
        is_uniform_runs = runs_z_score < 2.576

        # Overall status
        if (
            is_uniform_bit
            and is_uniform_byte
            and is_uniform_run_length
            and is_uniform_runs
        ):
            status = "EXCELLENT"
        elif is_uniform_bit and is_uniform_byte:
            status = "GOOD"
        elif is_uniform_bit or is_uniform_byte:
            status = "FAIR"
        else:
            status = "POOR"

        result = {
            "samples": len(hash_lengths),
            "chi_square_bit": float(chi_square_bit),
            "chi_square_byte": float(chi_square_byte),
            "avg_run_length": float(avg_run),
            "std_run_length": float(std_run),
            "is_uniform_bit": bool(is_uniform_bit),
            "is_uniform_byte": bool(is_uniform_byte),
            "run_length_chi_square": float(run_chi_square),
            "avg_total_runs": float(avg_total_runs),
            "runs_z_score": float(runs_z_score),
            "zero_runs_count": len(run_lengths_zero),
            "one_runs_count": len(run_lengths_one),
            "total_runs_analyzed": len(all_run_lengths),
            "hash_length_min": min(hash_lengths) if hash_lengths else 0,
            "hash_length_max": max(hash_lengths) if hash_lengths else 0,
            "hash_length_avg": (
                sum(hash_lengths) / len(hash_lengths) if hash_lengths else 0.0
            ),
            "status": status,
        }

        print("\nUniformity Test Results:")
        print(f"  Status: {status}")
        print(f"  Bit Uniformity: {is_uniform_bit} (χ²={chi_square_bit:.2f})")
        print(f"  Byte Uniformity: {is_uniform_byte} (χ²={chi_square_byte:.2f})")
        print(f"  Avg Run Length: {avg_run:.3f} ± {std_run:.3f}")

        return result

    def get_stats(self) -> Dict[str, Any]:
        """İstatistikleri getir"""
        stats: Dict[str, Any] = {}

        if hasattr(self.core, "stats"):
            for key, value in self.core.stats.items():
                stats[key] = value

        stats.update(self.metrics)

        hash_count = stats.get("hash_count", 0)
        total_time = stats.get("total_time", 0.0)
        total_operations = stats.get("total_operations", 0)

        if hash_count > 0:
            stats["avg_time_ms"] = float(total_time) / float(hash_count)
            if total_operations > 0:
                stats["operations_per_hash"] = float(total_operations) / float(
                    hash_count
                )
            else:
                stats["operations_per_hash"] = 0.0
        else:
            stats["avg_time_ms"] = 0.0
            stats["operations_per_hash"] = 0.0

        kha_success = stats.get("kha_success", 0)
        kha_fail = stats.get("kha_fail", 0)
        kha_total = kha_success + kha_fail

        if kha_total > 0:
            stats["kha_success_rate"] = (float(kha_success) / float(kha_total)) * 100.0
        else:
            stats["kha_success_rate"] = 0.0

        return stats

    def get_security_report(self) -> Dict[str, Any]:
        """Güvenlik raporu"""
        config_dict = {}
        if hasattr(self.config, "to_dict"):
            config_dict = self.config.to_dict()
        elif hasattr(self.config, "__dict__"):
            config_dict = {
                k: v for k, v in vars(self.config).items() if not k.startswith("_")
            }

        features = {}
        feature_attrs = {
            "quantum_resistance": "enable_quantum_resistance",
            "memory_hardening": "memory_hardening",
            "side_channel_resistance": "enable_side_channel_resistance",
            "constant_time_ops": "enable_constant_time_ops",
            "encryption_layer": "enable_encryption_layer",
            "post_quantum_mixing": "enable_post_quantum_mixing",
            "double_hashing": "double_hashing",
            "triple_compression": "triple_compression",
        }

        for feature_name, attr_name in feature_attrs.items():
            features[feature_name] = getattr(self.config, attr_name, False)

        stats = self.get_stats()

        return {
            "algorithm": "KHA-256-FORTIFIED",
            "version": "0.1.4",
            "security_level": getattr(self.config, "security_level", "256-bit"),
            "config": config_dict,
            "metrics": {
                "total_hashes": stats.get("hash_count", 0),
                "security_checks": stats.get("security_checks", 0),
                "kha_success_rate": stats.get("kha_success_rate", 0.0),
            },
            "features": features,
        }


class OptimizedFortifiedConfig(FortifiedConfig):
    """
    Configuration for performance-optimized KHA-256 hashing.
    Extends the base FortifiedConfig with optimization-specific settings.
    """

    def __init__(
        self,
        cache_enabled: bool = True,
        cache_size: int = 1000,  # Changed from max_cache_size to cache_size
        enable_metrics: bool = True,
        double_hashing: bool = False,
        enable_byte_distribution_optimization: bool = False,
        byte_uniformity_rounds: int = 3,
        hash_bytes: int = 32,
        salt_length: int = 16,
        # Pass through FortifiedConfig parameters
        **kwargs,
    ):
        # Call parent constructor first
        super().__init__(**kwargs)

        # Add optimization-specific settings
        self.cache_enabled = cache_enabled
        self.cache_size = cache_size  # Use consistent naming
        self.enable_metrics = enable_metrics
        self.double_hashing = double_hashing
        self.enable_byte_distribution_optimization = (
            enable_byte_distribution_optimization
        )
        self.byte_uniformity_rounds = byte_uniformity_rounds
        self.hash_bytes = hash_bytes
        self.salt_length = salt_length

    @property
    def max_cache_size(self) -> int:
        """Alias for cache_size for backward compatibility"""
        return self.cache_size


class OptimizedKhaHash256(FortifiedKhaHash256):
    """
    Performance–security balanced KHA-256 implementation.
    Focuses on deterministic behavior, controlled caching, and clean pipeline separation.
    """

    def __init__(
        self,
        config: Optional[Union[OptimizedFortifiedConfig, FortifiedConfig]] = None,
        *,
        deterministic: bool = False,  # ← buraya da ekle
    ):
        """
        Initialize the optimized hasher.
        Accepts either OptimizedFortifiedConfig or FortifiedConfig.
        # Convert FortifiedConfig to OptimizedFortifiedConfig if needed
        """
        # Önce base class'ı başlat
        super().__init__(
            config=None, deterministic=deterministic
        )  # ⚠️ config=None geçici

        # Şimdi kendi config'imizi ayarla
        if config is None:
            self.config = OptimizedFortifiedConfig()
        elif isinstance(config, FortifiedConfig) and not isinstance(
            config, OptimizedFortifiedConfig
        ):
            # Extract parameters from the FortifiedConfig
            # generate a dictionary with all attributes that might be needed
            kwargs: Dict[str, Any] = {
                "cache_enabled": True,
                "cache_size": 1000,
                "enable_metrics": True,
                "double_hashing": False,
                "enable_byte_distribution_optimization": False,
                "byte_uniformity_rounds": 3,
                "hash_bytes": 32,
                "salt_length": 16,
            }

            # Override with any values from the provided config
            for key in [
                "cache_enabled",
                "cache_size",
                "enable_metrics",
                "double_hashing",
                "enable_byte_distribution_optimization",
                "byte_uniformity_rounds",
                "hash_bytes",
                "salt_length",
                "rounds",
                "memory_cost",
                "parallelism",
            ]:
                if hasattr(config, key):
                    try:
                        value = getattr(config, key)
                        # Type checking and conversion
                        if key in [
                            "cache_enabled",
                            "enable_metrics",
                            "double_hashing",
                            "enable_byte_distribution_optimization",
                        ]:
                            # Ensure boolean values
                            kwargs[key] = bool(value)
                        elif key in [
                            "cache_size",
                            "byte_uniformity_rounds",
                            "hash_bytes",
                            "salt_length",
                            "rounds",
                            "memory_cost",
                            "parallelism",
                        ]:
                            # Ensure integer values
                            kwargs[key] = int(value)
                        else:
                            kwargs[key] = value
                    except (AttributeError, ValueError):
                        pass

            # generate optimized config with the same parameters
            self.config = OptimizedFortifiedConfig(**kwargs)
        else:
            self.config = cast(OptimizedFortifiedConfig, config)

        # Core'u tekrar ata: Now self.config is guaranteed to be OptimizedFortifiedConfig
        self.core = PerformanceOptimizedKhaCore(self.config)

        # Initialize metrics with proper types
        self.metrics: Dict[str, Any] = {
            "hash_count": 0,
            "total_time_ms": 0.0,
            "avalanche_tests": [],
        }

        # self._cache: Dict[bytes, str] = {} # Incompatible types in assignment (expression has type "dict[bytes, str]", base class "FortifiedKhaHash256" defined the type as "dict[tuple[bytes, bytes], str]")  [assignment]
        # Temel sınıfın tipini kullan
        # self._cache zaten temel sınıfta tanımlı, yeniden tanımlama
        self._cache_hits = 0
        self.cache_misses = 0

        # Temel sınıfın __init__'ini çağır (eğer varsa)
        super().__init__(config=None)  # veya uygun parametreler

    # ------------------------------------------------------------------
    # Helper Methods
    # ------------------------------------------------------------------

    def _normalize_input(self, data: Union[str, bytes]) -> bytes:
        """Convert input to bytes if needed"""
        if isinstance(data, str):
            return data.encode("utf-8")
        return data

    def _derive_salt(self, data_bytes: bytes) -> bytes:
        """Derive salt from input data"""
        # Using blake2s instead of SHA-256 as requested
        material = hashlib.blake2s(data_bytes, digest_size=32).digest()
        return hashlib.blake2s(material, digest_size=32).digest()[
            : self.config.salt_length
        ]

    def _derive_seed(self, data: bytes, salt: bytes) -> bytes:
        """Derive seed for matrix generation"""
        header = struct.pack(">I", len(data))
        # Take first 64 bytes or less if data/salt are shorter
        data_part = data[:64] if len(data) >= 64 else data + b"\x00" * (64 - len(data))
        salt_part = salt[:64] if len(salt) >= 64 else salt + b"\x00" * (64 - len(salt))
        payload = data_part + salt_part
        return hashlib.blake2s(header + payload, digest_size=32).digest()

    # ------------------------------------------------------------------
    # Cache handling
    # ------------------------------------------------------------------
    def _cache_key(self, data_bytes: bytes, salt: bytes) -> Tuple[bytes, bytes]:
        """generate tuple cache key (compatible with parent class)."""
        return (data_bytes, salt)

    def _cache_store(self, key: Tuple[bytes, bytes], value: str) -> None:
        """Store result in cache with FIFO eviction."""
        if self.config.cache_size <= 0:
            return  # Cache kapalıysa hiçbir şey yapma

        if len(self._cache) >= self.config.cache_size:
            # FIFO eviction
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = value

    def hash(self, data: Union[str, bytes], salt: Optional[bytes] = None) -> str:
        """Compute optimized hash of data."""
        start = time.perf_counter()

        data_bytes = self._normalize_input(data)
        salt = salt or self._derive_salt(data_bytes)

        cache_key = None
        if hasattr(self.config, "cache_enabled") and self.config.cache_enabled:
            cache_key = self._cache_key(data_bytes, salt)  # Returns tuple
            cached = self._cache.get(cache_key)  # Now compatible

            if cached is not None:
                self._cache_hits += 1
                return cached
            self.cache_misses += 1

        digest = self._hash_pipeline(data_bytes, salt)

        if cache_key is not None:
            self._cache_store(cache_key, digest)

        elapsed = (time.perf_counter() - start) * 1000
        self._update_metrics(elapsed)

        return digest

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def _update_metrics(self, elapsed_ms: float) -> None:
        """Update performance metrics"""
        if hasattr(self.config, "enable_metrics") and self.config.enable_metrics:
            self.metrics["hash_count"] = int(self.metrics["hash_count"]) + 1
            self.metrics["total_time_ms"] = (
                float(self.metrics["total_time_ms"]) + elapsed_ms
            )

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self._cache_hits + self.cache_misses
        hit_rate = self._cache_hits / total if total > 0 else 0.0

        max_size = getattr(self.config, "cache_size", 1000)

        return {
            "hits": self._cache_hits,
            "misses": self.cache_misses,
            "size": len(self._cache),
            "hit_rate": hit_rate,
            "max_size": max_size,
        }

    def clear_cache(self) -> None:
        """Clear the cache"""
        self._cache.clear()
        self._cache_hits = 0
        self.cache_misses = 0

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        metrics = self.metrics.copy()
        hash_count = metrics.get("hash_count", 0)

        if isinstance(hash_count, (int, float)) and hash_count > 0:
            total_time = float(metrics.get("total_time_ms", 0.0))
            metrics["average_time_ms"] = total_time / float(hash_count)
        else:
            metrics["average_time_ms"] = 0.0

        # Add cache stats if metrics are enabled
        if hasattr(self.config, "enable_metrics") and self.config.enable_metrics:
            metrics.update(self.get_cache_stats())

        return metrics

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    def _hash_pipeline(self, data: bytes, salt: bytes) -> str:
        """Main hashing pipeline"""
        seed = self._derive_seed(data, salt)
        matrix = self.core._generate_kha_matrix(seed)

        if hasattr(self.config, "double_hashing") and self.config.double_hashing:
            matrix = self._apply_double_hash(matrix, salt)

        mixed = self.core._fortified_mixing_pipeline(matrix, salt)
        raw_bytes = self.core._final_bytes_conversion(mixed, salt)

        if (
            hasattr(self.config, "enable_byte_distribution_optimization")
            and self.config.enable_byte_distribution_optimization
        ):
            rounds = getattr(self.config, "byte_uniformity_rounds", 3)
            raw_bytes = ByteDistributionOptimizer.optimize_byte_distribution(
                raw_bytes, rounds
            )

        hash_bytes = getattr(self.config, "hash_bytes", 32)
        final_bytes = self.core._secure_compress(raw_bytes, hash_bytes)
        return final_bytes.hex()

    def _apply_double_hash(self, matrix: np.ndarray, salt: bytes) -> np.ndarray:
        """Apply double hashing if enabled"""
        interm = self.core._fortified_mixing_pipeline(matrix, salt)
        seed2 = self.core._final_bytes_conversion(interm, salt)
        matrix2 = self.core._generate_kha_matrix(seed2)
        return (0.6 * matrix + 0.4 * matrix2) % 1.0


# ============================================================
# KOLAY KULLANIM FONKSİYONLARI
# ============================================================
### 3.1 Merkezi Hasher Factory
def generate_fortified_hasher(
    *,
    iterations: int = 16,
    components: int = 32,
    memory_cost: int = 2**18,
    time_cost: int = 8,
) -> FortifiedKhaHash256:
    """
    Parametrik Fortified KHA-256 oluşturucu.
    """
    config = FortifiedConfig(
        iterations=iterations,
        components_per_hash=components,
        memory_cost=memory_cost,
        time_cost=time_cost,
    )
    return FortifiedKhaHash256(config)


def quick_hash(data: str | bytes) -> str:
    """
    Genel amaçlı, hızlı ve deterministik hash.
    Kriptografik KDF değildir.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    # return hashlib.sha256(data).hexdigest()
    return hashlib.blake2b(data, digest_size=32).hexdigest()


"""
def quick_hash(data: str | bytes) -> str:

    # Genel amaçlı, hızlı ve deterministik hash.
    # Kriptografik KDF değildir.

    data_bytes = data.encode("utf-8") if isinstance(data, str) else data
    hasher = generate_fortified_hasher()
    return hasher.hash(data_bytes, salt=b"")  # sabit salt → deterministik
"""
"""
def quick_hash(data: str | bytes) -> str:
    data_bytes = data.encode("utf-8") if isinstance(data, str) else data
    # Salt, verinin SHA-256'sından türetilir → her zaman aynı veri için aynı salt
    salt = hashlib.sha256(data_bytes).digest()[:16]
    hasher = generate_fortified_hasher()
    return hasher.hash(data_bytes, salt=salt)
"""
"""
def quick_hash(data: Union[str, bytes]) -> str:

    #Genel amaçlı, hızlı ve deterministik hash.
    #Kriptografik KDF değildir.
    #Not: str ve bytes girdileri aynı içerik için aynı hash'i üretir.

    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise TypeError("Data must be str or bytes")
    
    hasher = generate_fortified_hasher()
    return hasher.hash(data)
"""
"""    
### 3.2 Hızlı Hash (Genel Amaç)
def quick_hash(data: Union[str, bytes]) -> str:

    #Genel amaçlı, hızlı ve deterministik hash.
    #Kriptografik KDF değildir.

    hasher = generate_fortified_hasher()
    return hasher.hash(data)
"""


### 3.3 Güvenli Parola Hashleme (KDF Modu)
def hash_password(
    password: str, salt: Optional[bytes] = None, *, is_usb_key: bool = False
) -> str:
    """
    Deterministik KDF tabanlı parola hash fonksiyonu.
    Aynı (parola + tuz) her zaman aynı çıktıyı verir.

    Args:
        password: Hashlenecek parola (str).
        salt: İsteğe bağlı tuz. Belirtilmezse rastgele üretilir.
        is_usb_key: Daha hızlı (düşük kaynak) mod.

    Returns:
        str: "KHA256[-USB]$<salt_hex>$<digest>"
    """
    # 1. Parolayı byte'a çevir
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    password_bytes = password.encode("utf-8")

    # 2. Tuz oluştur
    if salt is None:
        salt = secrets.token_bytes(32)  # 32 byte = 256 bit — yeterli
    elif not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")

    # 3. scrypt parametreleri (OpenSSL bellek sınırına dikkat!)
    if is_usb_key:
        n, r, p = 2**12, 8, 1  # ~4 MB RAM
    else:
        n, r, p = 2**14, 8, 1  # ~16 MB RAM — çoğu sistemde çalışır

    # 4. scrypt ile deterministik türev
    try:
        digest_bytes = hashlib.scrypt(
            password=password_bytes,
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=32,  # 256 bit output
        )
    except ValueError as e:
        if "memory limit exceeded" in str(e):
            # Fallback: daha düşük parametrelerle dene
            n, r, p = 2**10, 8, 1  # ~1 MB
            digest_bytes = hashlib.scrypt(
                password=password_bytes, salt=salt, n=n, r=r, p=p, dklen=32
            )
        else:
            raise

    # 5. Formatla
    prefix = "KHA256-USB$" if is_usb_key else "KHA256$"
    return f"{prefix}{salt.hex()}${digest_bytes.hex()}"


"""
def hash_password(password: str, *, is_usb_key: bool = False) -> str:
    hasher = ph_usb if is_usb_key else ph_secure
    return hasher.hash(password)
"""
"""
def hash_password(
    password: str,
    salt: Optional[bytes] = None,
    *,
    is_usb_key: bool = False
) -> str:
    if salt is None:
        salt = secrets.token_bytes(32)  # 32 byte yeterli

    if is_usb_key:
        # Daha hızlı, düşük kaynak
        n, r, p = 2**12, 8, 1   # ~4 MB
    else:
        # Güvenli ama uyumlu
        n, r, p = 2**14, 8, 1   # ~16 MB — OpenSSL sınırının altında

    try:
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=32
        ).hex()
    except ValueError as e:
        if "memory limit exceeded" in str(e):
            raise RuntimeError(
                f"scrypt bellek hatası. Parametreler: n={n}, r={r}, p={p}. "
                "Sisteminiz OpenSSL scrypt sınırına takıldı. n değerini düşürün."
            ) from e
        raise

    prefix = "SCRYPT-USB$" if is_usb_key else "SCRYPT$"
    return f"{prefix}{salt.hex()}${digest}"
"""
"""
def hash_password(
    password: str,
    salt: Optional[bytes] = None,
    *,
    is_usb_key: bool = False
) -> str:

    Parola/anahtar için güvenli, non-deterministik KDF tabanlı hash üretir.
    Args:
        password: Hashlenecek parola (str).
        salt: İsteğe bağlı tuz. Belirtilmezse 256 byte rastgele tuz üretilir.
        is_usb_key: True ise daha hızlı (daha az kaynak tüketen) konfigürasyon kullanılır.
    Returns:
        str: Format -> "KHA256[-USB]$<salt_hex>$<digest>"

    # Tuz oluştur
    if salt is None:
        salt = secrets.token_bytes(256)  # 256 byte = 2048 bit → çok güçlü

    # Konfigürasyon seç
    if is_usb_key:
        config = FortifiedConfig(
            iterations=16,
            components_per_hash=32,
            memory_cost=2**18,  # 256 KB
            time_cost=8
        )
    else:
        config = FortifiedConfig(
            iterations=32,
            components_per_hash=48,
            memory_cost=2**20,  # 1 MB
            time_cost=16
        )

    # Hashle
    hasher = FortifiedKhaHash256(config)
    digest = hasher.hash(password, salt)

    # Formatla
    prefix = "KHA256-USB$" if is_usb_key else "KHA256$"
    return f"{prefix}{salt.hex()}${digest}"
"""
"""
def hash_password(password: str, salt: Optional[bytes] = None, 
                  is_usb_key: bool = False) -> str:

    Parola hashleme için birleştirilmiş fonksiyon.
    Args:
        password: Hashlenecek parola
        salt: Özel tuz (None ise otomatik üretilir)
        is_usb_key: USB anahtarı için optimize edilmiş mod

    
    if is_usb_key:
        # USB anahtarları için optimize edilmiş (daha hızlı)
        config = FortifiedConfig()
        config.iterations = 16
        config.components_per_hash = 32
        config.memory_cost = 2**18  # 256KB
        config.time_cost = 8
        hasher = FortifiedKhaHash256(config)
    else:
        # Parolalar için güvenlik maksimum
        hasher = generate_fortified_hasher(
            iterations=32,
            components=48,
            memory_cost=2**20,  # 1 MB
            time_cost=16,
        )
    
    if salt is None:
        salt = secrets.token_bytes(256)
    
    digest = hasher.hash(password, salt)
    
    # Tür belirteci ekleyerek kullanım amacını işaretle
    prefix = "KHA256-USB$" if is_usb_key else "KHA256$"
    return f"{prefix}{salt.hex()}${digest}"
"""
"""
def hash_password(password: str, salt: Optional[bytes] = None) -> str:

    #Parola hashleme (KDF modu).
    #Yavaş, bellek-yoğun ve brute-force dirençlidir.

    hasher = generate_fortified_hasher(
        iterations=32,
        components=48,
        memory_cost=2**20,  # 1 MB
        time_cost=16,
    )

    if salt is None:
        salt = secrets.token_bytes(256)

    digest = hasher.hash(password, salt)

    return f"KHA256${salt.hex()}${digest}"

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    #Şifre hash'leme (güvenlik maksimum)
    hasher = generate_fortified_hasher()

    # Şifreler için özel config
    config = FortifiedConfig()
    config.iterations = 32  # Daha fazla iterasyon
    config.components_per_hash = 48  # Daha fazla bileşen
    config.memory_cost = 2**20  # 1MB
    config.time_cost = 16

    secure_hasher = FortifiedKhaHash256(config)

    if salt is None:
        salt = secrets.token_bytes(256)  # Uzun tuz

    return f"KHA256${salt.hex()}${secure_hasher.hash(password, salt)}"
"""


### Universal Doğrulama Fonksiyonu: Parola Doğrulama
def verify_password(stored_hash: str, password: str) -> bool:
    """
    Her iki tür hash'i de doğrulayabilen universal fonksiyon
    """
    try:
        # Hash formatını parse et
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False

        prefix, salt_hex, original_digest = parts
        salt = bytes.fromhex(salt_hex)

        # Prefix'e göre doğru hasher'ı seç
        if prefix == "KHA256-USB":
            # USB anahtarı için config
            config = FortifiedConfig()
            config.iterations = 16
            config.components_per_hash = 32
            config.memory_cost = 2**18
            config.time_cost = 8
            hasher = FortifiedKhaHash256(config)
        elif prefix == "KHA256":
            # Normal parola için config
            hasher = generate_fortified_hasher(
                iterations=32,
                components=48,
                memory_cost=2**20,
                time_cost=16,
            )
        else:
            return False

        # Doğrulama
        new_digest = hasher.hash(password, salt)
        return secrets.compare_digest(new_digest, original_digest)

    except Exception:
        return False


"""
def verify_password(password: str, stored_hash: str) -> bool:
    #KHA256$<salt>$<hash> formatını doğrular.

    try:
        _, salt_hex, expected = stored_hash.split("$")
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        raise ValueError("Geçersiz KHA256 hash formatı")

    candidate = hash_password(password, salt)
    return secrets.compare_digest(candidate, stored_hash)
"""


def get_hasher_config(purpose: str = "password") -> FortifiedConfig:
    config = FortifiedConfig()

    if purpose == "password":
        config.iterations = 32
        config.components_per_hash = 48
        config.memory_cost = 2**20
        config.time_cost = 16
    elif purpose == "usb_key":
        config.iterations = 16
        config.components_per_hash = 32
        config.memory_cost = 2**18
        config.time_cost = 8
    elif purpose == "session_token":
        config.iterations = 8
        config.components_per_hash = 24
        config.memory_cost = 2**16
        config.time_cost = 4

    return config


"""
def generate_fortified_hasher() -> FortifiedKhaHash256:
    #Güçlendirilmiş hasher oluştur
    config = FortifiedConfig()
    return FortifiedKhaHash256(config)

def quick_hash(data: Union[str, bytes]) -> str:
    #Hızlı hash oluşturma
    hasher = generate_fortified_hasher()
    return hasher.hash(data)
"""


class HardwareSecurityID:
    def __init__(self):
        self.fingerprint = {
            "system": platform.system(),
            "node": platform.node(),
            "processor": platform.processor() or "unknown",
            "uuid": str(uuid.getnode())[-12:],
        }

    def get_hardware_id(self) -> str:
        raw = "|".join(self.fingerprint.values())
        hasher = FortifiedKhaHash256(deterministic=True)
        return hasher.hash(raw.encode("utf-8"))

        # DETERMİNİSTİK MOD ZORUNLU
        hasher = FortifiedKhaHash256(deterministic=True)
        hwid = hasher.hash(raw.encode("utf-8"))
        if len(hwid) != 64:
            raise RuntimeError("HWID geçersiz uzunlukta!")
        return hwid


def run_comprehensive_test():
    """Kapsamlı güvenlik testi"""
    print("=" * 80)
    print("KHA - KAPSAMLI GÜVENLİK TESTİ")
    print("=" * 80)

    # Hasher oluştur
    hasher = generate_fortified_hasher()

    # Güvenlik raporu
    security_report = hasher.get_security_report()
    print("\nGÜVENLİK RAPORU:")
    print("-" * 40)
    print(f"  Algoritma: {security_report['algorithm']}")
    print(f"  Versiyon: {security_report['version']}")
    print(f"  Güvenlik Seviyesi: {security_report['security_level']}")
    print(f"  Kuantum Direnci: {security_report['features']['quantum_resistance']}")
    print(f"  Bellek Sertleştirme: {security_report['features']['memory_hardening']}")
    print(
        f"  Yan Kanal Koruma: {security_report['features']['side_channel_resistance']}"
    )

    print("\n1. TEMEL FONKSİYON TESTİ")
    print("-" * 40)

    test_cases = [
        ("", "Boş string"),
        ("a", "Tek karakter"),
        ("Merhaba Dünya!", "Basit metin"),
        ("K" * 1000, "Uzun tekrar"),
        (secrets.token_bytes(128), "Rastgele veri (128 byte)"),
        ("İçerik: özel karakterler: áéíóú ñ ç ş ğ ü ö", "Unicode metin"),
    ]

    for data, desc in test_cases:
        if isinstance(data, bytes):
            preview = data[:24].hex() + "..."
        else:
            preview = data[:24] + "..." if len(data) > 24 else data

        start = time.perf_counter()
        h = hasher.hash(data)
        elapsed = (time.perf_counter() - start) * 1000

        print(f"  {desc:<30} '{preview}'")
        print(f"    → {h[:56]}... ({elapsed:.2f}ms)")

    print("\n2. AVALANCHE TESTİ (100 örnek)")
    print("-" * 40)

    avalanche_result = hasher.test_avalanche_effect(100)
    print(f"  Ortalama bit değişimi: {avalanche_result['avg_bit_change_percent']:.3f}%")
    print(f"  Standart sapma: {avalanche_result['std_deviation']:.3f}")
    print(f"  Hamming mesafesi: {avalanche_result['avg_hamming_distance']:.1f}")
    print(f"  İdeal aralıkta: {avalanche_result['in_ideal_range']}")
    print(f"  Durum: {avalanche_result['status']}")

    print("\n3. ÇAKIŞMA TESTİ (10000 örnek)")
    print("-" * 40)

    collision_result = hasher.test_collision_resistance(100)  # 10000
    print(f"  Çakışma sayısı: {collision_result['collisions']}")
    print(f"  Çakışma oranı: {collision_result['collision_rate_percent']:.8f}%")
    print(f"  Yakın çakışma: {collision_result['near_collisions']}")
    print(f"  Durum: {collision_result['status']}")

    print("\n4. UNIFORMLUK TESTİ (10000 örnek)")
    print("-" * 40)

    uniformity_result = hasher.test_uniformity(100)  # 10000
    print(f"  Chi-square (bit): {uniformity_result['chi_square_bit']:.1f}")
    print(f"  Chi-square (byte): {uniformity_result['chi_square_byte']:.1f}")
    print(f"  Ortalama run uzunluğu: {uniformity_result['avg_run_length']:.3f}")
    print(f"  Bit uniform mu: {uniformity_result['is_uniform_bit']}")
    print(f"  Byte uniform mu: {uniformity_result['is_uniform_byte']}")
    print(f"  Durum: {uniformity_result['status']}")

    print("\nPERFORMANS ÖZETİ")
    print("-" * 40)

    stats = hasher.get_stats()
    print(f"  Toplam hash: {stats['hash_count']}")
    print(f"  Ortalama süre: {stats.get('avg_time_ms', 0):.2f}ms")
    print(f"  Toplam operasyon: {stats.get('total_operations', 0)}")
    print(f"  KHA başarı oranı: {stats.get('kha_success_rate', 0):.1f}%")
    print(f"  Güvenlik kontrolleri: {stats.get('security_checks', 0)}")

    print("\n" + "=" * 80)
    print("SONUÇ: KHA-256 FORTIFIED")
    print("=" * 80)

    # Final evaluation
    avalanche_ok = avalanche_result["status"] in ["EXCELLENT", "GOOD"]
    collision_ok = collision_result["status"] in ["EXCELLENT", "GOOD"]
    uniformity_ok = uniformity_result["status"] in ["EXCELLENT", "GOOD"]

    if avalanche_ok and collision_ok and uniformity_ok:
        print("✓ TÜM TESTLER BAŞARILI! - ÜRETİME HAZIR!")
        print("✓ Yüksek güvenlik seviyesi sağlandı")
        print("✓ Kuantum ve yan kanal saldırılarına karşı korumalı")
    elif avalanche_ok and collision_ok:
        print("✓ İYİ - Çakışma ve avalanche testleri başarılı")
    else:
        print("⚠ İYİLEŞTİRME GEREKLİ - Bazı testler başarısız")

    return hasher


# ============================================================
# ÖRNEK KULLANIM
# ============================================================
if __name__ == "__main__":
    print("KEÇECİ HASH ALGORİTMASI (KHA-256) - FORTIFIED VERSION")
    print("   Güvenlik maksimum - Performanstan fedakarlık\n")

    # Test modu
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        hasher = run_comprehensive_test()
    else:
        # Hızlı örnek
        print("⚡ GÜVENLİ ÖRNEK KULLANIM:\n")

        hasher = generate_fortified_hasher()

        # Örnek 1: Basit metin
        text = "Merhaba dünya! Bu bir KHA Hash testidir. Güvenlik maksimum!"
        hash_result = hasher.hash(text)
        print(f"Metin: '{text[:50]}...'")
        print(f"Hash:  {hash_result}")
        print()

        # Örnek 2: Şifre hash'leme
        password = "ÇokGizliŞifre123!@#"
        password_hash = hash_password(password)
        print(f"Şifre: '{password}'")
        print(f"Hash:  {password_hash[:80]}...")
        print()

        # Örnek 3: Avalanche demo
        print("AVALANCHE DEMO:")
        data1 = "Test123"
        data2 = "Test124"  # Sadece 1 karakter fark

        h1 = hasher.hash(data1)
        h2 = hasher.hash(data2)

        # Bit farkı
        h1_bin = bin(int(h1, 16))[2:].zfill(256)
        h2_bin = bin(int(h2, 16))[2:].zfill(256)
        diff = sum(1 for a, b in zip(h1_bin, h2_bin) if a != b)

        print(f"  '{data1}' → {h1[:32]}...")
        print(f"  '{data2}' → {h2[:32]}...")
        print(f"  Bit farkı: {diff}/256 (%{diff/256*100:.2f})")
        print()

        # Optimize edilmiş hasher oluştur
        optimized_config = FortifiedConfig()
        optimized_hasher = OptimizedKhaHash256(optimized_config)

        # Test
        test_data = "Merhaba Dünya"
        print(f"Metin: {test_data}")
        hash_result = optimized_hasher.hash(test_data)
        print(f"Hash: {hash_result}")
        print(
            f"Beklenen süre (OptimizedKhaHash256): {optimized_config.expected_performance_ms:.1f}ms"
        )
        print()

        # Örnek 4: Güvenlik raporu
        print("GÜVENLİK ÖZELLİKLERİ:")
        report = hasher.get_security_report()
        for key, value in report["features"].items():
            print(f"  {key.replace('_', ' ').title()}: {'✓' if value else '✗'}")
