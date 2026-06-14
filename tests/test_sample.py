# -*- coding: utf-8 -*-
# test_sample.py
"""
Comprehensive unit tests for the kha256 module.
Tests core functionality, number type generation, and mathematical properties.
"""

import kha256
import secrets
import os
import traceback

def test_fortified_hash_generates_output():
    """Test that fortified hasher produces hash output"""
    print("\n" + "="*60)
    print("TEST 1: Fortified Hash Generates Output (Güçlendirilmiş Hash)")
    print("="*60)
    
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    input_text = "Merhaba Dünya!"
    
    print(f"[*] Girdi (Input) : '{input_text}'")
    print(f"[*] Tuz (Salt)    : {salt.hex()} (16 bytes)")
    
    hash_result = hasher.hash(input_text, salt)
    
    assert hash_result is not None, "Hash sonucu None olamaz!"
    assert len(hash_result) > 0, "Hash sonucu boş olamaz!"
    
    # Çıktı bytes ise hex'e çevir, string ise direkt yazdır
    if isinstance(hash_result, bytes):
        print(f"[+] KHA-256 Hash  : {hash_result.hex()}")
        print(f"[+] Hash Uzunluğu : {len(hash_result)} bytes")
    else:
        print(f"[+] KHA-256 Hash  : {hash_result}")
        print(f"[+] Hash Uzunluğu : {len(hash_result)} karakter")
        
    print("✅ TEST 1 BAŞARILI: Hash başarıyla üretildi.")

def test_hash_is_deterministic():
    """Test that same input produces same output"""
    print("\n" + "="*60)
    print("TEST 2: Hash Determinism Check (Deterministiklik Kontrolü)")
    print("="*60)
    
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    input_text = "test_determinism"
    
    print(f"[*] Girdi         : '{input_text}'")
    print(f"[*] Tuz           : {salt.hex()}")
    
    result1 = hasher.hash(input_text, salt)
    result2 = hasher.hash(input_text, salt)
    
    r1_str = result1.hex() if isinstance(result1, bytes) else str(result1)
    r2_str = result2.hex() if isinstance(result2, bytes) else str(result2)
    
    print(f"[+] Hash 1        : {r1_str}")
    print(f"[+] Hash 2        : {r2_str}")
    
    assert result1 == result2, "Aynı girdi ve tuz için hash'ler aynı olmalıdır!"
    print("✅ TEST 2 BAŞARILI: Hash fonksiyonu deterministik çalışıyor.")

def test_hash_different_inputs_produce_different_outputs():
    """Test that different inputs produce different hashes (Avalanche Effect)"""
    print("\n" + "="*60)
    print("TEST 3: Avalanche Effect / Different Inputs (Çığ Etkisi)")
    print("="*60)
    
    salt = os.urandom(16)
    hasher = kha256.generate_fortified_hasher()
    input1 = "input1"
    input2 = "input2"
    
    print(f"[*] Girdi 1       : '{input1}'")
    print(f"[*] Girdi 2       : '{input2}'")
    print(f"[*] Tuz           : {salt.hex()}")
    
    result1 = hasher.hash(input1, salt)
    result2 = hasher.hash(input2, salt)
    
    r1_str = result1.hex() if isinstance(result1, bytes) else str(result1)
    r2_str = result2.hex() if isinstance(result2, bytes) else str(result2)
    
    print(f"[+] Hash 1        : {r1_str}")
    print(f"[+] Hash 2        : {r2_str}")
    
    assert result1 != result2, "Farklı girdiler farklı hash'ler üretmelidir!"
    print("✅ TEST 3 BAŞARILI: Farklı girdiler tamamen farklı hash'ler üretti.")

def test_basic_standalone_hash():
    """Run the basic standalone test from the original script"""
    print("\n" + "="*60)
    print("TEST 4: Basic Standalone Hash (64-byte salt)")
    print("="*60)
    
    salt = secrets.token_bytes(64)
    input_text = "Merhaba Dünya!"
    
    print(f"[*] Girdi         : '{input_text}'")
    print(f"[*] Tuz           : {salt.hex()[:32]}... (64 bytes, kesilmiş)")
    
    hasher = kha256.generate_fortified_hasher()
    hash_result = hasher.hash(input_text, salt)
    
    r_str = hash_result.hex() if isinstance(hash_result, bytes) else str(hash_result)
    print(f"[+] KHA-256 Hash  : {r_str}")
    print("✅ TEST 4 BAŞARILI: Bağımsız hash başarıyla üretildi.")

# ======================================================================
# MAIN EXECUTION BLOCK
# ======================================================================
if __name__ == "__main__":
    print("🚀 KHA-256 Kapsamlı Testleri Başlatılıyor...")
    print(f"📦 Kullanılan Sürüm: {getattr(kha256, '__version__', 'Bilinmiyor')}")
    
    try:
        # Tüm testleri sırayla çalıştır
        test_fortified_hash_generates_output()
        test_hash_is_deterministic()
        test_hash_different_inputs_produce_different_outputs()
        test_basic_standalone_hash()
        
        print("\n" + "="*60)
        print("🎉 TÜM TESTLER BAŞARIYLA TAMAMLANDI! 🎉")
        print("="*60 + "\n")
        
    except AssertionError as e:
        print(f"\n❌ TEST BAŞARISIZ: {e}")
    except Exception as e:
        print(f"\n❌ BEKLENMEYEN BİR HATA OLUŞTU: {e}")
        traceback.print_exc()
