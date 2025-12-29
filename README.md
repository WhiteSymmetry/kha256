# KEÇECİ HASH ALGORİTMASI (KHA-256) 🇹🇷/Eng

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-green)
![Version](https://img.shields.io/badge/version-0.1.0-orange)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen)

**Performanstan Fedakarlık Edilerek Güvenlik Maksimize Edilmiş Hash Algoritması**  
**Hash Algorithm with Security Maximized at the Sacrifice of Performance**

</div>

---

## 📖 İçindekiler / Table of Contents
- [🇹🇷 Türkçe](#türkçe)
  - [Özellikler](#özellikler)
  - [Kurulum](#kurulum)
  - [Hızlı Başlangıç](#hızlı-başlangıç)
  - [Detaylı Kullanım](#detaylı-kullanım)
  - [Güvenlik Testleri](#güvenlik-testleri)
  - [Performans](#performans)
  - [API Referansı](#api-referansı)
  - [Katkıda Bulunma](#katkıda-bulunma)
  - [Lisans](#lisans)
- [English](#english)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Advanced Usage](#advanced-usage)
  - [Security Tests](#security-tests)
  - [Performance](#performance)
  - [API Reference](#api-reference)
  - [Contributing](#contributing)
  - [License](#license)

---

# 🇹🇷 Türkçe

## 🚀 Özellikler

### 🔐 Güvenlik Öncelikli
- **256-bit hash çıktısı** - Endüstri standardı
- **Güçlü Avalanche Etkisi** - %49.5-50.5 ideal aralık
- **Kuantum Dirençli Tasarım** - Post-kuantum güvenlik
- **Çoklu Keçeci Sayısı Türleri** - 22 farklı matematiksel sistem
- **Entropi İnjeksiyonu** - Zaman ve sistem bazlı entropy
- **Çift Hashleme** - Ek güvenlik katmanı

### ⚡ Performans Optimizasyonları
- **Vektörel İşlemler** - NumPy ile optimize edilmiş
- **Akıllı Önbellekleme** - Tekrarlanan işlemler için
- **Batch İşleme** - Toplu hash işlemleri için optimize
- **Paralel İşleme Hazır** - (Opsiyonel)

### 🧪 Kapsamlı Testler
- **Avalanche Testi** - Bit değişim analizi
- **Çakışma Testi** - Hash çakışmalarının önlenmesi
- **Uniformluk Testi** - Bit dağılım analizi
- **Performans Benchmark** - Hız ve verimlilik testleri

## 📦 Kurulum

### Gereksinimler
- Python 3.10 veya üzeri
- NumPy 2.20.0+
- KeçeciNumbers 0.8.4+

### Pip ile Kurulum
```bash
pip install -U kececinumbers==0.8.4
pip install -U numpy>=2.3.0
```

### Manuel Kurulum
```bash
# Repository'yi klonla
git clone https://github.com/WhiteSymmetry/kha256.git
cd kha256

# Bağımlılıkları yükle
pip install -r requirements.txt

# Geliştirici modunda yükle
pip install -e .
```

## 🎯 Hızlı Başlangıç

### Temel Hashleme
```python
from kha256 import quick_hash

# Basit metin hash'i
hash_result = quick_hash("Merhaba Dünya!")
print(f"Hash: {hash_result}")
# Örnek: 8f3a2b1c5d7e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5
```

### Şifre Hashleme
```python
from kha256 import hash_password

password = "GizliŞifre123!"
hashed_password = hash_password(password)
print(f"Hashlenmiş Şifre: {hashed_password[:80]}...")
```

### Komut Satırı Kullanımı
```bash
# Test çalıştır
python -m kha256 --test

# Tek hash oluştur
python -m kha256 --hash "Merhaba Dünya!"

# Performans testi
python -m kha256 --benchmark

# Demo modu
python -m kha256 --demo
```

## 🔧 Detaylı Kullanım

### Özelleştirilmiş Hasher
```python
from kha256 import FortifiedKhaHash256, FortifiedConfig

# Özel konfigürasyon
config = FortifiedConfig(
    iterations=20,           # Daha fazla iterasyon
    shuffle_layers=16,       # Daha fazla karıştırma katmanı
    salt_length=128,         # Daha uzun tuz
    double_hashing=True,     # Çift hashleme aktif
    enable_quantum_resistance=True  # Kuantum direnç
)

# Hasher oluştur
hasher = FortifiedKhaHash256(config)

# Veriyi hash'le
data = "Önemli gizli veri"
salt = secrets.token_bytes(64)  # Güçlü tuz
hash_result = hasher.hash(data, salt)

print(f"Hash: {hash_result}")
```

### Batch İşlemleri
```python
from kha256 import FortifiedKhaHash256

hasher = FortifiedKhaHash256()

# Çoklu veri hash'leme
data_list = ["veri1", "veri2", "veri3", "veri4"]
hashes = [hasher.hash(data) for data in data_list]

# Dosya hash'leme
def hash_file(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    return hasher.hash(file_data)
```

## 🛡️ Güvenlik Testleri

### Avalanche Testi
```python
from kha256 import FortifiedKhaHash256

hasher = FortifiedKhaHash256()
results = hasher.test_avalanche_effect(samples=100)

print(f"Ortalama Bit Değişimi: {results['avg_bit_change_percent']:.2f}%")
print(f"İdeal Aralıkta: {results['in_ideal_range']}")
print(f"Durum: {results['status']}")
# Çıktı: EXCELLENT, GOOD, ACCEPTABLE veya POOR
```

### Çakışma Testi
```python
results = hasher.test_collision_resistance(samples=5000)
print(f"Çakışma Sayısı: {results['collisions']}")
print(f"Çakışma Oranı: {results['collision_rate_percent']:.6f}%")
```

### Kapsamlı Test
```python
from kha256 import run_comprehensive_test

# Tüm testleri çalıştır
hasher = run_comprehensive_test()
```

## 📊 Performans

### Benchmark Sonuçları
```
Boyut     Ortalama Süre    Verim
------    -------------    ------
64 byte     ? ms        ? MB/s
256 byte    ? ms        ? MB/s
1 KB        ? ms        ? MB/s
4 KB        ? ms        ? MB/s
16 KB       ? ms        ? MB/s
```

### Performans Optimizasyonları
```python
from kha256 import FortifiedConfig

# Hızlı mod (daha az güvenlik, daha hızlı)
fast_config = FortifiedConfig(
    iterations=8,
    shuffle_layers=6,
    components_per_hash=12,
    enable_quantum_resistance=False,
    double_hashing=False
)

# Güvenlik mod (maksimum güvenlik)
secure_config = FortifiedConfig(
    iterations=24,
    shuffle_layers=20,
    components_per_hash=32,
    enable_quantum_resistance=True,
    double_hashing=True,
    triple_compression=True
)
```

## 📚 API Referansı

### Ana Sınıflar

#### `FortifiedKhaHash256`
Ana hash sınıfı.

```python
class FortifiedKhaHash256:
    def __init__(self, config: Optional[FortifiedConfig] = None)
    def hash(self, data: Union[str, bytes], salt: Optional[bytes] = None) -> str
    def test_avalanche_effect(self, samples: int = 100) -> Dict[str, Any]
    def test_collision_resistance(self, samples: int = 5000) -> Dict[str, Any]
    def test_uniformity(self, samples: int = 5000) -> Dict[str, Any]
    def get_stats(self) -> Dict[str, Any]
```

#### `FortifiedConfig`
Konfigürasyon sınıfı.

```python
@dataclass
class FortifiedConfig:
    output_bits: int = 256
    hash_bytes: int = 32
    iterations: int = 16
    rounds: int = 8
    components_per_hash: int = 20
    salt_length: int = 96
    shuffle_layers: int = 12
    diffusion_rounds: int = 9
    avalanche_boosts: int = 6
    enable_quantum_resistance: bool = True
    enable_post_quantum_mixing: bool = True
    double_hashing: bool = True
    triple_compression: bool = True
    memory_hardening: bool = True
    entropy_injection: bool = True
    time_varying_salt: bool = True
    context_sensitive_mixing: bool = True
    cache_enabled: bool = False
    parallel_processing: bool = False
```

### Yardımcı Fonksiyonlar

```python
# Hızlı hash
quick_hash(data: Union[str, bytes]) -> str

# Şifre hashleme
hash_password(password: str, salt: Optional[bytes] = None) -> str

# Hasher oluşturma
generate_fortified_hasher() -> FortifiedKhaHash256

# Test çalıştırma
run_comprehensive_test() -> FortifiedKhaHash256

# Benchmark
benchmark_hash(data_sizes: List[int] = [64, 256, 1024, 4096]) -> Dict[str, Any]
```

### Geliştirme Ortamı Kurulumu
```bash
# Repository'yi klonla
git clone https://github.com/mehmetkececi/kha256.git
cd kha256

# Sanal ortam oluştur
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate  # Windows

# Bağımlılıkları yükle
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Geliştirme bağımlılıkları

# Testleri çalıştır
pytest tests/
python -m kha256 --test
```

### Kod Standartları
- [PEP 8](https://www.python.org/dev/peps/pep-0008/) stil rehberi
- Type hint'ler kullanılmalı
- Docstring'ler yazılmalı
- Unit testler eklenmeli

## 📄 Lisans

Bu proje AGPL-3.0 lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

```
Copyright 2025 Mehmet Keçeci

Bu program özgür yazılımdır: Özgür Yazılım Vakfı tarafından yayınlanan
GNU Affero Genel Kamu Lisansı’nın 3. ya da (isteğinize bağlı olarak) daha
sonraki sürümlerinin koşulları altında yeniden dağıtabilir ve/veya
değiştirebilirsiniz.

Bu program, yararlı olması umuduyla dağıtılmış olup, hiçbir garantisi yoktur;
hatta SATILABİLİRLİĞİ veya ŞAHİSİ BİR AMACA UYGUNLUĞU için dahi garanti
vermez. Daha fazla ayrıntı için GNU Affero Genel Kamu Lisansı’na bakınız.

Bu programla birlikte GNU Affero Genel Kamu Lisansı’nın bir kopyasını
almış olmalısınız. Almadıysanız, <http://www.gnu.org/licenses/> adresine bakınız.
```

---

# English

## 🚀 Features

### 🔐 Security First
- **256-bit hash output** - Industry standard
- **Strong Avalanche Effect** - 49.5-50.5% ideal range
- **Quantum-Resistant Design** - Post-quantum security
- **Multiple Keçeci Number Types** - 22 different mathematical systems
- **Entropy Injection** - Time and system-based entropy
- **Double Hashing** - Additional security layer

### ⚡ Performance Optimizations
- **Vectorized Operations** - Optimized with NumPy
- **Smart Caching** - For repeated operations
- **Batch Processing** - Optimized for bulk hashing
- **Parallel Processing Ready** - (Optional)

### 🧪 Comprehensive Tests
- **Avalanche Test** - Bit change analysis
- **Collision Test** - Hash collision prevention
- **Uniformity Test** - Bit distribution analysis
- **Performance Benchmark** - Speed and efficiency tests

## 📦 Installation

### Requirements
- Python 3.10 or higher
- NumPy 2.20.0+
- KeçeciNumbers 0.8.4+

### Install via Pip
```bash
pip install kececinumbers==0.8.4
pip install numpy>=1.20.0
```

### Manual Installation
```bash
# Clone repository
git clone https://github.com/WhiteSymmetry/kha256.git
cd kha256

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## 🎯 Quick Start

### Basic Hashing
```python
from kha256 import quick_hash

# Simple text hash
hash_result = quick_hash("Hello World!")
print(f"Hash: {hash_result}")
# Example: 8f3a2b1c5d7e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5
```

### Password Hashing
```python
from kha256 import hash_password

password = "SecretPassword123!"
hashed_password = hash_password(password)
print(f"Hashed Password: {hashed_password[:80]}...")
```

### Command Line Usage
```bash
# Run tests
python -m kha256 --test

# Create single hash
python -m kha256 --hash "Hello World!"

# Performance test
python -m kha256 --benchmark

# Demo mode
python -m kha256 --demo
```

## 🔧 Advanced Usage

### Customized Hasher
```python
from kha256 import FortifiedKhaHash256, FortifiedConfig

# Custom configuration
config = FortifiedConfig(
    iterations=20,           # More iterations
    shuffle_layers=16,       # More mixing layers
    salt_length=128,         # Longer salt
    double_hashing=True,     # Double hashing active
    enable_quantum_resistance=True  # Quantum resistance
)

# Create hasher
hasher = FortifiedKhaHash256(config)

# Hash data
data = "Important secret data"
salt = secrets.token_bytes(64)  # Strong salt
hash_result = hasher.hash(data, salt)

print(f"Hash: {hash_result}")
```

### Batch Operations
```python
from kha256 import FortifiedKhaHash256

hasher = FortifiedKhaHash256()

# Multiple data hashing
data_list = ["data1", "data2", "data3", "data4"]
hashes = [hasher.hash(data) for data in data_list]

# File hashing
def hash_file(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    return hasher.hash(file_data)
```

## 🛡️ Security Tests

### Avalanche Test
```python
from kha256 import FortifiedKhaHash256

hasher = FortifiedKhaHash256()
results = hasher.test_avalanche_effect(samples=100)

print(f"Average Bit Change: {results['avg_bit_change_percent']:.2f}%")
print(f"In Ideal Range: {results['in_ideal_range']}")
print(f"Status: {results['status']}")
# Output: EXCELLENT, GOOD, ACCEPTABLE or POOR
```

### Collision Test
```python
results = hasher.test_collision_resistance(samples=5000)
print(f"Collisions: {results['collisions']}")
print(f"Collision Rate: {results['collision_rate_percent']:.6f}%")
```

### Comprehensive Test
```python
from kha256 import run_comprehensive_test

# Run all tests
hasher = run_comprehensive_test()
```

## 📊 Performance

### Benchmark Results
```
Size      Average Time    Throughput
------    -------------    ----------
64 byte     ? ms        ? MB/s
256 byte    ? ms        ? MB/s
1 KB        ? ms        ? MB/s
4 KB        ? ms        ? MB/s
16 KB       ? ms        ? MB/s
```

### Performance Optimizations
```python
from kha256 import FortifiedConfig

# Fast mode (less security, faster)
fast_config = FortifiedConfig(
    iterations=8,
    shuffle_layers=6,
    components_per_hash=12,
    enable_quantum_resistance=False,
    double_hashing=False
)

# Security mode (maximum security)
secure_config = FortifiedConfig(
    iterations=24,
    shuffle_layers=20,
    components_per_hash=32,
    enable_quantum_resistance=True,
    double_hashing=True,
    triple_compression=True
)
```

## 📚 API Reference

### Main Classes

#### `FortifiedKhaHash256`
Main hash class.

```python
class FortifiedKhaHash256:
    def __init__(self, config: Optional[FortifiedConfig] = None)
    def hash(self, data: Union[str, bytes], salt: Optional[bytes] = None) -> str
    def test_avalanche_effect(self, samples: int = 100) -> Dict[str, Any]
    def test_collision_resistance(self, samples: int = 5000) -> Dict[str, Any]
    def test_uniformity(self, samples: int = 5000) -> Dict[str, Any]
    def get_stats(self) -> Dict[str, Any]
```

#### `FortifiedConfig`
Configuration class.

```python
@dataclass
class FortifiedConfig:
    output_bits: int = 256
    hash_bytes: int = 32
    iterations: int = 16
    rounds: int = 8
    components_per_hash: int = 20
    salt_length: int = 96
    shuffle_layers: int = 12
    diffusion_rounds: int = 9
    avalanche_boosts: int = 6
    enable_quantum_resistance: bool = True
    enable_post_quantum_mixing: bool = True
    double_hashing: bool = True
    triple_compression: bool = True
    memory_hardening: bool = True
    entropy_injection: bool = True
    time_varying_salt: bool = True
    context_sensitive_mixing: bool = True
    cache_enabled: bool = False
    parallel_processing: bool = False
```

### Helper Functions

```python
# Quick hash
quick_hash(data: Union[str, bytes]) -> str

# Password hashing
hash_password(password: str, salt: Optional[bytes] = None) -> str

# Hasher creation
generate_fortified_hasher() -> FortifiedKhaHash256

# Run tests
run_comprehensive_test() -> FortifiedKhaHash256

# Benchmark
benchmark_hash(data_sizes: List[int] = [64, 256, 1024, 4096]) -> Dict[str, Any]
```

### Development Environment Setup
```bash
# Clone repository
git clone https://github.com/mehmetkececi/kha256.git
cd kha256

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Run tests
pytest tests/
python -m kha256 --test
```

### Code Standards
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints
- Write docstrings
- Add unit tests

## 📄 License

This project is licensed under the AGPL-3.0 License. See the [LICENSE](LICENSE) file for details.

```
Copyright 2025 Mehmet Keçeci

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```

---
