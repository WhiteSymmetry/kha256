Installation
============

This guide covers installing KHA-256 on various platforms.

System Requirements
-------------------

Minimum Requirements
^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   
   * - Component
     - Minimum
     - Recommended
   * - **Python**
     - 3.8
     - 3.10+
   * - **RAM**
     - 512 MB
     - 2 GB+
   * - **Disk Space**
     - 100 MB
     - 1 GB+
   * - **CPU Cores**
     - 1
     - 2+

Supported Platforms
^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 30 40
   
   * - Platform
     - Support Status
     - Notes
   * - **Linux**
     - ✅ Full Support
     - All major distributions
   * - **Windows 10/11**
     - ✅ Full Support
     - Python 3.8+ required
   * - **macOS**
     - ✅ Full Support
     - 10.15 (Catalina)+
   * - **BSD**
     - ⚠️ Limited
     - Not fully tested

Installation Methods
--------------------

Method 1: Pip Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^

Basic Installation
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Install basic dependencies
   pip install numpy>=1.20.0
   
   # Install KeçeciNumbers library
   pip install kececinumbers==0.8.4
   
   # Install KHA-256 package
   pip install kha256

With Specific Version
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Install specific version
   pip install kha256==0.1.0
   
   # Install from GitHub
   pip install git+https://github.com/WhiteSymmetry/kha256.git

Method 2: Developer Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For development or contributing:

.. code-block:: bash

   # Clone repository
   git clone https://github.com/WhiteSymmetry/kha256.git
   cd kha256
   
   # Create virtual environment (recommended)
   python -m venv venv
   
   # Activate virtual environment
   # Linux/macOS:
   source venv/bin/activate
   
   # Windows:
   venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Install in development mode
   pip install -e .

Method 3: Conda Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Using Miniconda/Anaconda:

.. code-block:: bash

   # Create new conda environment
   conda create -n kha256 python=3.9
   
   # Activate environment
   conda activate kha256
   
   # Install basic packages
   conda install numpy pandas matplotlib
   
   # Install remaining with pip
   pip install kececinumbers==0.8.4
   pip install kha256

Using environment.yml:

.. code-block:: yaml
   :caption: environment.yml
   
   name: kha256
   channels:
     - conda-forge
     - defaults
   dependencies:
     - python=3.9
     - pip
     - numpy>=1.20.0
     - pandas>=1.3.0
     - matplotlib>=3.4.0
     - pip:
       - kececinumbers==0.8.4
       - kha256

.. code-block:: bash

   # Create environment from file
   conda env create -f environment.yml
   conda activate kha256

Platform-Specific Instructions
------------------------------

Windows Installation
^^^^^^^^^^^^^^^^^^^^

Using PowerShell:

.. code-block:: powershell

   # Run PowerShell as Administrator
   Set-ExecutionPolicy RemoteSigned
   
   # Install Python if not present
   winget install Python.Python.3.10
   
   # Create virtual environment
   python -m venv venv
   venv\Scripts\activate
   
   # Install KHA-256
   pip install kha256

Using Command Prompt:

.. code-block:: batch

   :: Run Command Prompt
   python -m venv venkha
   venkha\Scripts\activate.bat
   pip install kha256

Linux Installation
^^^^^^^^^^^^^^^^^^

Ubuntu/Debian:

.. code-block:: bash

   # Update system packages
   sudo apt update
   sudo apt install python3 python3-pip python3-venv
   
   # Create virtual environment
   python3 -m venv ~/kha256_env
   source ~/kha256_env/bin/activate
   
   # Install KHA-256
   pip install kha256

Fedora/RHEL:

.. code-block:: bash

   # Install Python
   sudo dnf install python3 python3-pip
   
   # Install virtualenv module
   sudo dnf install python3-virtualenv
   
   # Create and activate virtual environment
   python3 -m venv kha256_env
   source kha256_env/bin/activate
   
   # Install KHA-256
   pip install kha256

macOS Installation
^^^^^^^^^^^^^^^^^^

Using Homebrew:

.. code-block:: bash

   # Install Python via Homebrew
   brew install python
   
   # Create virtual environment
   python3 -m venv kha256_env
   source kha256_env/bin/activate
   
   # Install KHA-256
   pip install kha256

Verification
------------

Python Verification Script
^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a verification script:

.. code-block:: python
   :caption: verify_installation.py
   
   import sys
   print(f"Python version: {sys.version}")
   
   try:
       import numpy
       print(f"NumPy version: {numpy.__version__}")
   except ImportError:
       print("NumPy not installed!")
   
   try:
       import kececinumbers as kn
       print(f"KeçeciNumbers version: {kn.__version__}")
   except ImportError:
       print("KeçeciNumbers not installed!")
   
   try:
       import kha256
       print(f"KHA-256 version: {kha256.__version__}")
       print("✅ KHA-256 successfully installed!")
   except ImportError as e:
       print(f"❌ KHA-256 installation failed: {e}")

Command Line Verification
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Check version
   python -m kha256 --version
   
   # Run demo
   python -m kha256 --demo
   
   # Quick test
   python -c "from kha256 import quick_hash; print(quick_hash('test'))"

Development Dependencies
------------------------

For development work, additional packages are recommended:

.. code-block:: bash

   # requirements-dev.txt
   black>=22.0.0
   flake8>=4.0.0
   pytest>=7.0.0
   pytest-cov>=3.0.0
   mypy>=0.950
   pre-commit>=2.20.0
   jupyterlab>=3.4.0
   ipywidgets>=7.7.0

Install development dependencies:

.. code-block:: bash

   pip install -r requirements-dev.txt
   
   # Set up pre-commit hooks
   pre-commit install

Troubleshooting
---------------

Common Issues and Solutions
^^^^^^^^^^^^^^^^^^^^^^^^^^^

KeçeciNumbers Installation Error
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   ERROR: Could not find a version that satisfies the requirement kececinumbers==0.8.4

**Solution:**

.. code-block:: bash

   # Upgrade pip first
   pip install --upgrade pip
   
   # Try alternative source
   pip install kececinumbers --index-url https://test.pypi.org/simple/

NumPy Compilation Error
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   ERROR: Failed building wheel for numpy

**Solution:**

.. code-block:: bash

   # Use pre-compiled wheels
   pip install numpy --only-binary=:all:
   
   # Or install system dependencies
   # Ubuntu/Debian:
   sudo apt install python3-dev build-essential
   
   # macOS:
   brew install openblas

Virtual Environment Issues
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   bash: venv/bin/activate: No such file or directory

**Solution:**

.. code-block:: bash

   # Recreate virtual environment
   python -m venv venv --clear
   
   # On Windows:
   python -m venv venv
   venv\Scripts\activate

Performance Optimization
^^^^^^^^^^^^^^^^^^^^^^^^

For better performance, set environment variables:

.. code-block:: bash

   # Add to ~/.bashrc or ~/.zshrc
   export MKL_NUM_THREADS=1
   export OMP_NUM_THREADS=1
   export OPENBLAS_NUM_THREADS=1

Or in Python:

.. code-block:: python

   import os
   os.environ["OMP_NUM_THREADS"] = "1"

Offline Installation
--------------------

For environments without internet access:

.. code-block:: bash

   # Download all dependencies
   pip download kha256 numpy kececinumbers -d ./packages
   
   # Offline installation
   pip install --no-index --find-links=./packages kha256

Updating
--------

.. code-block:: bash

   # Update KHA-256 only
   pip install --upgrade kha256
   
   # Update all dependencies
   pip install --upgrade kha256 numpy kececinumbers

Uninstallation
--------------

.. code-block:: bash

   # Uninstall KHA-256
   pip uninstall kha256
   
   # Uninstall all dependencies
   pip uninstall kha256 kececinumbers numpy
   
   # Remove virtual environment
   # Windows:
   rmdir /s venv
   
   # Linux/macOS:
   rm -rf venv

Next Steps
----------

After successful installation:

1. Continue to :doc:`quickstart` for basic usage
2. Check out :doc:`usage` for advanced features
3. Explore the :doc:`api/kha256` for detailed API reference

.. note::

   If you encounter any issues, please report them on the 
   `GitHub Issues <https://github.com/WhiteSymmetry/kha256/issues>`_ page.
