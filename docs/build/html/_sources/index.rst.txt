.. KHA-256 documentation master file

=====================
KHA-256 Documentation
=====================

**Performance-Sacrificed, Security-Maximized Hash Algorithm**

.. toctree::
   :maxdepth: 2
   :caption: Contents
   
   quickstart
   installation
   usage

.. toctree::
   :maxdepth: 3
   :caption: API Reference
   
   api/kha256

.. toctree::
   :maxdepth: 2
   :caption: Additional Resources
   
   citation
   changelog

Overview
========

KHA-256 is a 256-bit cryptographic hash function designed with **security 
prioritized over performance**.

Quick Example
-------------

.. code-block:: python

   from kha256 import quick_hash
   
   result = quick_hash("Hello KHA-256!")
   print(f"Hash: {result}")

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
