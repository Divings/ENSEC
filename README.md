# EncryptSecureDEC

Secure file encryption toolkit with RSA integration and blockchain-style
operation logging.

EncryptSecureDEC is a cryptographic utility designed for secure file
handling, combining modern encryption standards with operational
integrity tracking.

------------------------------------------------------------------------

## ✨ Features

-   AES-GCM file encryption
-   RSA-OAEP key encryption
-   RSA private key password protection (v7.2.0+)
-   RSA digital signature support
-   Blockchain-style operation logging
-   Folder encryption support
-   WAV-based binary embedding support
-   CLI-based secure operation

------------------------------------------------------------------------

## 🔐 Cryptography Overview

EncryptSecureDEC uses:

-   AES-256-GCM for symmetric encryption
-   RSA-2048 with OAEP (SHA-256) for key encapsulation
-   PBKDF2-based key derivation
-   Optional password protection for RSA private keys

Security is not only about algorithms.\
It is also about secure key management.

------------------------------------------------------------------------

## 📦 Installation (RPM)

Download the latest RPM from the GitHub Releases page:

👉 https://github.com/Divings/ENSEC/releases

Example:

    sudo dnf install ./ENSEC-<version>.rpm

GitHub Releases provide: - The latest version - The previous version
only

------------------------------------------------------------------------

## 💼 Commercial Distribution

Official binary builds are commercially distributed.

The paid Yum repository provides:

-   Automated updates via `dnf update`
-   Extended version retention
-   Faster update channel
-   Repository-level integrity management
-   Priority support

Source code remains publicly available.

------------------------------------------------------------------------

## 🔄 Versioning Policy

EncryptSecureDEC follows semantic versioning:

MAJOR.MINOR.PATCH

-   MAJOR: Breaking changes
-   MINOR: New features
-   PATCH: Bug fixes

GitHub Releases include only the latest and previous versions.\
Extended version history is available through the commercial repository.

------------------------------------------------------------------------

## 🛠 Build From Source

Requirements:

-   Python 3.8+
-   cryptography
-   pycryptodome
-   lzma
-   SQLite3

Clone the repository:

    git clone https://github.com/Divings/ENSEC.git
    cd ENSEC

Run CLI:

    python3 EncryptSecureDEC_CUI.py

------------------------------------------------------------------------

## ⚠ License

This software is distributed under a proprietary license.

Source code is publicly accessible, but redistribution, commercial use,
and binary distribution are restricted unless explicitly permitted.

See LICENSE file for details.

------------------------------------------------------------------------

## 👤 Author

Anvelk Innovations\
contact@anvelk.jp
