# Dependencies and Installation Guide

## Core Dependencies

### Required Packages
- `cryptography>=41.0.0` - Modern encryption and cryptographic operations
- `psutil>=5.9.0` - System and process monitoring

## Installation Instructions

### Quick Setup
```bash
pip install -r requirements.txt
```

### Manual Installation
```bash
pip install cryptography psutil
```

### Alternative Installation Methods

#### Using conda
```bash
conda install cryptography psutil
```

#### Using pipenv
```bash
pipenv install cryptography psutil
```

## Package Descriptions

### cryptography
- **Purpose**: Modern encryption and cryptographic operations
- **Used in**: `01_cryptography/modern_crypto.py`
- **Features**: AES encryption, key derivation, secure hashing

### psutil
- **Purpose**: System and process monitoring
- **Used in**: `05_security_tools/security_monitor.py`
- **Features**: Process monitoring, network connections, system information

## Optional Dependencies

These packages enhance certain features but are not strictly required:

### For Advanced Network Operations
```bash
pip install scapy  # Advanced packet manipulation (optional)
```

### For Enhanced Visualization
```bash
pip install matplotlib  # For creating security charts (optional)
```

## Python Version Requirements

- **Minimum**: Python 3.7
- **Recommended**: Python 3.9 or higher
- **Tested on**: Python 3.8, 3.9, 3.10, 3.11

## Troubleshooting

### Common Installation Issues

#### Cryptography Package Issues
If you encounter issues installing cryptography:

**Windows:**
```bash
# Install Microsoft C++ Build Tools first
pip install --upgrade pip
pip install cryptography
```

**Linux:**
```bash
# Install development packages
sudo apt-get install build-essential libffi-dev python3-dev
pip install cryptography
```

**macOS:**
```bash
# Install Xcode command line tools
xcode-select --install
pip install cryptography
```

#### PSUtil Installation Issues
```bash
# Usually resolves most psutil issues
pip install --upgrade pip setuptools wheel
pip install psutil
```

### Verification

To verify all dependencies are correctly installed:

```python
# Run this in Python to check installations
try:
    import cryptography
    import psutil
    import hashlib
    import socket
    import sqlite3
    print("All required packages are installed!")
except ImportError as e:
    print(f"Missing package: {e}")
```

## Security Considerations

### Antivirus Software
Some security tools may trigger antivirus warnings. This is normal for educational security software. Consider:

- Adding project folder to antivirus exceptions
- Temporarily disabling real-time protection during testing
- Using a virtual machine for testing

### Network Testing
- Only test on networks you own or have permission to test
- Be aware that network scanning may trigger security alerts
- Consider using a local test environment

---

**Note**: This project is designed to work with minimal dependencies to ensure accessibility for beginners. Advanced features are optional and clearly marked in the documentation.