# Final Project Kriptografi (B) - ECC Digital Signing System

**Kelompok 1**

|Nama|NRP|
|-|-|
|Nathan Kho Pancras|5027231002|
|Diandra Naufal Abror|5027231004|
|Rafael Jonathan Arnoldus|5027231006|
|Michael Kenneth Salim|5027231008|
|Rafael Ega Krisaditya|5027231025|

A secure digital signing system using Elliptic Curve Cryptography (ECC) for signing and verifying binary files with encrypted key storage.

## Features

- 📝 **Digital Signing** - Sign any binary file using ECDSA-SECP256k1
- ✅ **Signature Verification** - Verify file integrity and authenticity  
- 🔧 **Binary Patching** - Embed signatures directly into files
- 🔐 **Encrypted Key Storage** - Private keys protected with AES-256-GCM
- 💾 **Persistent Storage** - Keys and signatures saved to disk
- 🔑 **Password Protection** - PBKDF2-SHA256 key derivation
- 🌐 **REST API** - Complete HTTP API for all operations
- 💻 **CLI Interface** - Command-line tools included

## Quick Start

**Backend**

> It is advised to use a package manager such as uv for the backend.

```bash
uv sync
uv run main.py
```

**Frontend**

```bash
```

## Backend APIs

### Generate Keys
```bash
# Encrypted key (recommended)
curl -X POST http://localhost:5000/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"key_id": "my_key", "password": "secure_password", "encrypt": true}'

# Unencrypted key
curl -X POST http://localhost:5000/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"key_id": "my_key", "encrypt": false}'
```

### Sign Files
```bash
# With encrypted key
curl -X POST http://localhost:5000/sign-file \
  -F "file=@myfile.bin" \
  -F "key_id=my_key" \
  -F "password=secure_password"

# With unencrypted key
curl -X POST http://localhost:5000/sign-file \
  -F "file=@myfile.bin" \
  -F "key_id=my_key"
```

### Verify Signatures
```bash
curl -X POST http://localhost:5000/verify-signature \
  -F "file=@myfile.bin" \
  -F "signature_data={...signature_json...}" \
  -F "key_id=my_key"
```

### Patch Binary (Embed Signature)
```bash
curl -X POST http://localhost:5000/patch-binary \
  -F "file=@myfile.bin" \
  -F "key_id=my_key" \
  -F "password=secure_password" \
  -o signed_myfile.bin
```

### Other Endpoints
```bash
curl http://localhost:5000/keys        # List keys
curl http://localhost:5000/signatures  # List signatures
curl http://localhost:5000/health      # Server status
```

## CLI Usage

```bash
# Generate key
python cli.py generate-key my_key

# Sign file  
python cli.py sign myfile.bin my_key

# Verify signature
python cli.py verify myfile.bin

# Patch binary with signature
python cli.py patch myfile.bin my_key --output signed_myfile.bin

# Verify patched binary
python cli.py verify-patched myfile.bin

# List keys
python cli.py list-keys

# Export private key
python export-key my_key
```

## Backend Testing

```bash
# Test basic functionality
python tests/test_signing.py

# Test encrypted key features
python tests/test_signing_encrypted.py
```

## Program Flow

1. **Key Generation** - Creates ECDSA key pairs with optional AES-256-GCM encryption
2. **File Signing** - Computes SHA-256 hash and signs with private key  
3. **Verification** - Uses public key to verify signature and file integrity
4. **Binary Patching** - Embeds signature metadata directly into files
5. **Persistent Storage** - Keys and signatures saved as JSON files

## Details

- **Elliptic Curve**: SECP256k1 (Bitcoin standard)
- **Encryption**: AES-256-GCM with authenticated encryption
- **Key Derivation**: PBKDF2-SHA256, 100,000 iterations
- **Storage**: JSON files with persistent signatures and keys