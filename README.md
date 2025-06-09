# Final Project Kriptografi (B) - ECC Digital Signing System

**Kelompok 1**

| Nama                      | NRP        | Field      | Pembagian Tugas                           |
| ------------------------- | ---------- | ---------- | ----------------------------------------- |
| Nathan Kho Pancras        | 5027231002 | Full-stack | Project Manager / Cryptographic Assessor  |
| Diandra Naufal Abror      | 5027231004 | Backend    | Key Management Developer                  |
| Rafael Jonathan Arnoldus  | 5027231006 | Backend    | Digital Signature Developer               |
| Michael Kenneth Salim     | 5027231008 | Frontend   | UI Lead                                   |
| Rafael Ega Krisaditya     | 5027231025 | Full-stack | Security Tester / Quality Assessor        |
| Amoes Noland              | 5027231028 | Backend    | Docs Maintainer / Quality Assessor        |
| Fico Simhanandi           | 5027231030 | Backend    | API Developer                             | 
| Rafi' Afnaan Fathurrahman | 5027231040 | Backend    | Binary Patching Specialist                |
| Dimas Andhika Diputra     | 5027231074 | Frontend   | State & API Integration                   |

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
npm dev
# OR
python -m http.server 3000
# OR just open up index.html frontend/index.html on your browser
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

## Web Interface Features

The frontend provides an intuitive web interface with:

### Key Generation
- Create new ECDSA key pairs
- Choose between encrypted (password-protected) or unencrypted keys
- Real-time key generation with progress indicators

### File Signing
- Upload any file for digital signing
- Select from available keys
- Password input for encrypted keys
- Download signature files (.sig format)

### Signature Verification
- Upload original file and signature file
- Automatic key detection from signature metadata
- Clear validation results with detailed information

### Binary Patching
- Embed signatures directly into files
- Create self-contained signed binaries
- Download patched files with embedded signatures

### Patched Binary Verification
- Verify files with embedded signatures
- No separate signature file needed
- Display signature metadata and file information

### Key Management
- View all stored keys
- Export keys in different formats (PEM, DER)
- Change passwords for encrypted keys
- Delete keys securely

### System Status
- Monitor server health
- View key and signature statistics
- Display cryptographic algorithm details

## Program Flow

### Standard Signing Process
1. **Key Generation**: Create ECDSA key pairs with optional AES-256-GCM encryption
2. **File Hashing**: Compute SHA-256 hash of the input file
3. **Digital Signing**: Sign the hash using the private key
4. **Signature Storage**: Save signature metadata as JSON
5. **Verification**: Use public key to verify signature authenticity

### Binary Patching Process
1. **File Analysis**: Read the original binary file
2. **Signature Creation**: Generate digital signature
3. **Metadata Embedding**: Append signature data to file
4. **Integrity Preservation**: Maintain original file functionality
5. **Self-Verification**: Enable signature checking without external files

## Details

### Cryptographic Algorithms
- **Elliptic Curve**: SECP256k1 (Bitcoin standard, 256-bit security)
- **Digital Signature**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Hash Function**: SHA-256 (256-bit cryptographic hash)
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-SHA256 with 100,000 iterations

### Security Features
- **Password Protection**: Private keys encrypted with user passwords
- **Authenticated Encryption**: GCM mode prevents tampering
- **Salt-based Derivation**: Each key uses unique salt values
- **Secure Storage**: Keys stored as encrypted JSON files
- **Tamper Detection**: Signatures detect any file modifications

### File Formats
- **Keys**: JSON format with encrypted private key data
- **Signatures**: JSON format with signature metadata
- **Patched Binaries**: Original file + appended signature block
