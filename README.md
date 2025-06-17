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

![Key Generation](https://github.com/user-attachments/assets/cf2fd171-83d6-47d4-b5f0-e3276defd1cf)

### Key Generation
- Create new ECDSA key pairs
- Choose between encrypted (password-protected) or unencrypted keys
- Real-time key generation with progress indicators

![File Signing](https://github.com/user-attachments/assets/d0b067b6-c201-4ca7-b692-07bb11bd6b31)

### File Signing
- Upload any file for digital signing
- Select from available keys
- Password input for encrypted keys
- Download signature files (.sig format)

![Signature Verification](https://github.com/user-attachments/assets/0fcd1bb2-0865-42d3-99f3-b92a4f72cd34)

### Signature Verification
- Upload original file and signature file
- Automatic key detection from signature metadata
- Clear validation results with detailed information

![Binary Patching](https://github.com/user-attachments/assets/edf4f7a2-023a-4dbc-8d64-35085d2df81d)

### Binary Patching
- Embed signatures directly into files
- Create self-contained signed binaries
- Download patched files with embedded signatures

![Patched Binary Verification](https://github.com/user-attachments/assets/841510bc-cd2d-4856-8a3d-7e44ae8c082f)

### Patched Binary Verification
- Verify files with embedded signatures
- No separate signature file needed
- Display signature metadata and file information

![Key Management](https://github.com/user-attachments/assets/65ae7a49-b728-4c82-a1ba-13d58aa7625a)

### Key Management
- View all stored keys
- Export keys in different formats (PEM, DER)
- Change passwords for encrypted keys
- Delete keys securely

![System Status](https://github.com/user-attachments/assets/8adfae25-14ae-4c3c-9493-d23fe32952dd)

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

## About ECC

Elliptic Curve Cryptography (ECC) is a modern approach to public-key cryptography, similar in purpose to RSA but based on different mathematical principles. Instead of relying on the difficulty of factoring large numbers, ECC's security is based on the difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

Here's the core idea in simple terms:

1.  **The Curve:** We start with a specific, publicly known elliptic curve equation and a base point `G` on that curve. This defines the domain parameters for all cryptographic operations.
2.  **Private Key:** A user generates a private key, which is simply a very large random number, `d`. This key is kept secret.
3.  **Public Key:** The public key is calculated by performing a special kind of "addition" on the curve. We "add" the base point `G` to itself `d` times. The resulting point on the curve, `Q`, becomes the public key (`Q = d * G`).
4.  **The Security:** While it is mathematically simple to calculate the public key `Q` from the private key `d`, it is computationally infeasible to determine the private key `d` even when you know the public key `Q` and the base point `G`. This one-way property is the foundation of ECC's security.

Because of its mathematical properties, ECC offers the same level of security as RSA but with much smaller key sizes. This makes it highly efficient and ideal for systems with limited computing power or bandwidth, such as mobile devices and secure messaging. This project directly applies these ECC principles for creating and verifying digital signatures using the Elliptic Curve Digital Signature Algorithm (ECDSA).

*   **Key Generation:** When you generate a new key pair in our system, the backend performs the steps described above. It creates a secret random number (`private key`) and uses the SECP256k1 curve's parameters to compute the corresponding `public key`. The private key is then securely stored (often encrypted with your password), while the public key is stored in plaintext, as it's meant to be shared.

*   **Signing:** When you sign a file, the system first computes a SHA-256 hash of the file. The ECDSA algorithm then uses your private key and this hash to generate a unique digital signature. This signature is mathematical proof that you, the holder of the private key, have approved the file's content at that specific moment.

*   **Verification:** To verify a signature, the system only needs the file, the signature itself, and the public key (which is publicly known). The verification algorithm uses the public key to confirm that the signature could *only* have been created by the corresponding private key for that specific file hash. This process ensures both the file's **integrity** (it hasn't changed) and its **authenticity** (it was signed by the correct person).

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
