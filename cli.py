#!/usr/bin/env python3
"""
Command-line interface for ECC Digital Signing System with Encrypted Keys
"""

import argparse
import requests
import json
import os
import sys
import getpass

BASE_URL = "http://localhost:5000"

def check_server():
    """Check if the server is running"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def generate_key(key_id, encrypt=True):
    """Generate a new key pair with optional encryption"""
    password = None
    if encrypt:
        password = getpass.getpass("Enter password to encrypt private key (press Enter for no encryption): ")
        if not password.strip():
            password = None
            encrypt = False
    
    payload = {
        "key_id": key_id,
        "encrypt": encrypt
    }
    
    if password:
        payload["password"] = password
    
    response = requests.post(f"{BASE_URL}/generate-keys", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Key '{key_id}' generated successfully")
        if result['data']['encrypted']:
            print("🔒 Private key is encrypted and stored securely")
            print(f"Encryption: {result['data']['encryption_info']['algorithm']}")
        else:
            print("⚠️  Private key is stored unencrypted")
        print(f"Public Key (share this):")
        print(result['data']['public_key_pem'])
        return True
    else:
        print(f"❌ Failed to generate key: {response.text}")
        return False

def sign_file(file_path, key_id):
    """Sign a file"""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False
    
    # Check if key is encrypted
    keys_response = requests.get(f"{BASE_URL}/keys")
    if keys_response.status_code == 200:
        keys_data = keys_response.json()
        if key_id in keys_data['keys'] and keys_data['keys'][key_id]['encrypted']:
            password = getpass.getpass("Enter password for encrypted private key: ")
        else:
            password = None
    else:
        password = None
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {'key_id': key_id}
        if password:
            data['password'] = password
        response = requests.post(f"{BASE_URL}/sign-file", files=files, data=data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ File '{file_path}' signed successfully")
        print(f"Signature ID: {result['signature_id']}")
        print(f"File hash: {result['signature_data']['file_hash']}")
        
        # Save signature to file
        sig_file = file_path + ".sig"
        with open(sig_file, 'w') as f:
            json.dump(result['signature_data'], f, indent=2)
        print(f"Signature saved to: {sig_file}")
        return True
    else:
        print(f"❌ Failed to sign file: {response.text}")
        return False

def verify_file(file_path, signature_path=None, key_id=None):
    """Verify a file signature"""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False
    
    # Try signature file if not provided
    if not signature_path:
        signature_path = file_path + ".sig"
    
    if not os.path.exists(signature_path):
        print(f"❌ Signature file not found: {signature_path}")
        return False
    
    with open(signature_path, 'r') as f:
        signature_data = json.load(f)
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'signature_data': json.dumps(signature_data),
            'key_id': key_id or signature_data.get('key_id')
        }
        response = requests.post(f"{BASE_URL}/verify-signature", files=files, data=data)
    
    if response.status_code == 200:
        result = response.json()
        if result['valid']:
            print(f"✅ Signature verification successful: {result['message']}")
            return True
        else:
            print(f"❌ Signature verification failed: {result['message']}")
            return False
    else:
        print(f"❌ Error verifying signature: {response.text}")
        return False

def patch_binary(file_path, key_id, output_path=None):
    """Patch binary with signature"""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False
    
    if not output_path:
        name, ext = os.path.splitext(file_path)
        output_path = f"{name}_signed{ext}"
    
    # Check if key is encrypted
    keys_response = requests.get(f"{BASE_URL}/keys")
    if keys_response.status_code == 200:
        keys_data = keys_response.json()
        if key_id in keys_data['keys'] and keys_data['keys'][key_id]['encrypted']:
            password = getpass.getpass("Enter password for encrypted private key: ")
        else:
            password = None
    else:
        password = None
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {'key_id': key_id}
        if password:
            data['password'] = password
        response = requests.post(f"{BASE_URL}/patch-binary", files=files, data=data)
    
    if response.status_code == 200:
        with open(output_path, 'wb') as f:
            f.write(response.content)
        
        original_size = os.path.getsize(file_path)
        patched_size = os.path.getsize(output_path)
        
        print(f"✅ Binary patched successfully")
        print(f"Original: {file_path} ({original_size} bytes)")
        print(f"Signed: {output_path} ({patched_size} bytes)")
        print(f"Signature overhead: {patched_size - original_size} bytes")
        return True
    else:
        print(f"❌ Failed to patch binary: {response.text}")
        return False

def verify_patched_binary(file_path):
    """Verify a patched binary"""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(f"{BASE_URL}/verify-patched-binary", files=files)
    
    if response.status_code == 200:
        result = response.json()
        if result['valid']:
            print(f"✅ Patched binary verification successful: {result['message']}")
            print(f"Algorithm: {result['signature_info']['algorithm']}")
            print(f"Signed by key: {result['signature_info']['key_id']}")
            print(f"Timestamp: {result['signature_info']['timestamp']}")
            return True
        else:
            print(f"❌ Patched binary verification failed: {result['message']}")
            return False
    else:
        print(f"❌ Error verifying patched binary: {response.text}")
        return False

def list_keys():
    """List all keys with encryption status"""
    response = requests.get(f"{BASE_URL}/keys")
    if response.status_code == 200:
        result = response.json()
        keys = result['keys']
        if keys:
            print("Available keys:")
            for key_id, key_info in keys.items():
                encryption_status = "🔒 Encrypted" if key_info['encrypted'] else "🔓 Unencrypted"
                print(f"  - {key_id} (created: {key_info['created_at']}) [{encryption_status}]")
                if key_info['encrypted']:
                    print(f"    Encryption: {key_info.get('encryption_algorithm', 'N/A')}")
        else:
            print("No keys found")
        return True
    else:
        print(f"❌ Failed to list keys: {response.text}")
        return False

def export_key(key_id, export_format='pem'):
    """Export a key"""
    password = None
    if export_format == 'pem':
        # Check if key is encrypted
        keys_response = requests.get(f"{BASE_URL}/keys")
        if keys_response.status_code == 200:
            keys_data = keys_response.json()
            if key_id in keys_data['keys'] and keys_data['keys'][key_id]['encrypted']:
                password = getpass.getpass("Enter password for encrypted private key: ")
    
    payload = {
        'key_id': key_id,
        'format': export_format
    }
    if password:
        payload['password'] = password
    
    response = requests.post(f"{BASE_URL}/export-key", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Key '{key_id}' exported successfully")
        
        if export_format == 'pem':
            print("Public Key:")
            print(result['public_key_pem'])
            print("\nPrivate Key:")
            print(result['private_key_pem'])
        elif export_format == 'encrypted':
            print("Encrypted private key data:")
            print(json.dumps(result['encrypted_private_key'], indent=2))
        
        return True
    else:
        print(f"❌ Failed to export key: {response.text}")
        return False

def change_key_password(key_id):
    """Change password for an encrypted key"""
    old_password = getpass.getpass("Enter current password: ")
    new_password = getpass.getpass("Enter new password: ")
    confirm_password = getpass.getpass("Confirm new password: ")
    
    if new_password != confirm_password:
        print("❌ Passwords do not match")
        return False
    
    payload = {
        'key_id': key_id,
        'old_password': old_password,
        'new_password': new_password
    }
    
    response = requests.post(f"{BASE_URL}/change-key-password", json=payload)
    
    if response.status_code == 200:
        print(f"✅ Password changed successfully for key '{key_id}'")
        return True
    else:
        print(f"❌ Failed to change password: {response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description='ECC Digital Signing System CLI with Encrypted Keys')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate key command
    gen_parser = subparsers.add_parser('generate-key', help='Generate a new key pair with optional encryption')
    gen_parser.add_argument('key_id', help='Unique identifier for the key')
    gen_parser.add_argument('--no-encrypt', action='store_true', help='Store private key unencrypted')
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign a file')
    sign_parser.add_argument('file', help='File to sign')
    sign_parser.add_argument('key_id', help='Key ID to use for signing')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a file signature')
    verify_parser.add_argument('file', help='File to verify')
    verify_parser.add_argument('--signature', help='Signature file (default: file.sig)')
    verify_parser.add_argument('--key-id', help='Key ID for verification')
    
    # Patch command
    patch_parser = subparsers.add_parser('patch', help='Patch binary with signature')
    patch_parser.add_argument('file', help='File to patch')
    patch_parser.add_argument('key_id', help='Key ID to use for signing')
    patch_parser.add_argument('--output', help='Output file path')
    
    # Verify patched command
    verify_patched_parser = subparsers.add_parser('verify-patched', help='Verify a patched binary')
    verify_patched_parser.add_argument('file', help='Patched file to verify')
    
    # List keys command
    subparsers.add_parser('list-keys', help='List all available keys')
    
    # Export key command
    export_parser = subparsers.add_parser('export-key', help='Export a private key')
    export_parser.add_argument('key_id', help='Key ID to export')
    export_parser.add_argument('--format', choices=['pem', 'encrypted'], default='pem', 
                              help='Export format (pem or encrypted)')
    
    # Change password command
    passwd_parser = subparsers.add_parser('change-password', help='Change password for encrypted key')
    passwd_parser.add_argument('key_id', help='Key ID to change password for')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Check if server is running
    if not check_server():
        print("❌ Server is not running. Please start the Flask server first:")
        print("   uv run main.py")
        sys.exit(1)
    
    # Execute commands
    success = False
    
    if args.command == 'generate-key':
        success = generate_key(args.key_id, not args.no_encrypt)
    elif args.command == 'sign':
        success = sign_file(args.file, args.key_id)
    elif args.command == 'verify':
        success = verify_file(args.file, args.signature, args.key_id)
    elif args.command == 'patch':
        success = patch_binary(args.file, args.key_id, args.output)
    elif args.command == 'verify-patched':
        success = verify_patched_binary(args.file)
    elif args.command == 'list-keys':
        success = list_keys()
    elif args.command == 'export-key':
        success = export_key(args.key_id, args.format)
    elif args.command == 'change-password':
        success = change_key_password(args.key_id)
    
    sys.exit(0 if success else 1)
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign a file')
    sign_parser.add_argument('file', help='File to sign')
    sign_parser.add_argument('key_id', help='Key ID to use for signing')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a file signature')
    verify_parser.add_argument('file', help='File to verify')
    verify_parser.add_argument('--signature', help='Signature file (default: file.sig)')
    verify_parser.add_argument('--key-id', help='Key ID for verification')
    
    # Patch command
    patch_parser = subparsers.add_parser('patch', help='Patch binary with signature')
    patch_parser.add_argument('file', help='File to patch')
    patch_parser.add_argument('key_id', help='Key ID to use for signing')
    patch_parser.add_argument('--output', help='Output file path')
    
    # Verify patched command
    verify_patched_parser = subparsers.add_parser('verify-patched', help='Verify a patched binary')
    verify_patched_parser.add_argument('file', help='Patched file to verify')
    
    # List keys command
    subparsers.add_parser('list-keys', help='List all available keys')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Check if server is running
    if not check_server():
        print("❌ Server is not running. Please start the Flask server first:")
        print("   python main.py")
        sys.exit(1)
    
    # Execute commands
    success = False
    
    if args.command == 'generate-key':
        success = generate_key(args.key_id)
    elif args.command == 'sign':
        success = sign_file(args.file, args.key_id)
    elif args.command == 'verify':
        success = verify_file(args.file, args.signature, args.key_id)
    elif args.command == 'patch':
        success = patch_binary(args.file, args.key_id, args.output)
    elif args.command == 'verify-patched':
        success = verify_patched_binary(args.file)
    elif args.command == 'list-keys':
        success = list_keys()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
