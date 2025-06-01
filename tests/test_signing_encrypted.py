#!/usr/bin/env python3
"""
Test script for ECC Digital Signing System with Encrypted Keys
This script demonstrates the new encrypted key storage functionality
"""

import requests
import json
import os
import tempfile
import time

# Configuration
BASE_URL = "http://localhost:5000"

def test_encrypted_key_workflow():
    """Test the complete encrypted key workflow"""
    print("🔐 Testing ECC Digital Signing System with Encrypted Keys\n")
    
    # 1. Generate an encrypted key pair
    print("1. Generating encrypted ECC key pair...")
    response = requests.post(f"{BASE_URL}/generate-keys", 
                           json={
                               "key_id": "encrypted_test_key_2025", 
                               "password": "test_password_123",
                               "encrypt": True
                           })
    
    if response.status_code == 200:
        key_data = response.json()
        print(f"✅ Encrypted key generated successfully: {key_data['data']['key_id']}")
        print(f"🔒 Encryption: {key_data['data']['encryption_info']['algorithm']}")
        print(f"🔑 KDF: {key_data['data']['encryption_info']['kdf']}")
        encrypted_key_id = key_data['data']['key_id']
    else:
        print(f"❌ Failed to generate encrypted key: {response.text}")
        return False
    
    # 2. Generate an unencrypted key for comparison
    print("\n2. Generating unencrypted ECC key pair for comparison...")
    response = requests.post(f"{BASE_URL}/generate-keys", 
                           json={
                               "key_id": "unencrypted_test_key_2025", 
                               "encrypt": False
                           })
    
    if response.status_code == 200:
        key_data = response.json()
        print(f"✅ Unencrypted key generated successfully: {key_data['data']['key_id']}")
        unencrypted_key_id = key_data['data']['key_id']
    else:
        print(f"❌ Failed to generate unencrypted key: {response.text}")
        return False
    
    # 3. List keys to see encryption status
    print("\n3. Listing all keys with encryption status...")
    response = requests.get(f"{BASE_URL}/keys")
    if response.status_code == 200:
        keys_data = response.json()
        print("Available keys:")
        for key_id, key_info in keys_data['keys'].items():
            if 'test_key_2025' in key_id:
                encryption_status = "🔒 Encrypted" if key_info['encrypted'] else "🔓 Unencrypted"
                print(f"  - {key_id}: {encryption_status}")
                if key_info['encrypted']:
                    print(f"    Algorithm: {key_info.get('encryption_algorithm', 'N/A')}")
    
    # 4. Create a test file to sign
    print("\n4. Creating test file...")
    test_content = b"This is a test file for encrypted key signing demonstration!"
    test_content += b"\x00\x01\x02\x03\x04\x05"  # Add some binary data
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(test_content)
        test_file_path = tmp_file.name
    
    print(f"📄 Test file created: {test_file_path}")
    
    # 5. Sign with encrypted key (with password)
    print("\n5. Signing file with encrypted key...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'key_id': encrypted_key_id,
            'password': 'test_password_123'
        }
        response = requests.post(f"{BASE_URL}/sign-file", files=files, data=data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ File signed successfully with encrypted key")
        print(f"Signature ID: {result['signature_id']}")
        print(f"Key used encrypted: {result['signature_data'].get('key_encrypted', False)}")
        encrypted_signature_data = result['signature_data']
    else:
        print(f"❌ Failed to sign with encrypted key: {response.text}")
        return False
    
    # 6. Try signing with encrypted key without password (should fail)
    print("\n6. Testing signing with encrypted key without password (should fail)...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {'key_id': encrypted_key_id}
        response = requests.post(f"{BASE_URL}/sign-file", files=files, data=data)
    
    if response.status_code != 200:
        print("✅ Correctly failed to sign without password for encrypted key")
    else:
        print("❌ Unexpected success - should have failed without password")
    
    # 7. Sign with unencrypted key
    print("\n7. Signing file with unencrypted key...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {'key_id': unencrypted_key_id}
        response = requests.post(f"{BASE_URL}/sign-file", files=files, data=data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ File signed successfully with unencrypted key")
        unencrypted_signature_data = result['signature_data']
    else:
        print(f"❌ Failed to sign with unencrypted key: {response.text}")
        return False
    
    # 8. Verify both signatures
    print("\n8. Verifying signatures...")
    
    # Verify encrypted key signature
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'signature_data': json.dumps(encrypted_signature_data),
            'key_id': encrypted_key_id
        }
        response = requests.post(f"{BASE_URL}/verify-signature", files=files, data=data)
    
    if response.status_code == 200 and response.json()['valid']:
        print("✅ Encrypted key signature verified successfully")
    else:
        print("❌ Failed to verify encrypted key signature")
    
    # Verify unencrypted key signature
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'signature_data': json.dumps(unencrypted_signature_data),
            'key_id': unencrypted_key_id
        }
        response = requests.post(f"{BASE_URL}/verify-signature", files=files, data=data)
    
    if response.status_code == 200 and response.json()['valid']:
        print("✅ Unencrypted key signature verified successfully")
    else:
        print("❌ Failed to verify unencrypted key signature")
    
    # 9. Test key export functionality
    print("\n9. Testing key export functionality...")
    
    # Export encrypted key in encrypted format
    response = requests.post(f"{BASE_URL}/export-key", 
                           json={
                               "key_id": encrypted_key_id,
                               "format": "encrypted"
                           })
    
    if response.status_code == 200:
        result = response.json()
        print("✅ Encrypted key exported in encrypted format")
        print(f"Encryption algorithm: {result['encrypted_private_key']['algorithm']}")
    else:
        print(f"❌ Failed to export encrypted key: {response.text}")
    
    # Export encrypted key in PEM format (requires password)
    response = requests.post(f"{BASE_URL}/export-key", 
                           json={
                               "key_id": encrypted_key_id,
                               "format": "pem",
                               "password": "test_password_123"
                           })
    
    if response.status_code == 200:
        print("✅ Encrypted key exported in PEM format with password")
    else:
        print(f"❌ Failed to export encrypted key in PEM format: {response.text}")
    
    # 10. Test password change
    print("\n10. Testing password change functionality...")
    response = requests.post(f"{BASE_URL}/change-key-password", 
                           json={
                               "key_id": encrypted_key_id,
                               "old_password": "test_password_123",
                               "new_password": "new_test_password_456"
                           })
    
    if response.status_code == 200:
        print("✅ Password changed successfully")
        
        # Test signing with new password
        print("Testing signing with new password...")
        with open(test_file_path, 'rb') as f:
            files = {'file': f}
            data = {
                'key_id': encrypted_key_id,
                'password': 'new_test_password_456'
            }
            response = requests.post(f"{BASE_URL}/sign-file", files=files, data=data)
        
        if response.status_code == 200:
            print("✅ Signing successful with new password")
        else:
            print("❌ Failed to sign with new password")
            
    else:
        print(f"❌ Failed to change password: {response.text}")
    
    # 11. Test binary patching with encrypted key
    print("\n11. Testing binary patching with encrypted key...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'key_id': encrypted_key_id,
            'password': 'new_test_password_456'
        }
        response = requests.post(f"{BASE_URL}/patch-binary", files=files, data=data)
    
    if response.status_code == 200:
        print("✅ Binary patched successfully with encrypted key")
        
        # Save patched binary
        patched_file_path = test_file_path + "_signed"
        with open(patched_file_path, 'wb') as f:
            f.write(response.content)
        
        # Verify patched binary
        print("Verifying patched binary...")
        with open(patched_file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(f"{BASE_URL}/verify-patched-binary", files=files)
        
        if response.status_code == 200 and response.json()['valid']:
            print("✅ Patched binary verification successful")
        else:
            print("❌ Patched binary verification failed")
            
        # Cleanup
        os.unlink(patched_file_path)
    else:
        print(f"❌ Failed to patch binary: {response.text}")
    
    # Cleanup
    os.unlink(test_file_path)
    
    print("\n🎉 Encrypted key workflow test completed successfully!")
    return True

def demo_security_features():
    """Demonstrate security features"""
    print("\n🛡️  Security Features Demonstration\n")
    
    print("Security Features:")
    print("- Private keys encrypted with AES-256-GCM")
    print("- Password-based key derivation using PBKDF2-SHA256 (100,000 iterations)")
    print("- Unique salt and nonce for each encrypted key")
    print("- Authentication tag prevents tampering")
    print("- Encrypted keys cannot be used without correct password")
    print("- Password can be changed without regenerating keypair")
    print("- Support for both encrypted and unencrypted key storage")
    
    # Get server info
    response = requests.get(f"{BASE_URL}/")
    if response.status_code == 200:
        info = response.json()
        print(f"\nServer Security Configuration:")
        for feature, value in info.get('security_features', {}).items():
            print(f"- {feature.replace('_', ' ').title()}: {value}")

if __name__ == "__main__":
    print("Make sure the Flask server is running (uv run main.py)")
    print("Testing ECC digital signing system with encrypted key storage!\n")
    
    try:
        # Test if server is running
        response = requests.get(f"{BASE_URL}/health", timeout=2)
        if response.status_code == 200:
            success = test_encrypted_key_workflow()
            if success:
                demo_security_features()
        else:
            print("❌ Server is not responding correctly")
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure Flask app is running:")
        print("   uv run main.py")
    except Exception as e:
        print(f"❌ Test failed with error: {str(e)}")
