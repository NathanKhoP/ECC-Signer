#!/usr/bin/env python3
"""
Test script for ECC Digital Signing System
This script demonstrates how to use the digital signing service
"""

import requests
import json
import os
import tempfile

# Configuration
BASE_URL = "http://localhost:5000"

def test_digital_signing_system():
    """Test the complete digital signing workflow"""
    print("🔐 Testing ECC Digital Signing System\n")
    
    # 1. Generate a key pair
    print("1. Generating ECC key pair...")
    response = requests.post(f"{BASE_URL}/generate-keys", 
                           json={"key_id": "test_key_2024"})
    
    if response.status_code == 200:
        key_data = response.json()
        print(f"✅ Key generated successfully: {key_data['data']['key_id']}")
        key_id = key_data['data']['key_id']
    else:
        print(f"❌ Failed to generate key: {response.text}")
        return
    
    # 2. Create a test binary file
    print("\n2. Creating test binary file...")
    test_content = b"This is a test binary file content for ECC signing demo!"
    test_content += b"\x00\x01\x02\x03\x04\x05"  # Add some binary data
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(test_content)
        test_file_path = tmp_file.name
    
    print(f"✅ Test file created: {os.path.basename(test_file_path)}")
    
    # 3. Sign the file
    print("\n3. Signing the test file...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {'key_id': key_id}
        response = requests.post(f"{BASE_URL}/sign-file", files=files, data=data)
    
    if response.status_code == 200:
        sign_result = response.json()
        print(f"✅ File signed successfully")
        print(f"   Signature ID: {sign_result['signature_id']}")
        print(f"   File hash: {sign_result['signature_data']['file_hash']}")
        signature_data = sign_result['signature_data']
    else:
        print(f"❌ Failed to sign file: {response.text}")
        return
    
    # 4. Verify the signature
    print("\n4. Verifying the signature...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'signature_data': json.dumps(signature_data),
            'key_id': key_id
        }
        response = requests.post(f"{BASE_URL}/verify-signature", files=files, data=data)
    
    if response.status_code == 200:
        verify_result = response.json()
        if verify_result['valid']:
            print(f"✅ Signature verification: {verify_result['message']}")
        else:
            print(f"❌ Signature verification failed: {verify_result['message']}")
    else:
        print(f"❌ Failed to verify signature: {response.text}")
    
    # 5. Patch binary with signature
    print("\n5. Patching binary with signature...")
    with open(test_file_path, 'rb') as f:
        files = {'file': f}
        data = {'key_id': key_id}
        response = requests.post(f"{BASE_URL}/patch-binary", files=files, data=data)
    
    if response.status_code == 200:
        # Save the patched binary
        patched_file_path = test_file_path + ".signed"
        with open(patched_file_path, 'wb') as f:
            f.write(response.content)
        print(f"✅ Binary patched and saved as: {os.path.basename(patched_file_path)}")
        
        # Show size difference
        original_size = os.path.getsize(test_file_path)
        patched_size = os.path.getsize(patched_file_path)
        print(f"   Original size: {original_size} bytes")
        print(f"   Patched size: {patched_size} bytes")
        print(f"   Signature overhead: {patched_size - original_size} bytes")
        
    else:
        print(f"❌ Failed to patch binary: {response.text}")
        return
    
    # 6. Verify patched binary
    print("\n6. Verifying the patched binary...")
    with open(patched_file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(f"{BASE_URL}/verify-patched-binary", files=files)
    
    if response.status_code == 200:
        verify_result = response.json()
        if verify_result['valid']:
            print(f"✅ Patched binary verification: {verify_result['message']}")
            print(f"   Signature algorithm: {verify_result['signature_info']['algorithm']}")
            print(f"   Signing timestamp: {verify_result['signature_info']['timestamp']}")
        else:
            print(f"❌ Patched binary verification failed: {verify_result['message']}")
    else:
        print(f"❌ Failed to verify patched binary: {response.text}")
    
    # 7. Test integrity - modify file and verify again
    print("\n7. Testing integrity detection...")
    modified_content = test_content + b"TAMPERED!"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(modified_content)
        modified_file_path = tmp_file.name
    
    with open(modified_file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'signature_data': json.dumps(signature_data),
            'key_id': key_id
        }
        response = requests.post(f"{BASE_URL}/verify-signature", files=files, data=data)
    
    if response.status_code == 200:
        verify_result = response.json()
        if not verify_result['valid']:
            print(f"✅ Tampering detected: {verify_result['message']}")
        else:
            print(f"❌ Failed to detect tampering!")
    
    # 8. Show system status
    print("\n8. System status:")
    response = requests.get(f"{BASE_URL}/health")
    if response.status_code == 200:
        health = response.json()
        print(f"   Status: {health['status']}")
        print(f"   Keys generated: {health['keys_count']}")
        print(f"   Signatures created: {health['signatures_count']}")
    
    # Cleanup
    os.unlink(test_file_path)
    os.unlink(patched_file_path)
    os.unlink(modified_file_path)
    
    print("\n🎉 Digital signing system test completed!")

def demo_api_usage():
    """Demonstrate various API endpoints"""
    print("\n📋 API Endpoints Demo:")
    
    # List available endpoints
    response = requests.get(f"{BASE_URL}/")
    if response.status_code == 200:
        endpoints = response.json()
        print("Available endpoints:", json.dumps(endpoints, indent=2))
    
    # List keys
    response = requests.get(f"{BASE_URL}/keys")
    if response.status_code == 200:
        keys = response.json()
        print(f"\nKeys in system: {len(keys['keys'])}")
    
    # List signatures
    response = requests.get(f"{BASE_URL}/signatures")
    if response.status_code == 200:
        signatures = response.json()
        print(f"Signatures in system: {len(signatures['signatures'])}")

if __name__ == "__main__":
    print("Make sure the Flask server is running (python main.py)")
    print("Then run this test script to see the ECC digital signing system in action!\n")
    
    try:
        # Test if server is running
        response = requests.get(f"{BASE_URL}/health", timeout=2)
        if response.status_code == 200:
            test_digital_signing_system()
            demo_api_usage()
        else:
            print("❌ Server is not responding correctly")
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure Flask app is running on localhost:5000")
    except Exception as e:
        print(f"❌ Error: {e}")
