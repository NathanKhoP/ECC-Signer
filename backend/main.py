
from flask import Flask, request, jsonify, send_file
import os
import hashlib
import base64
import json
from datetime import datetime
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import io
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

app = Flask(__name__)

class ECCDigitalSigner:
    def __init__(self, storage_dir="keys", signatures_dir="signatures"):
        self.storage_dir = storage_dir
        self.signatures_dir = signatures_dir
        self.key_storage = {}  # Cache for loaded keys
        self.signatures_db = {}  # Cache for loaded signatures - now with persistent storage
        
        # Create storage directories if they don't exist
        os.makedirs(self.storage_dir, exist_ok=True)
        os.makedirs(self.signatures_dir, exist_ok=True)
        
        # Load existing keys and signatures from storage
        self._load_keys_from_storage()
        self._load_signatures_from_storage()
    
    def _get_key_file_path(self, key_id):
        """Get the file path for a key"""
        return os.path.join(self.storage_dir, f"{key_id}.json")
    
    def _get_signature_file_path(self, signature_id):
        """Get the file path for a signature"""
        return os.path.join(self.signatures_dir, f"{signature_id}.json")
    
    def _save_key_to_storage(self, key_id, key_data):
        """Save key data to persistent storage"""
        file_path = self._get_key_file_path(key_id)
        
        # Prepare data for storage
        storage_data = {
            'key_id': key_id,
            'created_at': key_data['created_at'],
            'encrypted': key_data.get('encrypted', False),
            'public_key_pem': key_data['public_key'].to_pem().decode('utf-8')
        }
        
        # Add private key data (encrypted or unencrypted)
        if 'encrypted_private_key' in key_data:
            storage_data['encrypted_private_key'] = key_data['encrypted_private_key']
        elif 'private_key' in key_data:
            storage_data['private_key_pem'] = key_data['private_key'].to_pem().decode('utf-8')
        
        # Save to file
        with open(file_path, 'w') as f:
            json.dump(storage_data, f, indent=2)
    
    def _load_keys_from_storage(self):
        """Load all keys from storage directory"""
        if not os.path.exists(self.storage_dir):
            return
        
        for filename in os.listdir(self.storage_dir):
            if filename.endswith('.json'):
                key_id = filename[:-5]  # Remove .json extension
                self._load_key_from_storage(key_id)
    
    def _load_key_from_storage(self, key_id):
        """Load a specific key from storage"""
        file_path = self._get_key_file_path(key_id)
        
        if not os.path.exists(file_path):
            return None
        
        try:
            with open(file_path, 'r') as f:
                storage_data = json.load(f)
            
            # Reconstruct key data
            key_data = {
                'created_at': storage_data['created_at'],
                'encrypted': storage_data.get('encrypted', False),
                'public_key': VerifyingKey.from_pem(storage_data['public_key_pem'])
            }
            
            # Load private key data
            if 'encrypted_private_key' in storage_data:
                key_data['encrypted_private_key'] = storage_data['encrypted_private_key']
            elif 'private_key_pem' in storage_data:
                key_data['private_key'] = SigningKey.from_pem(storage_data['private_key_pem'])
            
            # Cache in memory
            self.key_storage[key_id] = key_data
            return key_data
            
        except Exception as e:
            print(f"Error loading key {key_id}: {e}")
            return None
    
    def _save_signature_to_storage(self, signature_id, signature_data):
        """Save signature data to persistent storage"""
        file_path = self._get_signature_file_path(signature_id)
        
        # Prepare data for storage
        storage_data = {
            'signature_id': signature_id,
            'signature_data': signature_data,
            'saved_at': datetime.now().isoformat()
        }
        
        # Save to file
        try:
            with open(file_path, 'w') as f:
                json.dump(storage_data, f, indent=2)
        except Exception as e:
            print(f"Error saving signature {signature_id}: {e}")
    
    def _load_signatures_from_storage(self):
        """Load all signatures from storage directory"""
        if not os.path.exists(self.signatures_dir):
            return
        
        for filename in os.listdir(self.signatures_dir):
            if filename.endswith('.json'):
                signature_id = filename[:-5]  # Remove .json extension
                self._load_signature_from_storage(signature_id)
    
    def _load_signature_from_storage(self, signature_id):
        """Load a specific signature from storage"""
        file_path = self._get_signature_file_path(signature_id)
        
        if not os.path.exists(file_path):
            return None
        
        try:
            with open(file_path, 'r') as f:
                storage_data = json.load(f)
            
            # Load signature data into memory cache
            self.signatures_db[signature_id] = storage_data['signature_data']
            return storage_data['signature_data']
            
        except Exception as e:
            print(f"Error loading signature {signature_id}: {e}")
            return None
    
    def _derive_encryption_key(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        return PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA256)
    
    def _encrypt_private_key(self, private_key_pem, password):
        """Encrypt private key using AES-256-GCM with password-derived key"""
        # Generate random salt and nonce
        salt = get_random_bytes(16)
        nonce = get_random_bytes(12)
        
        # Derive encryption key from password
        key = self._derive_encryption_key(password.encode('utf-8'), salt)
        
        # Encrypt the private key
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(private_key_pem.encode('utf-8'))
        
        # Package encrypted data
        encrypted_data = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-SHA256'
        }
        
        return encrypted_data
    
    def _decrypt_private_key(self, encrypted_data, password):
        """Decrypt private key using the provided password"""
        try:
            # Extract components
            salt = base64.b64decode(encrypted_data['salt'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            # Derive decryption key
            key = self._derive_encryption_key(password.encode('utf-8'), salt)
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            private_key_pem = cipher.decrypt_and_verify(ciphertext, tag)
            
            return private_key_pem.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: {str(e)}")
    
    def _get_private_key(self, key_id, password=None):
        """Get decrypted private key for signing operations"""
        if key_id not in self.key_storage:
            raise ValueError(f"Key ID {key_id} not found")
        
        key_data = self.key_storage[key_id]
        
        # If key is encrypted, decrypt it
        if 'encrypted_private_key' in key_data:
            if password is None:
                raise ValueError("Password required for encrypted private key")
            
            private_key_pem = self._decrypt_private_key(key_data['encrypted_private_key'], password)
            return SigningKey.from_pem(private_key_pem)
        
        # Return unencrypted key (legacy support)
        return key_data['private_key']
    
    def generate_key_pair(self, key_id, password=None, store_encrypted=True):
        """Generate a new ECC key pair with optional encryption"""
        # Using ECDSA library
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        
        private_key_pem = private_key.to_pem().decode('utf-8')
        public_key_pem = public_key.to_pem().decode('utf-8')
        
        # Prepare key storage data
        key_storage_data = {
            'public_key': public_key,
            'created_at': datetime.now().isoformat(),
            'encrypted': store_encrypted and password is not None
        }
        
        # Store private key (encrypted or unencrypted)
        if store_encrypted and password is not None:
            # Encrypt and store private key
            encrypted_private_key = self._encrypt_private_key(private_key_pem, password)
            key_storage_data['encrypted_private_key'] = encrypted_private_key
            
            # Return result without plaintext private key for security
            result = {
                'key_id': key_id,
                'public_key_pem': public_key_pem,
                'encrypted': True,
                'encryption_info': {
                    'algorithm': encrypted_private_key['algorithm'],
                    'kdf': encrypted_private_key['kdf']
                }
            }
        else:
            # Store unencrypted (for backward compatibility)
            key_storage_data['private_key'] = private_key
            result = {
                'key_id': key_id,
                'public_key_pem': public_key_pem,
                'private_key_pem': private_key_pem,
                'encrypted': False
            }
        
        # Store in key storage
        self.key_storage[key_id] = key_storage_data
        
        # Save to persistent storage
        self._save_key_to_storage(key_id, key_storage_data)
        
        return result
    
    def sign_file(self, file_data, key_id, password=None):
        """Sign a file using ECC digital signature"""
        if key_id not in self.key_storage:
            raise ValueError(f"Key ID {key_id} not found")
        
        # Get private key (decrypt if necessary)
        private_key = self._get_private_key(key_id, password)
        
        # Calculate file hash
        file_hash = hashlib.sha256(file_data).digest()
        
        # Sign the hash
        signature = private_key.sign(file_hash)
        
        # Create signature metadata
        signature_data = {
            'signature': base64.b64encode(signature).decode('utf-8'),
            'file_hash': hashlib.sha256(file_data).hexdigest(),
            'key_id': key_id,
            'timestamp': datetime.now().isoformat(),
            'algorithm': 'ECDSA-SECP256k1',
            'file_size': len(file_data),
            'key_encrypted': self.key_storage[key_id].get('encrypted', False)
        }
        
        # Store signature record
        signature_id = hashlib.sha256(
            f"{key_id}{signature_data['timestamp']}{signature_data['file_hash']}".encode()
        ).hexdigest()[:16]
        
        # Store in memory cache
        self.signatures_db[signature_id] = signature_data
        
        # Save to persistent storage
        self._save_signature_to_storage(signature_id, signature_data)
        
        return signature_id, signature_data
    
    def verify_signature(self, file_data, signature_data, key_id=None):
        """Verify a file signature"""
        try:
            # Get key_id from signature if not provided
            if key_id is None:
                key_id = signature_data['key_id']
            
            if key_id not in self.key_storage:
                return False, "Key not found"
            
            # Verify file hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            if file_hash != signature_data['file_hash']:
                return False, "File hash mismatch"
            
            # Verify signature
            public_key = self.key_storage[key_id]['public_key']
            signature = base64.b64decode(signature_data['signature'])
            original_hash = hashlib.sha256(file_data).digest()
            
            try:
                public_key.verify(signature, original_hash)
                return True, "Signature valid"
            except:
                return False, "Invalid signature"
                
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def patch_binary_with_signature(self, file_data, signature_data):
        """Patch binary file with signature metadata"""
        # Create signature block
        signature_block = {
            'signature_metadata': signature_data,
            'ecc_signature_marker': 'ECC_DIGITAL_SIGNATURE'
        }
        
        signature_json = json.dumps(signature_block, indent=2)
        signature_bytes = signature_json.encode('utf-8')
        
        # Create marker for finding signature in binary
        marker = b'---ECC_SIGNATURE_START---'
        end_marker = b'---ECC_SIGNATURE_END---'
        
        # Patch the binary
        patched_data = file_data + marker + signature_bytes + end_marker
        
        return patched_data
    
    def extract_signature_from_patched_binary(self, patched_data):
        """Extract signature from patched binary"""
        marker = b'---ECC_SIGNATURE_START---'
        end_marker = b'---ECC_SIGNATURE_END---'
        
        start_idx = patched_data.rfind(marker)
        end_idx = patched_data.rfind(end_marker)
        
        if start_idx == -1 or end_idx == -1:
            return None, None
        
        signature_bytes = patched_data[start_idx + len(marker):end_idx]
        original_data = patched_data[:start_idx]
        
        try:
            signature_block = json.loads(signature_bytes.decode('utf-8'))
            return original_data, signature_block['signature_metadata']
        except:
            return None, None

# Initialize the signer
signer = ECCDigitalSigner()

@app.route('/')
def index():
    return jsonify({
        'message': 'ECC Digital Signing Service with Encrypted Key Storage',
        'endpoints': {
            'generate_keys': '/generate-keys',
            'sign_file': '/sign-file',
            'verify_signature': '/verify-signature',
            'patch_binary': '/patch-binary',
            'verify_patched_binary': '/verify-patched-binary',
            'list_keys': '/keys',
            'export_key': '/export-key',
            'change_key_password': '/change-key-password',
            'list_signatures': '/signatures'
        },
        'security_features': {
            'private_key_encryption': 'AES-256-GCM',
            'key_derivation': 'PBKDF2-SHA256',
            'elliptic_curve': 'SECP256k1',
            'hash_algorithm': 'SHA-256'
        }
    })

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """Generate a new ECC key pair with optional encryption"""
    data = request.get_json() or {}
    key_id = data.get('key_id', f"key_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    password = data.get('password')  # Optional password for encryption
    store_encrypted = data.get('encrypt', True)  # Default to encrypted storage
    
    try:
        result = signer.generate_key_pair(key_id, password, store_encrypted)
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/sign-file', methods=['POST'])
def sign_file():
    """Sign an uploaded file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    key_id = request.form.get('key_id')
    password = request.form.get('password')  # Password for encrypted keys
    
    if not key_id:
        return jsonify({'success': False, 'error': 'key_id required'}), 400
    
    try:
        file_data = file.read()
        signature_id, signature_data = signer.sign_file(file_data, key_id, password)
        
        return jsonify({
            'success': True,
            'signature_id': signature_id,
            'signature_data': signature_data,
            'file_info': {
                'filename': file.filename,
                'size': len(file_data),
                'hash': signature_data['file_hash']
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/verify-signature', methods=['POST'])
def verify_signature():
    """Verify a file signature"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    signature_data = request.form.get('signature_data')
    key_id = request.form.get('key_id')
    
    if not signature_data:
        return jsonify({'success': False, 'error': 'signature_data required'}), 400
    
    try:
        file_data = file.read()
        signature_dict = json.loads(signature_data)
        
        is_valid, message = signer.verify_signature(file_data, signature_dict, key_id)
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': message,
            'file_info': {
                'filename': file.filename,
                'size': len(file_data),
                'hash': hashlib.sha256(file_data).hexdigest()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/patch-binary', methods=['POST'])
def patch_binary():
    """Patch binary with signature and return the patched file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    key_id = request.form.get('key_id')
    password = request.form.get('password')  # Password for encrypted keys
    
    if not key_id:
        return jsonify({'success': False, 'error': 'key_id required'}), 400
    
    try:
        file_data = file.read()
        
        # Sign the file
        signature_id, signature_data = signer.sign_file(file_data, key_id, password)
        
        # Patch the binary
        patched_data = signer.patch_binary_with_signature(file_data, signature_data)
        
        # Return patched file
        return send_file(
            io.BytesIO(patched_data),
            as_attachment=True,
            download_name=f"signed_{file.filename}",
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/verify-patched-binary', methods=['POST'])
def verify_patched_binary():
    """Verify a patched binary file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    try:
        patched_data = file.read()
        
        # Extract signature and original data
        original_data, signature_data = signer.extract_signature_from_patched_binary(patched_data)
        
        if original_data is None or signature_data is None:
            return jsonify({
                'success': False,
                'error': 'No valid signature found in file'
            }), 400
        
        # Verify the signature
        is_valid, message = signer.verify_signature(original_data, signature_data)
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'message': message,
            'signature_info': signature_data,
            'file_info': {
                'filename': file.filename,
                'original_size': len(original_data),
                'patched_size': len(patched_data),
                'signature_size': len(patched_data) - len(original_data)
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/keys', methods=['GET'])
def list_keys():
    """List all generated keys with encryption status"""
    keys_info = {}
    for key_id, key_data in signer.key_storage.items():
        key_info = {
            'created_at': key_data['created_at'],
            'public_key_pem': key_data['public_key'].to_pem().decode('utf-8'),
            'encrypted': key_data.get('encrypted', False)
        }
        
        # Add encryption details if key is encrypted
        if key_info['encrypted'] and 'encrypted_private_key' in key_data:
            encryption_info = key_data['encrypted_private_key']
            key_info['encryption_algorithm'] = encryption_info.get('algorithm', 'Unknown')
            key_info['kdf'] = encryption_info.get('kdf', 'Unknown')
        
        keys_info[key_id] = key_info
    
    return jsonify({
        'success': True,
        'keys': keys_info
    })

@app.route('/export-key', methods=['POST'])
def export_key():
    """Export private key (requires password for encrypted keys)"""
    data = request.get_json() or {}
    key_id = data.get('key_id')
    password = data.get('password')
    export_format = data.get('format', 'pem')  # pem or encrypted
    
    if not key_id:
        return jsonify({'success': False, 'error': 'key_id required'}), 400
    
    if key_id not in signer.key_storage:
        return jsonify({'success': False, 'error': 'Key not found'}), 404
    
    try:
        key_data = signer.key_storage[key_id]
        
        if export_format == 'encrypted' and 'encrypted_private_key' in key_data:
            # Return encrypted private key data
            return jsonify({
                'success': True,
                'key_id': key_id,
                'encrypted_private_key': key_data['encrypted_private_key'],
                'public_key_pem': key_data['public_key'].to_pem().decode('utf-8')
            })
        elif export_format == 'pem':
            # Decrypt and return PEM format
            if key_data.get('encrypted', False):
                if not password:
                    return jsonify({'success': False, 'error': 'Password required for encrypted key'}), 400
                
                private_key_pem = signer._decrypt_private_key(key_data['encrypted_private_key'], password)
            else:
                private_key_pem = key_data['private_key'].to_pem().decode('utf-8')
            
            return jsonify({
                'success': True,
                'key_id': key_id,
                'private_key_pem': private_key_pem,
                'public_key_pem': key_data['public_key'].to_pem().decode('utf-8')
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid export format'}), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/change-key-password', methods=['POST'])
def change_key_password():
    """Change password for an encrypted private key"""
    data = request.get_json() or {}
    key_id = data.get('key_id')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not all([key_id, old_password, new_password]):
        return jsonify({'success': False, 'error': 'key_id, old_password, and new_password required'}), 400
    
    if key_id not in signer.key_storage:
        return jsonify({'success': False, 'error': 'Key not found'}), 404
    
    try:
        key_data = signer.key_storage[key_id]
        
        if not key_data.get('encrypted', False):
            return jsonify({'success': False, 'error': 'Key is not encrypted'}), 400
        
        # Decrypt with old password
        private_key_pem = signer._decrypt_private_key(key_data['encrypted_private_key'], old_password)
        
        # Re-encrypt with new password
        new_encrypted_data = signer._encrypt_private_key(private_key_pem, new_password)
        
        # Update stored data
        signer.key_storage[key_id]['encrypted_private_key'] = new_encrypted_data
        
        # Save to persistent storage
        signer._save_key_to_storage(key_id, signer.key_storage[key_id])
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully',
            'key_id': key_id
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/signatures', methods=['GET'])
def list_signatures():
    """List all signatures"""
    return jsonify({
        'success': True,
        'signatures': signer.signatures_db
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'keys_count': len(signer.key_storage),
        'signatures_count': len(signer.signatures_db)
    })

def main():
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()
