# Cryptographic Key Management Troubleshooting Guide

This guide provides comprehensive solutions for cryptographic key management issues, key generation problems, and secure storage challenges in Privatus-chat.

## Table of Contents

1. [Key Generation Issues](#key-generation-issues)
2. [Key Storage and Encryption Problems](#key-storage-and-encryption-problems)
3. [Password and Key Derivation Issues](#password-and-key-derivation-issues)
4. [Prekey Management Problems](#prekey-management-problems)
5. [Double Ratchet Issues](#double-ratchet-issues)
6. [Key Recovery and Backup Issues](#key-recovery-and-backup-issues)
7. [Performance and Security Issues](#performance-and-security-issues)
8. [Diagnostic Tools and Commands](#diagnostic-tools-and-commands)

## Key Generation Issues

### Identity Key Generation Failures

**Problem**: Cannot generate or load identity keys.

**Symptoms**:
- "Failed to generate identity key" errors
- Application startup failures
- Authentication problems

**Solutions**:

1. **Check Cryptographic Library Availability**:
   ```python
   # Verify cryptography library is properly installed
   try:
       from cryptography.hazmat.primitives.asymmetric import ed25519
       print("✓ Cryptography library available")
   except ImportError as e:
       print(f"✗ Cryptography library missing: {e}")
   ```

2. **Test Key Generation**:
   ```python
   # Test basic key generation
   from cryptography.hazmat.primitives.asymmetric import ed25519

   try:
       private_key = ed25519.Ed25519PrivateKey.generate()
       public_key = private_key.public_key()
       print("✓ Key generation works")

       # Test serialization
       public_bytes = public_key.public_bytes(
           encoding=serialization.Encoding.Raw,
           format=serialization.PublicFormat.Raw
       )
       print(f"✓ Public key length: {len(public_bytes)} bytes")

   except Exception as e:
       print(f"✗ Key generation failed: {e}")
   ```

3. **Check System Entropy**:
   ```bash
   # Check available entropy on Linux
   cat /proc/sys/kernel/random/entropy_avail

   # Should be > 1000 for good entropy
   # If low, install rng-tools or haveged
   sudo apt-get install rng-tools
   sudo rngd -r /dev/urandom
   ```

4. **Verify Secure Random Module**:
   ```python
   # Test secure random number generation
   from src.crypto.secure_random import SecureRandom

   try:
       random_bytes = SecureRandom.generate_bytes(32)
       print(f"✓ Secure random works: {len(random_bytes)} bytes")

       random_int = SecureRandom.generate_int(32)
       print(f"✓ Secure random int works: {random_int}")

   except Exception as e:
       print(f"✗ Secure random failed: {e}")
   ```

### Key Manager Initialization Problems

**Problem**: KeyManager fails to initialize properly.

**Solutions**:

1. **Check Storage Path Permissions**:
   ```python
   from pathlib import Path
   import os

   storage_path = Path.home() / '.config' / 'privatus-chat' / 'keys'

   # Check if path exists and is writable
   try:
       storage_path.mkdir(parents=True, exist_ok=True)
       test_file = storage_path / 'test.tmp'
       test_file.write_text('test')
       test_file.unlink()
       print("✓ Storage path is writable")
   except Exception as e:
       print(f"✗ Storage path issue: {e}")
   ```

2. **Verify Password Requirements**:
   ```python
   # Test password validation
   password = "your_password_here"

   if not password or len(password) < 8:
       print("✗ Password too short (minimum 8 characters)")
   else:
       print("✓ Password meets minimum requirements")
   ```

3. **Test KeyManager Creation**:
   ```python
   from src.crypto.key_management import KeyManager
   from pathlib import Path

   try:
       storage_path = Path.home() / '.config' / 'privatus-chat' / 'keys'
       manager = KeyManager(storage_path, password="test_password")
       print("✓ KeyManager created successfully")
   except Exception as e:
       print(f"✗ KeyManager creation failed: {e}")
   ```

## Key Storage and Encryption Problems

### Encrypted Key File Corruption

**Problem**: Key files are corrupted or cannot be decrypted.

**Symptoms**:
- "Failed to decrypt key file" errors
- "Salt mismatch" errors
- "Invalid padding" errors

**Solutions**:

1. **Check File Integrity**:
   ```bash
   # Verify key files exist and have content
   ls -la ~/.config/privatus-chat/keys/
   file ~/.config/privatus-chat/keys/*.enc

   # Check file sizes (should not be zero)
   du -h ~/.config/privatus-chat/keys/*.enc
   ```

2. **Test Decryption Process**:
   ```python
   # Test decryption with known password
   from src.crypto.key_management import KeyManager
   import json

   try:
       manager = KeyManager(storage_path, password="your_password")

       # Try to load identity key
       if manager.identity_key:
           print("✓ Identity key loaded successfully")
       else:
           print("✗ No identity key available")

   except Exception as e:
       print(f"✗ Decryption failed: {e}")
   ```

3. **Verify Salt Consistency**:
   ```python
   # Check if salt matches between encryption and decryption
   import hashlib

   # The salt should be the first 32 bytes of encrypted files
   with open('identity_key.enc', 'rb') as f:
       data = f.read()

   if len(data) >= 32:
       stored_salt = data[:32]
       print(f"✓ Stored salt: {stored_salt.hex()}")

       # Compare with manager's salt
       if manager.encryption_salt == stored_salt:
           print("✓ Salt consistency verified")
       else:
           print("✗ Salt mismatch detected")
   ```

### Storage Path Issues

**Problem**: Cannot write to or read from key storage directory.

**Solutions**:

1. **Check Directory Permissions**:
   ```bash
   # Linux/macOS
   ls -ld ~/.config/privatus-chat/
   ls -ld ~/.config/privatus-chat/keys/

   # Fix permissions if needed
   chmod 700 ~/.config/privatus-chat/
   chmod 700 ~/.config/privatus-chat/keys/
   ```

2. **Windows Permissions**:
   ```powershell
   # Check permissions
   Get-Acl "$env:APPDATA\Privatus-chat\keys" | Format-List

   # Fix permissions if needed
   $acl = Get-Acl "$env:APPDATA\Privatus-chat\keys"
   $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
       $env:USERNAME, "FullControl", "Allow"
   )
   $acl.SetAccessRule($rule)
   Set-Acl "$env:APPDATA\Privatus-chat\keys" $acl
   ```

3. **Test Storage Operations**:
   ```python
   # Test basic file operations
   test_data = b"test encryption data"

   try:
       # Test encryption
       encrypted = manager._encrypt_data(test_data)
       print(f"✓ Encryption works: {len(encrypted)} bytes")

       # Test decryption
       decrypted = manager._decrypt_data(encrypted)
       print(f"✓ Decryption works: {decrypted == test_data}")

   except Exception as e:
       print(f"✗ Storage operation failed: {e}")
   ```

## Password and Key Derivation Issues

### Password Verification Failures

**Problem**: Password verification fails even with correct password.

**Solutions**:

1. **Check Password Encoding**:
   ```python
   # Ensure password is properly encoded
   password = "your_password"
   encoded = password.encode('utf-8')

   print(f"Password: {password}")
   print(f"Encoded: {encoded}")
   print(f"Length: {len(encoded)} bytes")
   ```

2. **Test Key Derivation**:
   ```python
   # Test PBKDF2/Argon2 key derivation
   from src.crypto.key_management import adaptive_pbkdf2_iterations

   try:
       salt = SecureRandom.generate_bytes(32)
       iterations = adaptive_pbkdf2_iterations(password, salt)
       print(f"✓ Adaptive iterations: {iterations:,}")

   except Exception as e:
       print(f"✗ Key derivation failed: {e}")
   ```

3. **Verify Timing-Safe Comparison**:
   ```python
   # Test timing-safe comparison
   from src.crypto.key_management import timing_safe_compare

   key1 = b"test_key_123"
   key2 = b"test_key_123"
   key3 = b"different_key"

   print(f"Same keys: {timing_safe_compare(key1, key2)}")
   print(f"Different keys: {timing_safe_compare(key1, key3)}")
   ```

### Argon2 vs PBKDF2 Fallback Issues

**Problem**: Argon2 not available, falling back to PBKDF2.

**Solutions**:

1. **Install Argon2 Library**:
   ```bash
   # Install argon2-cffi for better security
   pip install argon2-cffi

   # Verify installation
   python -c "import argon2; print('Argon2 available')"
   ```

2. **Check Argon2 Availability**:
   ```python
   # Check which KDF is being used
   try:
       from argon2 import low_level
       ARGON2_AVAILABLE = True
       print("✓ Using Argon2 for key derivation")
   except ImportError:
       ARGON2_AVAILABLE = False
       print("○ Using PBKDF2 (Argon2 not available)")
   ```

3. **Test Performance Impact**:
   ```python
   # Compare performance between Argon2 and PBKDF2
   import time

   # Test Argon2 if available
   if ARGON2_AVAILABLE:
       start = time.time()
       # Argon2 test code here
       argon2_time = time.time() - start
       print(f"Argon2 time: {argon2_time:.3f}s")

   # Test PBKDF2
   start = time.time()
   # PBKDF2 test code here
   pbkdf2_time = time.time() - start
   print(f"PBKDF2 time: {pbkdf2_time:.3f}s")
   ```

## Prekey Management Problems

### Prekey Generation Issues

**Problem**: Cannot generate or manage prekeys.

**Solutions**:

1. **Test Prekey Generation**:
   ```python
   # Test signed prekey generation
   try:
       signed_prekey = manager.generate_signed_prekey(key_id=1)
       print(f"✓ Signed prekey generated: ID {signed_prekey.key_id}")

       # Test one-time prekeys
       one_time_keys = manager.generate_one_time_prekeys(count=10)
       print(f"✓ Generated {len(one_time_keys)} one-time prekeys")

   except Exception as e:
       print(f"✗ Prekey generation failed: {e}")
   ```

2. **Check Prekey Limits**:
   ```python
   # Verify prekey counts
   print(f"One-time prekeys: {len(manager.one_time_prekeys)}")

   # Check for used prekeys
   used_count = sum(1 for pk in manager.one_time_prekeys.values() if pk.used)
   print(f"Used prekeys: {used_count}")
   ```

3. **Test Prekey Bundle Creation**:
   ```python
   # Test prekey bundle for X3DH
   try:
       bundle = manager.get_prekey_bundle()
       print("✓ Prekey bundle created")
       print(f"  Identity key: {len(bundle['identity_key'])} bytes")
       print(f"  Signed prekey ID: {bundle['signed_prekey']['key_id']}")
       print(f"  One-time prekey: {'present' if 'one_time_prekey' in bundle else 'none'}")

   except Exception as e:
       print(f"✗ Prekey bundle creation failed: {e}")
   ```

### Prekey Storage Issues

**Problem**: Prekeys not saving or loading correctly.

**Solutions**:

1. **Check File Operations**:
   ```bash
   # Verify prekey files exist
   ls -la ~/.config/privatus-chat/keys/*.enc

   # Check file modification times
   stat ~/.config/privatus-chat/keys/signed_prekey.enc
   stat ~/.config/privatus-chat/keys/one_time_prekeys.enc
   ```

2. **Test File I/O Operations**:
   ```python
   # Test saving and loading prekeys
   try:
       # Save current state
       manager._save_signed_prekey()
       manager._save_one_time_prekeys()
       print("✓ Prekeys saved successfully")

       # Create new manager and load
       new_manager = KeyManager(storage_path, password="test_password")
       print("✓ Prekeys loaded successfully")

   except Exception as e:
       print(f"✗ Prekey I/O failed: {e}")
   ```

## Double Ratchet Issues

### Session Initialization Problems

**Problem**: Double Ratchet sessions fail to initialize.

**Solutions**:

1. **Check Shared Secret Generation**:
   ```python
   # Test X3DH shared secret generation
   from src.crypto.key_management import KeyManager

   try:
       # Generate test keys
       alice_manager = KeyManager(Path("/tmp/alice"), "alice_password")
       bob_manager = KeyManager(Path("/tmp/bob"), "bob_password")

       alice_manager.generate_identity_key()
       bob_manager.generate_identity_key()

       # Generate prekeys
       alice_signed = alice_manager.generate_signed_prekey(1)
       bob_one_time = bob_manager.generate_one_time_prekeys(1)[1]

       print("✓ Key generation successful")

   except Exception as e:
       print(f"✗ Shared secret generation failed: {e}")
   ```

2. **Test Ratchet Initialization**:
   ```python
   # Test Double Ratchet initialization
   from src.crypto.double_ratchet import DoubleRatchet

   try:
       ratchet = DoubleRatchet("test_session")

       # Test Alice initialization
       shared_secret = SecureRandom.generate_bytes(32)
       bob_public_key = SecureRandom.generate_bytes(32)

       ratchet.initialize_alice(shared_secret, bob_public_key)
       print("✓ Alice initialization successful")

   except Exception as e:
       print(f"✗ Ratchet initialization failed: {e}")
   ```

### Message Encryption/Decryption Failures

**Problem**: Messages fail to encrypt or decrypt properly.

**Solutions**:

1. **Test Message Key Derivation**:
   ```python
   # Test chain key advancement
   from src.crypto.double_ratchet import ChainKey

   try:
       initial_key = SecureRandom.generate_bytes(32)
       chain_key = ChainKey(initial_key, 0)

       # Advance chain
       for i in range(5):
           message_key = chain_key.derive_message_key()
           print(f"Message key {i}: {len(message_key)} bytes")
           chain_key = chain_key.advance()

       print("✓ Chain key advancement works")

   except Exception as e:
       print(f"✗ Chain key derivation failed: {e}")
   ```

2. **Test Message Encryption**:
   ```python
   # Test full encryption/decryption cycle
   from src.crypto.double_ratchet import DoubleRatchet
   from src.crypto.encryption import MessageEncryption

   try:
       ratchet = DoubleRatchet("test_session")
       shared_secret = SecureRandom.generate_bytes(32)
       bob_dh_key = SecureRandom.generate_bytes(32)

       ratchet.initialize_alice(shared_secret, bob_dh_key)

       # Test message encryption
       plaintext = b"Hello, World!"
       encrypted = ratchet.encrypt_message(plaintext)

       print("✓ Message encryption successful")
       print(f"  Ciphertext length: {len(encrypted['ciphertext'])}")

   except Exception as e:
       print(f"✗ Message encryption failed: {e}")
   ```

## Key Recovery and Backup Issues

### Backup Creation Problems

**Problem**: Cannot create secure backups of keys.

**Solutions**:

1. **Test Backup Export**:
   ```python
   # Test key export functionality
   try:
       # Export identity key
       if manager.identity_key:
           public_key = manager.identity_key.get_public_key_bytes()
           print(f"✓ Identity key export: {len(public_key)} bytes")

       # Export prekey bundle
       bundle = manager.get_prekey_bundle()
       print("✓ Prekey bundle export successful")

   except Exception as e:
       print(f"✗ Backup export failed: {e}")
   ```

2. **Verify Backup Storage**:
   ```bash
   # Check backup directory
   ls -la ~/Privatus-chat-backups/

   # Verify backup integrity
   file ~/Privatus-chat-backups/*.backup
   ```

### Recovery from Backup Failures

**Problem**: Cannot restore keys from backup.

**Solutions**:

1. **Test Recovery Process**:
   ```python
   # Test key recovery
   try:
       # Create backup data
       backup_data = {
           'identity_key': manager.identity_key.get_public_key_bytes().hex(),
           'signed_prekey': manager.signed_prekey.get_public_key_bytes().hex(),
           'one_time_prekeys': {
               str(kid): pk.get_public_key_bytes().hex()
               for kid, pk in manager.one_time_prekeys.items()
           }
       }

       # Test recovery
       print("✓ Backup data created successfully")
       print(f"  Identity key: {len(backup_data['identity_key'])} chars")
       print(f"  One-time prekeys: {len(backup_data['one_time_prekeys'])}")

   except Exception as e:
       print(f"✗ Recovery test failed: {e}")
   ```

2. **Verify Backup File Format**:
   ```bash
   # Check backup file format
   head -c 100 ~/Privatus-chat-backups/latest.backup | hexdump -C

   # Verify JSON structure
   python -c "
   import json
   with open('latest.backup', 'r') as f:
       data = json.load(f)
       print('Valid JSON structure')
       print(f'Keys: {list(data.keys())}')
   "
   ```

## Performance and Security Issues

### Slow Key Operations

**Problem**: Key operations are too slow.

**Solutions**:

1. **Check System Performance**:
   ```bash
   # Monitor CPU usage during key operations
   top -p $(pgrep -f privatus-chat)

   # Check memory usage
   free -h

   # Monitor disk I/O
   iostat -x 1
   ```

2. **Optimize Key Derivation**:
   ```python
   # Test different iteration counts
   from src.crypto.key_management import adaptive_pbkdf2_iterations

   password = "test_password"
   salt = SecureRandom.generate_bytes(32)

   # Test different target times
   for target_ms in [50, 100, 200]:
       # Temporarily modify target time
       original_target = SecurityConfig.PBKDF2_TARGET_TIME_MS
       SecurityConfig.PBKDF2_TARGET_TIME_MS = target_ms

       iterations = adaptive_pbkdf2_iterations(password, salt)
       print(f"Target {target_ms}ms: {iterations:,}","iterations")

       SecurityConfig.PBKDF2_TARGET_TIME_MS = original_target
   ```

3. **Enable Key Caching**:
   ```python
   # Implement key caching for frequently used keys
   key_cache = {}
   cache_ttl = 300  # 5 minutes

   def get_cached_key(key_id):
       if key_id in key_cache:
           key_data, timestamp = key_cache[key_id]
           if time.time() - timestamp < cache_ttl:
               return key_data

       # Load key and cache it
       key_data = load_key_from_storage(key_id)
       key_cache[key_id] = (key_data, time.time())
       return key_data
   ```

### Memory Usage Issues

**Problem**: Key management consumes too much memory.

**Solutions**:

1. **Monitor Memory Usage**:
   ```python
   # Check memory usage of key objects
   import sys
   import gc

   def get_object_size(obj):
       return sys.getsizeof(obj)

   print(f"KeyManager size: {get_object_size(manager)} bytes")
   print(f"Identity key size: {get_object_size(manager.identity_key)} bytes")
   print(f"One-time prekeys count: {len(manager.one_time_prekeys)}")

   # Force garbage collection
   gc.collect()
   ```

2. **Implement Key Cleanup**:
   ```python
   # Clean up unused keys
   def cleanup_unused_keys():
       # Remove used one-time prekeys
       used_keys = [kid for kid, pk in manager.one_time_prekeys.items() if pk.used]
       for key_id in used_keys:
           del manager.one_time_prekeys[key_id]

       # Clear ephemeral keys after use
       manager.ephemeral_keys.clear()

       print(f"Cleaned up {len(used_keys)} used keys")
   ```

## Diagnostic Tools and Commands

### Key Management Diagnostics Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Key Management Diagnostics Tool
"""

import asyncio
import sys
from pathlib import Path
from src.crypto.key_management import KeyManager, SecurityConfig
from src.crypto.secure_random import SecureRandom

def run_key_diagnostics():
    print("=== Privatus-chat Key Management Diagnostics ===\n")

    # 1. Check storage path
    print("1. Checking storage configuration...")
    storage_path = Path.home() / '.config' / 'privatus-chat' / 'keys'

    try:
        storage_path.mkdir(parents=True, exist_ok=True)
        print(f"✓ Storage path: {storage_path}")

        # Test write permissions
        test_file = storage_path / 'diag_test.tmp'
        test_file.write_text('test')
        test_file.unlink()
        print("✓ Storage path writable")

    except Exception as e:
        print(f"✗ Storage path issue: {e}")
        return

    # 2. Test secure random
    print("\n2. Testing secure random generation...")
    try:
        random_bytes = SecureRandom.generate_bytes(32)
        random_int = SecureRandom.generate_int(32)
        print(f"✓ Secure random: {len(random_bytes)} bytes, int: {random_int}")
    except Exception as e:
        print(f"✗ Secure random failed: {e}")

    # 3. Test key generation
    print("\n3. Testing key generation...")
    try:
        # Test Ed25519 key generation
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print(f"✓ Ed25519 key generation: {len(public_bytes)} bytes")

        # Test X25519 key generation
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        dh_private = X25519PrivateKey.generate()
        dh_public = dh_private.public_key()

        dh_public_bytes = dh_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print(f"✓ X25519 key generation: {len(dh_public_bytes)} bytes")

    except Exception as e:
        print(f"✗ Key generation failed: {e}")

    # 4. Test KeyManager
    print("\n4. Testing KeyManager...")
    try:
        manager = KeyManager(storage_path, password="diag_test_password")

        # Test identity key generation
        identity_key = manager.generate_identity_key()
        print(f"✓ Identity key generated: {identity_key.key_id}")

        # Test prekey generation
        signed_prekey = manager.generate_signed_prekey(1)
        one_time_keys = manager.generate_one_time_prekeys(5)
        print(f"✓ Prekeys generated: 1 signed + {len(one_time_keys)} one-time")

        # Test prekey bundle
        bundle = manager.get_prekey_bundle()
        print("✓ Prekey bundle created successfully")

    except Exception as e:
        print(f"✗ KeyManager test failed: {e}")

    # 5. Test encryption/decryption
    print("\n5. Testing encryption/decryption...")
    try:
        test_data = b"This is a test message for encryption"

        encrypted = manager._encrypt_data(test_data)
        decrypted = manager._decrypt_data(encrypted)

        if decrypted == test_data:
            print(f"✓ Encryption/decryption: {len(encrypted)} bytes")
        else:
            print("✗ Encryption/decryption mismatch")

    except Exception as e:
        print(f"✗ Encryption test failed: {e}")

    # 6. Performance test
    print("\n6. Testing performance...")
    try:
        import time

        # Test key derivation performance
        start_time = time.time()
        for _ in range(10):
            test_key, _ = manager._derive_encryption_key("test_password")
        derivation_time = time.time() - start_time

        print(f"✓ Key derivation: {derivation_time:.3f".3f"or 10 operations")

        # Test key generation performance
        start_time = time.time()
        for _ in range(10):
            ed25519.Ed25519PrivateKey.generate()
        generation_time = time.time() - start_time

        print(f"✓ Key generation: {generation_time:.3f".3f"or 10 keys")

    except Exception as e:
        print(f"✗ Performance test failed: {e}")

    print("\n=== Key Management Diagnostics Complete ===")

if __name__ == "__main__":
    run_key_diagnostics()
```

### Key Security Audit Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Key Security Audit Tool
"""

import os
import stat
from pathlib import Path

def audit_key_security():
    print("=== Privatus-chat Key Security Audit ===\n")

    storage_path = Path.home() / '.config' / 'privatus-chat' / 'keys'

    # 1. Check directory permissions
    print("1. Checking directory permissions...")
    try:
        if storage_path.exists():
            stat_info = storage_path.stat()
            mode = stat.filemode(stat_info.st_mode)
            print(f"✓ Directory permissions: {mode}")

            # Check if only owner can access
            if stat_info.st_mode & stat.S_IRWXO:
                print("⚠ Warning: Group/others have access to key directory")
            else:
                print("✓ Key directory properly restricted")
        else:
            print("○ Key directory does not exist yet")

    except Exception as e:
        print(f"✗ Directory permission check failed: {e}")

    # 2. Check file permissions
    print("\n2. Checking file permissions...")
    try:
        for key_file in storage_path.glob("*.enc"):
            stat_info = key_file.stat()
            mode = stat.filemode(stat_info.st_mode)
            print(f"✓ {key_file.name}: {mode}")

            # Check if only owner can read/write
            if stat_info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                print(f"⚠ Warning: {key_file.name} accessible by group/others")
            else:
                print(f"✓ {key_file.name} properly restricted")

    except Exception as e:
        print(f"✗ File permission check failed: {e}")

    # 3. Check for backup files
    print("\n3. Checking for backup files...")
    try:
        backup_files = list(storage_path.glob("*backup*"))
        if backup_files:
            print(f"⚠ Found {len(backup_files)} backup files:")
            for backup in backup_files:
                print(f"  - {backup}")
        else:
            print("✓ No backup files found")

    except Exception as e:
        print(f"✗ Backup check failed: {e}")

    # 4. Check file timestamps
    print("\n4. Checking file timestamps...")
    try:
        for key_file in storage_path.glob("*.enc"):
            mtime = key_file.stat().st_mtime
            age_hours = (time.time() - mtime) / 3600

            print(f"✓ {key_file.name}: {age_hours:.1f}".1f"old")

            if age_hours > 24:
                print(f"  ⚠ {key_file.name} is older than 24 hours")

    except Exception as e:
        print(f"✗ Timestamp check failed: {e}")

    print("\n=== Security Audit Complete ===")

if __name__ == "__main__":
    audit_key_security()
```

### Emergency Key Recovery Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Emergency Key Recovery Tool
"""

import json
import sys
from pathlib import Path
from src.crypto.key_management import KeyManager

def recover_keys():
    print("=== Privatus-chat Emergency Key Recovery ===\n")

    if len(sys.argv) != 3:
        print("Usage: python recover_keys.py <storage_path> <password>")
        sys.exit(1)

    storage_path = Path(sys.argv[1])
    password = sys.argv[2]

    try:
        print(f"Attempting to recover keys from: {storage_path}")

        # Try to create KeyManager with provided password
        manager = KeyManager(storage_path, password)

        # Check what keys are available
        if manager.identity_key:
            print(f"✓ Identity key recovered: {manager.identity_key.key_id}")
        else:
            print("✗ No identity key found")

        if manager.signed_prekey:
            print(f"✓ Signed prekey recovered: ID {manager.signed_prekey.key_id}")
        else:
            print("○ No signed prekey found")

        print(f"✓ One-time prekeys: {len(manager.one_time_prekeys)}")

        # Export recovery data
        recovery_data = {
            'identity_key': manager.identity_key.get_public_key_bytes().hex() if manager.identity_key else None,
            'signed_prekey': {
                'key_id': manager.signed_prekey.key_id,
                'public_key': manager.signed_prekey.get_public_key_bytes().hex()
            } if manager.signed_prekey else None,
            'one_time_prekeys': {
                str(kid): {
                    'key_id': pk.key_id,
                    'public_key': pk.get_public_key_bytes().hex(),
                    'used': pk.used
                }
                for kid, pk in manager.one_time_prekeys.items()
            }
        }

        # Save recovery data
        recovery_file = storage_path / 'key_recovery.json'
        with open(recovery_file, 'w') as f:
            json.dump(recovery_data, f, indent=2)

        print(f"✓ Recovery data saved to: {recovery_file}")

    except Exception as e:
        print(f"✗ Key recovery failed: {e}")
        print("\nPossible causes:")
        print("- Incorrect password")
        print("- Corrupted key files")
        print("- Insufficient permissions")
        print("- Missing dependencies")

        sys.exit(1)

if __name__ == "__main__":
    recover_keys()
```

## Platform-Specific Issues

### Windows Key Storage Issues

**Problem**: Key storage problems on Windows.

**Solutions**:

1. **Check Windows Permissions**:
   ```powershell
   # Check if running as administrator
   $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
   $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
   $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   Write-Host "Running as admin: $isAdmin"

   # Fix permissions if needed
   $acl = Get-Acl "$env:APPDATA\Privatus-chat\keys"
   $acl.SetAccessRuleProtection($true, $false)
   Set-Acl "$env:APPDATA\Privatus-chat\keys" $acl
   ```

2. **Check Windows Defender**:
   ```powershell
   # Add exclusions for key directory
   Add-MpPreference -ExclusionPath "$env:APPDATA\Privatus-chat\keys"
   Add-MpPreference -ExclusionProcess "privatus-chat.exe"
   ```

### macOS Keychain Issues

**Problem**: Keychain access problems on macOS.

**Solutions**:

1. **Check Keychain Access**:
   ```bash
   # Check keychain permissions
   security dump-keychain | grep -i privatus

   # Reset keychain if needed
   security delete-keychain login.keychain
   ```

2. **Fix Keychain Permissions**:
   ```bash
   # Unlock keychain
   security unlock-keychain -p "your_password"

   # Set partition list
   security set-generic-password-partition-list -S apple-tool:,apple:,codesign: -s "privatus-chat" login.keychain
   ```

### Linux GPG/SSH Agent Issues

**Problem**: GPG agent or SSH agent interfering with key operations.

**Solutions**:

1. **Check GPG Agent**:
   ```bash
   # Check if GPG agent is running
   ps aux | grep gpg-agent

   # Kill GPG agent if interfering
   gpg-connect-agent killagent /bye
   ```

2. **Check SSH Agent**:
   ```bash
   # Check SSH agent
   ssh-add -l

   # Clear SSH agent if needed
   ssh-add -D
   ```

## Emergency Procedures

### Complete Key Reset

```python
# Emergency key reset procedure
async def emergency_key_reset():
    print("WARNING: This will delete all existing keys!")
    print("Ensure you have backups before proceeding.")

    confirmation = input("Type 'RESET' to confirm: ")
    if confirmation != 'RESET':
        print("Reset cancelled")
        return

    try:
        # 1. Backup existing keys if possible
        backup_path = storage_path / 'emergency_backup'
        backup_path.mkdir(exist_ok=True)

        for file in storage_path.glob("*.enc"):
            import shutil
            shutil.copy2(file, backup_path / file.name)

        print("✓ Emergency backup created")

        # 2. Delete all key files
        for file in storage_path.glob("*.enc"):
            file.unlink()

        print("✓ Key files deleted")

        # 3. Clear KeyManager state
        manager.identity_key = None
        manager.signed_prekey = None
        manager.one_time_prekeys.clear()

        print("✓ KeyManager state cleared")

        # 4. Generate new keys
        new_identity = manager.generate_identity_key()
        new_signed = manager.generate_signed_prekey(1)
        new_one_time = manager.generate_one_time_prekeys(10)

        print("✓ New keys generated")
        print(f"  Identity key: {new_identity.key_id}")
        print(f"  Signed prekey: {new_signed.key_id}")
        print(f"  One-time prekeys: {len(new_one_time)}")

    except Exception as e:
        print(f"✗ Emergency reset failed: {e}")
```

### Secure Key Deletion

```python
# Secure key deletion procedure
def secure_delete_all_keys():
    """Delete all keys with DoD 5220.22-M secure deletion."""

    try:
        # 1. Identify all key files
        key_files = list(storage_path.glob("*.enc"))
        print(f"Found {len(key_files)} key files to delete")

        # 2. Overwrite each file multiple times
        for file_path in key_files:
            print(f"Securely deleting: {file_path.name}")

            # DoD 5220.22-M 35-pass deletion
            with open(file_path, 'r+b') as f:
                file_size = f.seek(0, 2)  # Seek to end

                # Pass 1: Zeros
                f.seek(0)
                f.write(b'\x00' * file_size)

                # Pass 2: Ones
                f.seek(0)
                f.write(b'\xFF' * file_size)

                # Pass 3: Random
                f.seek(0)
                random_data = SecureRandom.generate_bytes(file_size)
                f.write(random_data)

                # Passes 4-35: Pattern + random
                patterns = [0x55, 0xAA, 0xCC, 0x33]
                for pass_num in range(4, 36):
                    f.seek(0)
                    if (pass_num - 4) % 4 == 3:
                        # Random pass
                        random_data = SecureRandom.generate_bytes(file_size)
                        f.write(random_data)
                    else:
                        # Pattern pass
                        pattern = patterns[(pass_num - 4) % len(patterns)]
                        pattern_data = bytes([pattern]) * file_size
                        f.write(pattern_data)

            # Delete the file
            file_path.unlink()

        print("✓ Secure deletion complete")

    except Exception as e:
        print(f"✗ Secure deletion failed: {e}")
```

## Prevention and Best Practices

### Key Management Best Practices

1. **Regular Key Rotation**:
   ```python
   # Rotate keys periodically
   def rotate_keys():
       # Generate new signed prekey
       old_signed_id = manager.signed_prekey.key_id if manager.signed_prekey else 0
       new_signed = manager.generate_signed_prekey(old_signed_id + 1)

       # Generate fresh one-time prekeys
       new_one_time = manager.generate_one_time_prekeys(50)

       print(f"Rotated keys: signed {old_signed_id} -> {new_signed.key_id}")
       print(f"Generated {len(new_one_time)} new one-time prekeys")
   ```

2. **Secure Backup Strategy**:
   ```python
   # Create encrypted backups
   def create_secure_backup(password):
       backup_data = {
           'identity_key': manager.identity_key.get_public_key_bytes().hex(),
           'signed_prekey': manager.signed_prekey.get_public_key_bytes().hex(),
           'one_time_prekeys': {
               str(kid): pk.get_public_key_bytes().hex()
               for kid, pk in manager.one_time_prekeys.items()
           },
           'timestamp': time.time()
       }

       # Encrypt backup data
       backup_json = json.dumps(backup_data)
       encrypted_backup = encrypt_with_password(backup_json, password)

       # Save to multiple locations
       backup_locations = [
           storage_path / 'backup.enc',
           Path.home() / 'Privatus-chat-backup.enc',
           '/media/external/Privatus-chat-backup.enc'
       ]

       for location in backup_locations:
           try:
               with open(location, 'wb') as f:
                   f.write(encrypted_backup)
               print(f"✓ Backup saved to: {location}")
           except Exception as e:
               print(f"✗ Failed to save backup to {location}: {e}")
   ```

3. **Key Health Monitoring**:
   ```python
   # Monitor key health
   def monitor_key_health():
       issues = []

       # Check identity key
       if not manager.identity_key:
           issues.append("No identity key")

       # Check signed prekey
       if not manager.signed_prekey:
           issues.append("No signed prekey")

       # Check one-time prekeys
       available_prekeys = sum(1 for pk in manager.one_time_prekeys.values() if not pk.used)
       if available_prekeys < 10:
           issues.append(f"Low one-time prekeys: {available_prekeys}")

       # Check key file timestamps
       for file_path in storage_path.glob("*.enc"):
           age_hours = (time.time() - file_path.stat().st_mtime) / 3600
           if age_hours > 24 * 30:  # 30 days
               issues.append(f"Old key file: {file_path.name} ({age_hours:.1f}h)")

       if issues:
           print(f"⚠ Key health issues: {issues}")
       else:
           print("✓ All keys healthy")

       return len(issues) == 0
   ```

### Security Hardening

1. **Enable Additional Security Features**:
   ```python
   # Enable signature requirements
   manager = KeyManager(storage_path, password)
   manager.signature_required = True

   # Use maximum security level
   from src.network.connection_manager import SecurityLevel
   security_level = SecurityLevel.PARANOID
   ```

2. **Implement Key Usage Auditing**:
   ```python
   # Track key usage
   key_usage_log = []

   def log_key_usage(operation, key_type, key_id=None):
       entry = {
           'timestamp': time.time(),
           'operation': operation,
           'key_type': key_type,
           'key_id': key_id
       }
       key_usage_log.append(entry)

       # Keep only last 1000 entries
       if len(key_usage_log) > 1000:
           key_usage_log.pop(0)

   # Use in key operations
   identity_key = manager.generate_identity_key()
   log_key_usage('generate', 'identity', identity_key.key_id)
   ```

## Getting Help

### Self-Service Resources

1. **Documentation**:
   - [Security Best Practices](security-best-practices.md)
   - [Installation Guide](installation-guide.md)
   - [FAQ](faq.md)

2. **Community Support**:
   - [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
   - [Security Discussions](https://github.com/privatus-chat/privatus-chat/discussions/categories/security)

### Reporting Key Management Issues

When reporting key management issues, please include:

1. **System Information**:
   - Operating system and version
   - Python version and cryptography library version
   - Privatus-chat version

2. **Error Details**:
   - Exact error messages
   - Steps to reproduce
   - Diagnostic tool output

3. **Key State Information**:
   - Which keys are affected (identity, signed prekey, one-time)
   - Key file timestamps and sizes
   - Storage path permissions

4. **Security Context**:
   - When the issue started
   - Any recent changes or updates
   - Security software that might interfere

---

*Remember: Cryptographic key management is critical for security. Always maintain secure backups and never share private keys. If you suspect key compromise, perform emergency key rotation immediately.*

*Last updated: January 2025*
*Version: 1.0.0*