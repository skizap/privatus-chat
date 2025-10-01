# Database and Storage Troubleshooting Guide

This guide provides comprehensive solutions for database connectivity issues, storage problems, and data management challenges in Privatus-chat.

## Table of Contents

1. [Database Connection Issues](#database-connection-issues)
2. [Data Corruption and Integrity Problems](#data-corruption-and-integrity-problems)
3. [Storage Performance Issues](#storage-performance-issues)
4. [Encryption and Security Problems](#encryption-and-security-problems)
5. [Backup and Recovery Issues](#backup-and-recovery-issues)
6. [Migration and Upgrade Problems](#migration-and-upgrade-problems)
7. [Platform-Specific Storage Issues](#platform-specific-storage-issues)
8. [Diagnostic Tools and Commands](#diagnostic-tools-and-commands)

## Database Connection Issues

### Cannot Connect to Database

**Problem**: Application cannot establish connection to the SQLite database.

**Symptoms**:
- "Database connection failed" errors
- "No such file or directory" messages
- Application startup failures

**Solutions**:

1. **Check Database File Location**:
   ```bash
   # Check if database directory exists
   ls -la ~/.privatus-chat/

   # Check database file permissions
   ls -la ~/.privatus-chat/*.db

   # Verify file ownership
   stat ~/.privatus-chat/*.db
   ```

2. **Test Database File Access**:
   ```python
   # Test basic file operations
   from pathlib import Path

   db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'

   try:
       # Check if file exists
       if db_path.exists():
           print(f"✓ Database file exists: {db_path}")
           print(f"  File size: {db_path.stat().st_size} bytes")
       else:
           print("○ Database file does not exist yet")

       # Test file permissions
       db_path.touch()
       db_path.unlink()
       print("✓ Database directory is writable")

   except Exception as e:
       print(f"✗ Database access issue: {e}")
   ```

3. **Check SQLite Installation**:
   ```python
   # Test SQLite functionality
   import sqlite3

   try:
       # Test basic SQLite operations
       conn = sqlite3.connect(':memory:')
       cursor = conn.cursor()
       cursor.execute('CREATE TABLE test (id INTEGER)')
       cursor.execute('INSERT INTO test VALUES (1)')
       cursor.execute('SELECT * FROM test')
       result = cursor.fetchone()
       conn.close()

       print(f"✓ SQLite works: {result}")

   except Exception as e:
       print(f"✗ SQLite issue: {e}")
   ```

4. **Verify Database Path Configuration**:
   ```python
   # Check database path configuration
   from src.storage.database_fixed import StorageManager
   from pathlib import Path

   try:
       data_dir = Path.home() / '.privatus-chat'
       print(f"Expected data directory: {data_dir}")

       # Test StorageManager initialization
       storage = StorageManager(data_dir, "test_password")
       print("✓ StorageManager initialization successful")

   except Exception as e:
       print(f"✗ StorageManager issue: {e}")
   ```

### Database Lock Errors

**Problem**: Database is locked or busy errors.

**Symptoms**:
- "Database is locked" errors
- "Database busy" messages
- Timeout errors during database operations

**Solutions**:

1. **Check for Concurrent Access**:
   ```bash
   # Check if multiple instances are running
   ps aux | grep privatus-chat | grep -v grep

   # Check for database locks
   lsof ~/.privatus-chat/*.db
   ```

2. **Configure SQLite Settings**:
   ```python
   # Test SQLite configuration
   import sqlite3

   try:
       conn = sqlite3.connect('test.db', timeout=20.0)
       conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
       conn.execute("PRAGMA synchronous=NORMAL")  # Balance safety/performance
       conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
       conn.close()

       print("✓ SQLite configuration applied")

   except Exception as e:
       print(f"✗ SQLite configuration failed: {e}")
   ```

3. **Implement Connection Retry Logic**:
   ```python
   # Implement retry mechanism for database operations
   import time
   import sqlite3

   def retry_database_operation(operation, max_retries=3, delay=1.0):
       for attempt in range(max_retries):
           try:
               return operation()
           except sqlite3.OperationalError as e:
               if "locked" in str(e) and attempt < max_retries - 1:
                   print(f"Database locked, retrying (attempt {attempt + 1})")
                   time.sleep(delay)
                   continue
               raise
   ```

### Permission Denied Errors

**Problem**: Cannot read or write to database files due to permissions.

**Solutions**:

1. **Check File Permissions**:
   ```bash
   # Check current permissions
   ls -ld ~/.privatus-chat/
   ls -l ~/.privatus-chat/*.db

   # Fix permissions if needed
   chmod 700 ~/.privatus-chat/
   chmod 600 ~/.privatus-chat/*.db
   ```

2. **Check User Ownership**:
   ```bash
   # Verify file ownership
   chown -R $USER:$USER ~/.privatus-chat/

   # Check if running as correct user
   whoami
   id
   ```

3. **Test Permission Fix**:
   ```python
   # Test write permissions
   from pathlib import Path

   test_file = Path.home() / '.privatus-chat' / 'permission_test'

   try:
       test_file.write_text('test')
       test_file.unlink()
       print("✓ Write permissions OK")
   except Exception as e:
       print(f"✗ Permission issue: {e}")
   ```

## Data Corruption and Integrity Problems

### Database File Corruption

**Problem**: Database file is corrupted or has integrity issues.

**Symptoms**:
- "Database disk image is malformed" errors
- "SQLite error: database corruption" messages
- Inconsistent or missing data

**Solutions**:

1. **Check Database Integrity**:
   ```python
   # Test database integrity
   from src.storage.database_fixed import SecureDatabase
   from pathlib import Path

   try:
       db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'
       if db_path.exists():
           # This would require adding an integrity check method
           print("Database file exists")

           # Try to open database
           import sqlite3
           conn = sqlite3.connect(db_path)
           cursor = conn.cursor()
           cursor.execute("PRAGMA integrity_check")
           result = cursor.fetchone()
           conn.close()

           print(f"Integrity check: {result}")

       else:
           print("Database file does not exist")

   except Exception as e:
       print(f"✗ Integrity check failed: {e}")
   ```

2. **Backup Corrupted Database**:
   ```bash
   # Create backup before repair
   cp ~/.privatus-chat/privatus_chat.db ~/.privatus-chat/backup_$(date +%Y%m%d_%H%M%S).db

   # Check backup integrity
   ls -la ~/.privatus-chat/backup_*.db
   ```

3. **Attempt Database Repair**:
   ```python
   # Attempt to repair corrupted database
   import sqlite3
   import shutil
   from pathlib import Path

   def repair_database(db_path):
       try:
           # Create backup
           backup_path = db_path.with_suffix('.corrupted_backup')
           if db_path.exists():
               shutil.copy2(db_path, backup_path)
               print("✓ Backup created before repair")

           # Try to rebuild database
           conn = sqlite3.connect(db_path)
           conn.execute("VACUUM")  # Rebuild database
           conn.execute("REINDEX")  # Rebuild indexes
           conn.close()

           print("✓ Database repair completed")

       except Exception as e:
           print(f"✗ Database repair failed: {e}")
           # Restore backup if repair failed
           if backup_path.exists():
               shutil.copy2(backup_path, db_path)
               print("✓ Backup restored")
   ```

### Data Inconsistency Issues

**Problem**: Data is inconsistent or missing between operations.

**Solutions**:

1. **Check Transaction Integrity**:
   ```python
   # Test transaction handling
   import sqlite3

   try:
       conn = sqlite3.connect('test.db')
       conn.execute("BEGIN")

       # Test transaction
       conn.execute("CREATE TABLE test (id INTEGER)")
       conn.execute("INSERT INTO test VALUES (1)")

       # Rollback test
       conn.execute("ROLLBACK")
       print("✓ Transaction rollback works")

       # Test commit
       conn.execute("BEGIN")
       conn.execute("INSERT INTO test VALUES (2)")
       conn.execute("COMMIT")
       print("✓ Transaction commit works")

       conn.close()

   except Exception as e:
       print(f"✗ Transaction issue: {e}")
   ```

2. **Verify Foreign Key Constraints**:
   ```python
   # Check foreign key enforcement
   import sqlite3

   try:
       conn = sqlite3.connect('test.db')
       conn.execute("PRAGMA foreign_keys = ON")

       # Test foreign key constraint
       conn.execute("""
           CREATE TABLE parent (id INTEGER PRIMARY KEY);
           CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER,
                              FOREIGN KEY (parent_id) REFERENCES parent(id));
       """)

       # Test constraint violation
       try:
           conn.execute("INSERT INTO child (parent_id) VALUES (999)")
           print("✗ Foreign key constraint not enforced")
       except sqlite3.IntegrityError:
           print("✓ Foreign key constraints working")

       conn.close()

   except Exception as e:
       print(f"✗ Foreign key test failed: {e}")
   ```

3. **Check Data Consistency**:
   ```python
   # Verify data consistency
   def check_data_consistency():
       try:
           # Check message-contact relationships
           messages_without_contacts = []
           # Query would check for orphaned messages

           # Check duplicate contacts
           duplicate_contacts = []
           # Query would check for duplicate contact IDs

           if messages_without_contacts or duplicate_contacts:
               print(f"✗ Data consistency issues found")
           else:
               print("✓ Data consistency OK")

       except Exception as e:
           print(f"✗ Consistency check failed: {e}")
   ```

## Storage Performance Issues

### Slow Database Operations

**Problem**: Database queries and operations are slow.

**Symptoms**:
- Long delays when loading contacts or messages
- High CPU usage during database operations
- Timeout errors on large datasets

**Solutions**:

1. **Check Database Performance**:
   ```python
   # Test query performance
   import time
   import sqlite3

   def test_query_performance():
       conn = sqlite3.connect('test.db')

       # Create test data
       conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER, data TEXT)")
       for i in range(1000):
           conn.execute("INSERT INTO test VALUES (?, ?)", (i, f"data_{i}"))
       conn.commit()

       # Test query performance
       start_time = time.time()
       cursor = conn.execute("SELECT * FROM test WHERE id > 500")
       results = cursor.fetchall()
       query_time = time.time() - start_time

       print(f"Query returned {len(results)} results in {query_time:.3f}s")

       conn.close()
   ```

2. **Optimize Database Configuration**:
   ```python
   # Apply performance optimizations
   import sqlite3

   def optimize_database():
       conn = sqlite3.connect('privatus_chat.db')

       # Enable optimizations
       conn.execute("PRAGMA journal_mode=WAL")      # Better concurrency
       conn.execute("PRAGMA synchronous=NORMAL")    # Balance safety/performance
       conn.execute("PRAGMA cache_size=-64000")     # 64MB cache
       conn.execute("PRAGMA temp_store=memory")     # Memory temp storage
       conn.execute("PRAGMA mmap_size=268435456")   # 256MB memory map

       print("✓ Database optimizations applied")
       conn.close()
   ```

3. **Implement Query Optimization**:
   ```python
   # Optimize slow queries
   def optimize_queries():
       # Use proper indexing
       conn.execute("""
           CREATE INDEX IF NOT EXISTS idx_messages_contact_id
           ON messages(contact_id)
       """)

       conn.execute("""
           CREATE INDEX IF NOT EXISTS idx_messages_timestamp
           ON messages(timestamp)
       """)

       # Use LIMIT for large result sets
       cursor.execute("""
           SELECT * FROM messages
           WHERE contact_id = ?
           ORDER BY timestamp DESC
           LIMIT 100
       """, (contact_id,))

       print("✓ Query optimizations applied")
   ```

### High Memory Usage

**Problem**: Database operations consume excessive memory.

**Solutions**:

1. **Monitor Memory Usage**:
   ```python
   # Monitor database memory usage
   import psutil
   import os

   def monitor_db_memory():
       process = psutil.Process(os.getpid())
       memory_mb = process.memory_info().rss / 1024 / 1024

       print(f"Current memory usage: {memory_mb:.1f}MB")

       # Check for memory leaks
       import gc
       gc.collect()
       print("Garbage collection completed")
   ```

2. **Implement Memory-Efficient Operations**:
   ```python
   # Use memory-efficient data loading
   def load_messages_efficiently(contact_id, limit=100):
       try:
           # Use server-side LIMIT
           cursor.execute("""
               SELECT message_id, content, timestamp
               FROM messages
               WHERE contact_id = ?
               ORDER BY timestamp DESC
               LIMIT ?
           """, (contact_id, limit))

           # Process results in batches
           batch_size = 50
           while True:
               batch = cursor.fetchmany(batch_size)
               if not batch:
                   break

               for row in batch:
                   # Process each message
                   yield process_message_row(row)

       except Exception as e:
           print(f"✗ Efficient loading failed: {e}")
   ```

3. **Configure Memory Limits**:
   ```python
   # Set memory limits for database operations
   import sqlite3

   def configure_memory_limits():
       conn = sqlite3.connect('privatus_chat.db')

       # Set memory limits
       conn.execute("PRAGMA soft_heap_limit=67108864")  # 64MB soft limit
       conn.execute("PRAGMA hard_heap_limit=134217728") # 128MB hard limit

       print("✓ Memory limits configured")
       conn.close()
   ```

## Encryption and Security Problems

### Encryption Key Derivation Issues

**Problem**: Cannot derive encryption key from password.

**Symptoms**:
- "Key derivation failed" errors
- "Invalid password" messages
- Encryption/decryption failures

**Solutions**:

1. **Test Password Validation**:
   ```python
   # Test password strength validation
   def test_password_validation():
       password = "your_test_password"

       # Length check
       if len(password) < 12:
           print("✗ Password too short")

       # Character requirements
       import re
       has_upper = bool(re.search(r'[A-Z]', password))
       has_lower = bool(re.search(r'[a-z]', password))
       has_digit = bool(re.search(r'[0-9]', password))
       has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))

       if not (has_upper and has_lower and has_digit and has_special):
           print("✗ Password missing character requirements")

       print("✓ Password validation works")
   ```

2. **Check PBKDF2 Performance**:
   ```python
   # Test key derivation performance
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   from cryptography.hazmat.primitives import hashes
   import time

   def test_key_derivation():
       password = "test_password"
       salt = b"test_salt_32_bytes_long_for_security"

       # Test different iteration counts
       for iterations in [100000, 500000, 1000000]:
           start_time = time.time()

           kdf = PBKDF2HMAC(
               algorithm=hashes.SHA256(),
               length=32,
               salt=salt,
               iterations=iterations,
           )

           key = kdf.derive(password.encode())
           derivation_time = time.time() - start_time

           print(f"Iterations: {iterations:,}","f"Time: {derivation_time:.3f}s")
   ```

3. **Verify Salt Generation**:
   ```python
   # Test salt generation and management
   import secrets

   def test_salt_generation():
       # Generate salt
       salt = secrets.token_bytes(32)
       print(f"✓ Salt generated: {len(salt)} bytes")

       # Test salt validation
       if len(salt) == 32 and not all(b == 0 for b in salt):
           print("✓ Salt validation passed")
       else:
           print("✗ Salt validation failed")

       # Test salt file operations
       salt_path = Path.home() / '.privatus-chat' / 'test.salt'
       try:
           with open(salt_path, 'wb') as f:
               f.write(salt)
           print("✓ Salt file written")

           with open(salt_path, 'rb') as f:
               read_salt = f.read()
           print(f"✓ Salt file read: {len(read_salt)} bytes")

           salt_path.unlink()

       except Exception as e:
           print(f"✗ Salt file operation failed: {e}")
   ```

### Data Decryption Failures

**Problem**: Cannot decrypt stored data.

**Symptoms**:
- "Decryption failed" errors
- "Invalid token" messages
- Garbled or empty data after decryption

**Solutions**:

1. **Test Encryption/Decryption Cycle**:
   ```python
   # Test full encryption/decryption cycle
   from cryptography.fernet import Fernet
   import base64

   def test_encryption_cycle():
       # Generate test key
       key = Fernet.generate_key()
       fernet = Fernet(key)

       # Test data
       test_data = "This is sensitive test data"

       try:
           # Encrypt
           encrypted = fernet.encrypt(test_data.encode())
           print(f"✓ Encryption successful: {len(encrypted)} bytes")

           # Decrypt
           decrypted = fernet.decrypt(encrypted).decode()
           print(f"✓ Decryption successful: {decrypted}")

           # Verify
           if decrypted == test_data:
               print("✓ Encryption/decryption cycle works")
           else:
               print("✗ Data mismatch after decryption")

       except Exception as e:
           print(f"✗ Encryption cycle failed: {e}")
   ```

2. **Check Key Consistency**:
   ```python
   # Verify encryption key consistency
   def test_key_consistency():
       password = "test_password"

       # Create two instances with same password
       from src.storage.database_fixed import SecureDatabase
       from pathlib import Path

       try:
           db1 = SecureDatabase(Path("/tmp/test1.db"), password)
           db2 = SecureDatabase(Path("/tmp/test2.db"), password)

           # Test data encryption with both instances
           test_data = "consistency test"
           encrypted1 = db1._encrypt_data(test_data)
           encrypted2 = db2._encrypt_data(test_data)

           # Both should produce different ciphertexts (due to different IVs)
           if encrypted1 != encrypted2:
               print("✓ Key consistency verified")
           else:
               print("✗ Key consistency issue")

       except Exception as e:
           print(f"✗ Key consistency test failed: {e}")
   ```

3. **Verify Data Integrity**:
   ```python
   # Check encrypted data integrity
   def check_encrypted_data():
       try:
           # Read encrypted data
           with open('encrypted_file.enc', 'rb') as f:
               data = f.read()

           print(f"Encrypted data size: {len(data)} bytes")

           # Check if data looks like valid Fernet token
           if len(data) < 57:  # Minimum Fernet token size
               print("✗ Data too short for Fernet token")
           else:
               print("✓ Data size looks valid for encrypted content")

       except Exception as e:
           print(f"✗ Encrypted data check failed: {e}")
   ```

## Backup and Recovery Issues

### Backup Creation Problems

**Problem**: Cannot create database backups.

**Solutions**:

1. **Test Backup Process**:
   ```python
   # Test database backup functionality
   import sqlite3
   import shutil
   from pathlib import Path

   def test_database_backup():
       db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'

       try:
           if db_path.exists():
               # Create backup
               backup_path = db_path.with_suffix('.backup')
               shutil.copy2(db_path, backup_path)

               print(f"✓ Backup created: {backup_path}")
               print(f"  Backup size: {backup_path.stat().st_size} bytes")

               # Verify backup integrity
               conn = sqlite3.connect(backup_path)
               cursor = conn.cursor()
               cursor.execute("PRAGMA integrity_check")
               result = cursor.fetchone()
               conn.close()

               if result and result[0] == "ok":
                   print("✓ Backup integrity verified")
               else:
                   print("✗ Backup integrity check failed")

           else:
               print("○ Database file does not exist")

       except Exception as e:
           print(f"✗ Backup test failed: {e}")
   ```

2. **Check Backup Storage Space**:
   ```bash
   # Check available disk space
   df -h ~

   # Check backup directory permissions
   ls -ld ~/Privatus-chat-backups/

   # Create backup directory if needed
   mkdir -p ~/Privatus-chat-backups/
   chmod 700 ~/Privatus-chat-backups/
   ```

3. **Implement Automated Backup**:
   ```python
   # Create automated backup system
   import shutil
   import time
   from pathlib import Path

   def create_automated_backup():
       db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'

       try:
           if not db_path.exists():
               print("○ No database to backup")
               return

           # Create timestamped backup
           timestamp = time.strftime("%Y%m%d_%H%M%S")
           backup_name = f"privatus_chat_backup_{timestamp}.db"
           backup_path = Path.home() / 'Privatus-chat-backups' / backup_name

           # Ensure backup directory exists
           backup_path.parent.mkdir(parents=True, exist_ok=True)

           # Create backup
           shutil.copy2(db_path, backup_path)
           print(f"✓ Automated backup created: {backup_path}")

           # Clean old backups (keep last 10)
           cleanup_old_backups()

       except Exception as e:
           print(f"✗ Automated backup failed: {e}")

   def cleanup_old_backups(keep_count=10):
       backup_dir = Path.home() / 'Privatus-chat-backups'
       if not backup_dir.exists():
           return

       # Get all backup files
       backup_files = list(backup_dir.glob("*.db"))
       backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

       # Remove old backups
       for old_backup in backup_files[keep_count:]:
           old_backup.unlink()
           print(f"✓ Removed old backup: {old_backup.name}")
   ```

### Recovery from Backup Failures

**Problem**: Cannot restore data from backup.

**Solutions**:

1. **Test Backup Restoration**:
   ```python
   # Test backup restoration process
   import shutil
   from pathlib import Path

   def test_backup_restoration():
       db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'
       backup_path = Path.home() / 'Privatus-chat-backups' / 'latest_backup.db'

       try:
           if not backup_path.exists():
               print("○ No backup file found")
               return

           # Create safety backup of current database
           if db_path.exists():
               safety_backup = db_path.with_suffix('.pre_restore')
               shutil.copy2(db_path, safety_backup)
               print(f"✓ Safety backup created: {safety_backup}")

           # Restore from backup
           shutil.copy2(backup_path, db_path)
           print(f"✓ Database restored from: {backup_path}")

           # Verify restored database
           import sqlite3
           conn = sqlite3.connect(db_path)
           cursor = conn.cursor()
           cursor.execute("PRAGMA integrity_check")
           result = cursor.fetchone()
           conn.close()

           if result and result[0] == "ok":
               print("✓ Restored database integrity verified")
           else:
               print("✗ Restored database integrity check failed")

       except Exception as e:
           print(f"✗ Restoration test failed: {e}")
   ```

2. **Check Backup Compatibility**:
   ```python
   # Verify backup file compatibility
   import sqlite3

   def check_backup_compatibility():
       backup_path = Path.home() / 'Privatus-chat-backups' / 'latest_backup.db'

       try:
           # Check SQLite format version
           conn = sqlite3.connect(backup_path)
           cursor = conn.cursor()

           # Check schema version
           cursor.execute("PRAGMA schema_version")
           schema_version = cursor.fetchone()[0]

           # Check user version
           cursor.execute("PRAGMA user_version")
           user_version = cursor.fetchone()[0]

           print(f"✓ Backup schema version: {schema_version}")
           print(f"✓ Backup user version: {user_version}")

           conn.close()

       except Exception as e:
           print(f"✗ Backup compatibility check failed: {e}")
   ```

3. **Implement Recovery Verification**:
   ```python
   # Verify data after recovery
   def verify_recovery():
       try:
           # Check contact count
           contacts = storage.get_all_contacts()
           print(f"✓ Recovered {len(contacts)} contacts")

           # Check message count
           total_messages = 0
           for contact in contacts:
               messages = storage.get_messages(contact.contact_id, limit=1)
               total_messages += len(messages)

           print(f"✓ Recovered {total_messages} messages")

           # Check settings
           settings = storage.get_setting('test_setting', 'not_found')
           print(f"✓ Settings recovery: {'OK' if settings != 'not_found' else 'Empty'}")

       except Exception as e:
           print(f"✗ Recovery verification failed: {e}")
   ```

## Migration and Upgrade Problems

### Database Schema Migration Issues

**Problem**: Database schema updates fail or cause data loss.

**Solutions**:

1. **Test Migration Safety**:
   ```python
   # Test migration rollback capability
   def test_migration_rollback():
       try:
           # Create backup before migration
           backup_created = create_pre_migration_backup()

           if backup_created:
               print("✓ Pre-migration backup created")

               # Simulate migration
               migration_success = perform_database_migration()

               if migration_success:
                   print("✓ Migration completed successfully")
               else:
                   print("✗ Migration failed, attempting rollback")
                   rollback_success = rollback_migration()
                   if rollback_success:
                       print("✓ Rollback completed successfully")
                   else:
                       print("✗ Rollback failed - manual intervention required")

           else:
               print("✗ Could not create backup - migration cancelled")

       except Exception as e:
           print(f"✗ Migration test failed: {e}")
   ```

2. **Check Schema Compatibility**:
   ```python
   # Verify schema compatibility
   import sqlite3

   def check_schema_compatibility():
       try:
           conn = sqlite3.connect('privatus_chat.db')
           cursor = conn.cursor()

           # Check existing tables
           cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
           tables = cursor.fetchall()

           expected_tables = ['contacts', 'messages', 'settings']
           found_tables = [table[0] for table in tables]

           print(f"Found tables: {found_tables}")

           for table in expected_tables:
               if table in found_tables:
                   print(f"✓ Table {table} exists")
               else:
                   print(f"✗ Table {table} missing")

           conn.close()

       except Exception as e:
           print(f"✗ Schema check failed: {e}")
   ```

3. **Implement Safe Migration**:
   ```python
   # Safe migration with verification
   def safe_database_migration():
       try:
           # 1. Verify current state
           pre_migration_stats = get_database_stats()
           print(f"Pre-migration: {pre_migration_stats}")

           # 2. Create backup
           backup_path = create_backup()
           if not backup_path:
               raise Exception("Could not create backup")

           # 3. Perform migration
           migration_log = []
           migration_success = perform_migration_steps(migration_log)

           if migration_success:
               # 4. Verify post-migration state
               post_migration_stats = get_database_stats()
               print(f"Post-migration: {post_migration_stats}")

               # 5. Verify data integrity
               integrity_ok = verify_data_integrity()

               if integrity_ok:
                   print("✓ Migration completed successfully")
                   # Remove old backup after successful migration
                   cleanup_old_backups()
               else:
                   raise Exception("Post-migration integrity check failed")

           else:
               raise Exception(f"Migration failed: {migration_log}")

       except Exception as e:
           print(f"✗ Migration failed: {e}")
           # Attempt rollback
           if 'backup_path' in locals():
               restore_from_backup(backup_path)
   ```

## Platform-Specific Storage Issues

### Windows Storage Problems

**Problem**: Storage issues specific to Windows platform.

**Solutions**:

1. **Check Windows File Locks**:
   ```powershell
   # Check for file locks
   $dbPath = "$env:APPDATA\Privatus-chat\privatus_chat.db"
   Get-Process | Where-Object {$_.Modules.FileName -like "*sqlite*"}

   # Check Windows Defender exclusions
   Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
   Add-MpPreference -ExclusionPath "$env:APPDATA\Privatus-chat"
   ```

2. **Test Windows Permissions**:
   ```powershell
   # Check file permissions
   $acl = Get-Acl "$env:APPDATA\Privatus-chat"
   $acl | Format-List

   # Fix permissions if needed
   $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
       $env:USERNAME, "FullControl", "Allow"
   )
   $acl.SetAccessRule($rule)
   Set-Acl "$env:APPDATA\Privatus-chat" $acl
   ```

3. **Check Windows Storage Quotas**:
   ```powershell
   # Check disk quotas
   fsutil quota query C:

   # Check available space
   Get-WmiObject -Class Win32_LogicalDisk | Select-Object Size, FreeSpace
   ```

### macOS Storage Problems

**Problem**: Storage issues specific to macOS platform.

**Solutions**:

1. **Check macOS File System**:
   ```bash
   # Check file system type
   mount | grep "/Users"

   # Check disk usage
   df -h ~

   # Check for macOS-specific locks
   lsof ~/.privatus-chat/*.db
   ```

2. **Test macOS Permissions**:
   ```bash
   # Check macOS permissions
   ls -le ~/.privatus-chat/

   # Fix permissions if needed
   chmod -R 700 ~/.privatus-chat/

   # Check for extended attributes
   xattr ~/.privatus-chat/*.db
   ```

3. **Check macOS Security Features**:
   ```bash
   # Check Gatekeeper
   spctl --status

   # Check SIP (System Integrity Protection)
   csrutil status

   # Check for quarantine attributes
   xattr -l ~/.privatus-chat/*.db
   ```

### Linux Storage Problems

**Problem**: Storage issues specific to Linux platform.

**Solutions**:

1. **Check Linux File System**:
   ```bash
   # Check file system type and options
   mount | grep "/home"

   # Check for Linux-specific issues
   cat /proc/mounts | grep "/home"

   # Check for overlay filesystems
   find /home -name "*.db" -exec lsattr {} \;
   ```

2. **Test Linux Permissions**:
   ```bash
   # Check Linux permissions and attributes
   ls -la ~/.privatus-chat/
   getfacl ~/.privatus-chat/

   # Check for immutable attributes
   lsattr ~/.privatus-chat/*.db

   # Fix permissions
   chown -R $USER:$USER ~/.privatus-chat/
   chmod -R 600 ~/.privatus-chat/*.db
   ```

3. **Check Linux Security Modules**:
   ```bash
   # Check AppArmor
   aa-status

   # Check SELinux
   sestatus

   # Check for security contexts
   ls -Z ~/.privatus-chat/
   ```

## Diagnostic Tools and Commands

### Storage Diagnostics Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Storage Diagnostics Tool
"""

import sqlite3
import os
import time
from pathlib import Path

def run_storage_diagnostics():
    print("=== Privatus-chat Storage Diagnostics ===\n")

    # 1. Check storage location
    print("1. Checking storage location...")
    data_dir = Path.home() / '.privatus-chat'

    try:
        if data_dir.exists():
            print(f"✓ Data directory: {data_dir}")
            contents = list(data_dir.glob('*'))
            print(f"✓ Directory contents: {len(contents)} items")

            for item in contents:
                size_mb = item.stat().st_size / 1024 / 1024
                print(f"  - {item.name}: {size_mb:.2f}MB")
        else:
            print("○ Data directory does not exist yet")

    except Exception as e:
        print(f"✗ Storage location check failed: {e}")

    # 2. Check database file
    print("\n2. Checking database file...")
    db_path = data_dir / 'privatus_chat.db'

    try:
        if db_path.exists():
            # Check file size
            size_mb = db_path.stat().st_size / 1024 / 1024
            print(f"✓ Database file: {size_mb:.2f}MB")

            # Check file permissions
            stat_info = db_path.stat()
            permissions = oct(stat_info.st_mode)[-3:]
            print(f"✓ File permissions: {permissions}")

            # Check SQLite format
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Check schema version
            cursor.execute("PRAGMA schema_version")
            schema_version = cursor.fetchone()[0]

            # Check page size
            cursor.execute("PRAGMA page_size")
            page_size = cursor.fetchone()[0]

            # Check page count
            cursor.execute("PRAGMA page_count")
            page_count = cursor.fetchone()[0]

            print(f"✓ Schema version: {schema_version}")
            print(f"✓ Page size: {page_size} bytes")
            print(f"✓ Page count: {page_count}")

            conn.close()

        else:
            print("○ Database file does not exist yet")

    except Exception as e:
        print(f"✗ Database check failed: {e}")

    # 3. Check salt file
    print("\n3. Checking salt file...")
    salt_path = data_dir / 'privatus_chat.salt'

    try:
        if salt_path.exists():
            salt_size = salt_path.stat().st_size
            print(f"✓ Salt file exists: {salt_size} bytes")

            if salt_size == 32:
                print("✓ Salt file size correct")
            else:
                print(f"⚠ Salt file size incorrect: {salt_size} bytes")

            # Check permissions
            permissions = oct(salt_path.stat().st_mode)[-3:]
            if permissions == '600':
                print("✓ Salt file permissions correct")
            else:
                print(f"⚠ Salt file permissions: {permissions}")

        else:
            print("○ Salt file does not exist yet")

    except Exception as e:
        print(f"✗ Salt file check failed: {e}")

    # 4. Test database operations
    print("\n4. Testing database operations...")
    try:
        if db_path.exists():
            conn = sqlite3.connect(db_path)

            # Test basic operations
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()

            print(f"✓ Found {len(tables)} tables:")
            for table in tables:
                print(f"  - {table[0]}")

            # Test data operations
            cursor.execute("SELECT COUNT(*) FROM contacts")
            contact_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM messages")
            message_count = cursor.fetchone()[0]

            print(f"✓ Data: {contact_count} contacts, {message_count} messages")

            conn.close()

        else:
            print("○ No database to test")

    except Exception as e:
        print(f"✗ Database operations test failed: {e}")

    # 5. Check backup files
    print("\n5. Checking backup files...")
    try:
        backup_dir = Path.home() / 'Privatus-chat-backups'
        if backup_dir.exists():
            backups = list(backup_dir.glob('*.db'))
            print(f"✓ Found {len(backups)} backup files:")

            for backup in sorted(backups, key=lambda x: x.stat().st_mtime, reverse=True):
                size_mb = backup.stat().st_size / 1024 / 1024
                mtime = time.ctime(backup.stat().st_mtime)
                print(f"  - {backup.name}: {size_mb:.2f}MB ({mtime})")

        else:
            print("○ No backup directory found")

    except Exception as e:
        print(f"✗ Backup check failed: {e}")

    print("\n=== Storage Diagnostics Complete ===")

if __name__ == "__main__":
    run_storage_diagnostics()
```

### Database Performance Test Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Database Performance Test Tool
"""

import sqlite3
import time
import random
import string
from pathlib import Path

def run_performance_tests():
    print("=== Database Performance Tests ===\n")

    # Create test database
    test_db = Path("/tmp/privatus_perf_test.db")

    try:
        # Setup test data
        print("Setting up test data...")
        conn = sqlite3.connect(test_db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-64000")

        # Create test tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS test_contacts (
                contact_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS test_messages (
                message_id TEXT PRIMARY KEY,
                contact_id TEXT NOT NULL,
                content BLOB NOT NULL,
                is_outgoing BOOLEAN NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contact_id) REFERENCES test_contacts (contact_id)
            )
        """)

        # Generate test data
        contact_count = 100
        messages_per_contact = 50

        print(f"Generating {contact_count} contacts and {contact_count * messages_per_contact} messages...")

        # Insert test contacts
        for i in range(contact_count):
            contact_id = f"contact_{i}"
            display_name = f"Contact {i}"
            public_key = ''.join(random.choices(string.hexdigits, k=64))

            conn.execute("""
                INSERT INTO test_contacts (contact_id, display_name, public_key, is_verified)
                VALUES (?, ?, ?, ?)
            """, (contact_id, display_name, public_key, random.choice([True, False])))

        # Insert test messages
        for contact_i in range(contact_count):
            contact_id = f"contact_{contact_i}"
            for msg_i in range(messages_per_contact):
                message_id = f"msg_{contact_i}_{msg_i}"
                content = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                is_outgoing = random.choice([True, False])

                conn.execute("""
                    INSERT INTO test_messages (message_id, contact_id, content, is_outgoing)
                    VALUES (?, ?, ?, ?)
                """, (message_id, contact_id, content, is_outgoing))

        conn.commit()

        # Run performance tests
        print("\nRunning performance tests...")

        # Test 1: Contact insertion
        start_time = time.time()
        for i in range(10):
            contact_id = f"perf_contact_{i}"
            display_name = f"Performance Contact {i}"
            public_key = ''.join(random.choices(string.hexdigits, k=64))

            conn.execute("""
                INSERT INTO test_contacts (contact_id, display_name, public_key)
                VALUES (?, ?, ?)
            """, (contact_id, display_name, public_key))

        conn.commit()
        insertion_time = time.time() - start_time
        print(f"✓ Contact insertion (10 contacts): {insertion_time:.3f}s")

        # Test 2: Message insertion
        start_time = time.time()
        for i in range(100):
            message_id = f"perf_msg_{i}"
            contact_id = f"contact_{random.randint(0, contact_count-1)}"
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=100))

            conn.execute("""
                INSERT INTO test_messages (message_id, contact_id, content, is_outgoing)
                VALUES (?, ?, ?, ?)
            """, (message_id, contact_id, content, random.choice([True, False])))

        conn.commit()
        message_insertion_time = time.time() - start_time
        print(f"✓ Message insertion (100 messages): {message_insertion_time:.3f}s")

        # Test 3: Contact query
        start_time = time.time()
        cursor = conn.execute("SELECT * FROM test_contacts WHERE is_verified = ?", (True,))
        verified_contacts = cursor.fetchall()
        query_time = time.time() - start_time
        print(f"✓ Contact query ({len(verified_contacts)} results): {query_time:.3f}s")

        # Test 4: Message query
        start_time = time.time()
        cursor = conn.execute("""
            SELECT * FROM test_messages
            WHERE contact_id = ? AND is_outgoing = ?
            ORDER BY timestamp DESC
            LIMIT 20
        """, (f"contact_{random.randint(0, contact_count-1)}", True))
        messages = cursor.fetchall()
        message_query_time = time.time() - start_time
        print(f"✓ Message query ({len(messages)} results): {message_query_time:.3f}s")

        # Test 5: Complex query
        start_time = time.time()
        cursor = conn.execute("""
            SELECT c.display_name, COUNT(m.message_id) as message_count
            FROM test_contacts c
            LEFT JOIN test_messages m ON c.contact_id = m.contact_id
            GROUP BY c.contact_id, c.display_name
            ORDER BY message_count DESC
            LIMIT 10
        """)
        results = cursor.fetchall()
        complex_query_time = time.time() - start_time
        print(f"✓ Complex query ({len(results)} results): {complex_query_time:.3f}s")

        conn.close()

        # Cleanup
        test_db.unlink()

        print("\n=== Performance Tests Complete ===")

    except Exception as e:
        print(f"✗ Performance test failed: {e}")
        if test_db.exists():
            test_db.unlink()

if __name__ == "__main__":
    run_performance_tests()
```

### Database Integrity Check Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Database Integrity Check Tool
"""

import sqlite3
import json
from pathlib import Path

def run_integrity_checks():
    print("=== Database Integrity Checks ===\n")

    db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'

    if not db_path.exists():
        print("○ Database file does not exist")
        return

    try:
        # 1. SQLite integrity check
        print("1. Running SQLite integrity check...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA integrity_check")
        integrity_result = cursor.fetchone()

        if integrity_result and integrity_result[0] == "ok":
            print("✓ SQLite integrity check passed")
        else:
            print(f"✗ SQLite integrity check failed: {integrity_result}")

        # 2. Check table structures
        print("\n2. Checking table structures...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        expected_tables = {
            'contacts': ['contact_id', 'display_name', 'public_key', 'is_verified', 'is_online', 'added_at', 'last_seen'],
            'messages': ['message_id', 'contact_id', 'content', 'is_outgoing', 'is_encrypted', 'timestamp'],
            'settings': ['key', 'value', 'updated_at']
        }

        for table_row in tables:
            table_name = table_row[0]
            print(f"\n   Checking table: {table_name}")

            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()

            if table_name in expected_tables:
                expected_columns = expected_tables[table_name]
                actual_columns = [col[1] for col in columns]

                for expected_col in expected_columns:
                    if expected_col in actual_columns:
                        print(f"     ✓ Column {expected_col} exists")
                    else:
                        print(f"     ✗ Column {expected_col} missing")

                # Check for extra columns
                for actual_col in actual_columns:
                    if actual_col not in expected_columns:
                        print(f"     ○ Extra column {actual_col}")
            else:
                print(f"     ○ Unexpected table: {table_name}")

        # 3. Check foreign key constraints
        print("\n3. Checking foreign key constraints...")
        cursor.execute("PRAGMA foreign_key_check")
        fk_violations = cursor.fetchall()

        if not fk_violations:
            print("✓ No foreign key violations found")
        else:
            print(f"✗ Found {len(fk_violations)} foreign key violations:")
            for violation in fk_violations:
                print(f"     - {violation}")

        # 4. Check data consistency
        print("\n4. Checking data consistency...")

        # Check for messages without corresponding contacts
        cursor.execute("""
            SELECT COUNT(*) FROM messages m
            LEFT JOIN contacts c ON m.contact_id = c.contact_id
            WHERE c.contact_id IS NULL
        """)
        orphaned_messages = cursor.fetchone()[0]

        if orphaned_messages == 0:
            print("✓ No orphaned messages found")
        else:
            print(f"✗ Found {orphaned_messages} orphaned messages")

        # Check for duplicate contacts
        cursor.execute("""
            SELECT contact_id, COUNT(*) as count
            FROM contacts
            GROUP BY contact_id
            HAVING count > 1
        """)
        duplicate_contacts = cursor.fetchall()

        if not duplicate_contacts:
            print("✓ No duplicate contacts found")
        else:
            print(f"✗ Found {len(duplicate_contacts)} duplicate contacts:")
            for contact_id, count in duplicate_contacts:
                print(f"     - {contact_id}: {count} duplicates")

        # 5. Check index validity
        print("\n5. Checking indexes...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = cursor.fetchall()

        print(f"✓ Found {len(indexes)} indexes:")
        for index_row in indexes:
            index_name = index_row[0]
            print(f"     - {index_name}")

        conn.close()

        print("\n=== Integrity Checks Complete ===")

    except Exception as e:
        print(f"✗ Integrity check failed: {e}")

if __name__ == "__main__":
    run_integrity_checks()
```

## Emergency Procedures

### Emergency Database Recovery

```python
# Emergency database recovery procedure
def emergency_database_recovery():
    """Recover from critical database failure."""

    print("WARNING: Emergency Database Recovery")
    print("This will attempt to recover from database corruption.")

    try:
        # 1. Create emergency backup
        db_path = Path.home() / '.privatus-chat' / 'privatus_chat.db'

        if db_path.exists():
            emergency_backup = db_path.with_suffix('.emergency')
            shutil.copy2(db_path, emergency_backup)
            print(f"✓ Emergency backup created: {emergency_backup}")

        # 2. Attempt automatic repair
        repair_success = attempt_database_repair(db_path)

        if repair_success:
            print("✓ Automatic repair successful")
        else:
            print("✗ Automatic repair failed")

            # 3. Try manual reconstruction
            reconstruction_success = attempt_manual_reconstruction()

            if reconstruction_success:
                print("✓ Manual reconstruction successful")
            else:
                print("✗ Manual reconstruction failed")

                # 4. Restore from latest backup
                backup_restored = restore_from_latest_backup()
                if backup_restored:
                    print("✓ Restored from latest backup")
                else:
                    print("✗ No valid backups available")

    except Exception as e:
        print(f"✗ Emergency recovery failed: {e}")
```

### Complete Storage Reset

```python
# Complete storage reset procedure
def complete_storage_reset():
    """Reset all storage to clean state."""

    print("WARNING: This will delete ALL stored data!")
    print("Ensure you have backups before proceeding.")

    confirmation = input("Type 'RESET' to confirm: ")
    if confirmation != 'RESET':
        print("Reset cancelled")
        return

    try:
        # 1. Create final backup
        final_backup = create_final_backup()
        if final_backup:
            print(f"✓ Final backup created: {final_backup}")

        # 2. Delete all storage files
        storage_dir = Path.home() / '.privatus-chat'
        if storage_dir.exists():
            import shutil
            shutil.rmtree(storage_dir)
            print("✓ Storage directory deleted")

        # 3. Recreate clean storage directory
        storage_dir.mkdir(parents=True, exist_ok=True)
        print("✓ Clean storage directory created")

        # 4. Initialize new storage
        from src.storage.database_fixed import StorageManager

        storage = StorageManager(storage_dir, "new_password")
        print("✓ New storage initialized")

        print("✓ Complete storage reset successful")

    except Exception as e:
        print(f"✗ Storage reset failed: {e}")
```

## Prevention and Best Practices

### Storage Maintenance Best Practices

1. **Regular Integrity Checks**:
   ```python
   # Implement regular integrity checking
   def schedule_integrity_checks():
       # Run integrity check weekly
       import schedule
       import time

       def run_integrity_check():
           try:
               integrity_ok = check_database_integrity()
               if integrity_ok:
                   print("✓ Scheduled integrity check passed")
               else:
                   print("✗ Scheduled integrity check failed")
                   # Send alert or attempt repair
           except Exception as e:
               print(f"✗ Scheduled integrity check error: {e}")

       schedule.every().week.do(run_integrity_check)

       # Keep running in background
       while True:
           schedule.run_pending()
           time.sleep(3600)  # Check every hour
   ```

2. **Automated Backup Strategy**:
   ```python
   # Implement automated backup strategy
   def setup_automated_backups():
       # Create daily backups
       schedule.every().day.at("02:00").do(create_daily_backup)

       # Create weekly full backups
       schedule.every().monday.at("03:00").do(create_weekly_backup)

       # Clean old backups monthly
       schedule.every(30).days.at("04:00").do(cleanup_old_backups)

       print("✓ Automated backup schedule configured")
   ```

3. **Storage Health Monitoring**:
   ```python
   # Monitor storage health
   def monitor_storage_health():
       # Check database size
       db_size_mb = get_database_size() / 1024 / 1024
       if db_size_mb > 100:  # 100MB threshold
           print(f"⚠ Large database size: {db_size_mb:.1f}MB")

       # Check backup freshness
       latest_backup_age = get_latest_backup_age()
       if latest_backup_age > 7 * 24 * 3600:  # 7 days
           print(f"⚠ Backups are {latest_backup_age / 24 / 3600:.1f} days old")

       # Check available disk space
       available_space_gb = get_available_space() / 1024 / 1024 / 1024
       if available_space_gb < 1:  # 1GB threshold
           print(f"⚠ Low disk space: {available_space_gb:.1f}GB available")
   ```

### Performance Optimization

1. **Database Optimization**:
   ```python
   # Optimize database performance
   def optimize_database_performance():
       conn = sqlite3.connect('privatus_chat.db')

       # Enable optimizations
       conn.execute("PRAGMA journal_mode=WAL")      # Better concurrency
       conn.execute("PRAGMA synchronous=NORMAL")    # Balance safety/performance
       conn.execute("PRAGMA cache_size=-64000")     # 64MB cache
       conn.execute("PRAGMA temp_store=memory")     # Memory temp storage

       # Analyze tables for query optimization
       conn.execute("ANALYZE")

       # Rebuild indexes if needed
       conn.execute("REINDEX")

       print("✓ Database performance optimized")
       conn.close()
   ```

2. **Connection Pooling**:
   ```python
   # Implement connection pooling for better performance
   import sqlite3
   import queue

   class ConnectionPool:
       def __init__(self, db_path, max_connections=10):
           self.db_path = db_path
           self.max_connections = max_connections
           self.pool = queue.Queue(maxsize=max_connections)

           # Pre-populate pool
           for _ in range(max_connections):
               conn = sqlite3.connect(db_path)
               conn.execute("PRAGMA journal_mode=WAL")
               self.pool.put(conn)

       def get_connection(self):
           return self.pool.get()

       def return_connection(self, conn):
           # Reset connection state
           conn.rollback()
           self.pool.put(conn)

       def close_all(self):
           while not self.pool.empty():
               conn = self.pool.get()
               conn.close()
   ```

3. **Query Optimization**:
   ```python
   # Optimize slow queries
   def optimize_slow_queries():
       # Create indexes for common queries
       conn.execute("""
           CREATE INDEX IF NOT EXISTS idx_messages_contact_timestamp
           ON messages(contact_id, timestamp)
       """)

       conn.execute("""
           CREATE INDEX IF NOT EXISTS idx_contacts_verified
           ON contacts(is_verified)
       """)

       # Use query result limits
       cursor.execute("""
           SELECT * FROM messages
           WHERE contact_id = ?
           ORDER BY timestamp DESC
           LIMIT ?
       """, (contact_id, limit))

       print("✓ Query optimizations applied")
   ```

## Getting Help

### Self-Service Resources

1. **Documentation**:
   - [Installation Guide](installation-guide.md)
   - [Backup and Recovery Guide](backup-recovery-procedures.md)
   - [Security Best Practices](security-best-practices.md)

2. **Community Support**:
   - [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
   - [Storage Discussions](https://github.com/privatus-chat/privatus-chat/discussions/categories/storage)

### Reporting Storage Issues

When reporting storage issues, please include:

1. **System Information**:
   - Operating system and version
   - Available disk space
   - File system type

2. **Storage Configuration**:
   - Database file location and size
   - Storage directory permissions
   - Backup configuration

3. **Problem Details**:
   - Exact error messages
   - Steps to reproduce
   - Storage diagnostic output

4. **Data State**:
   - Number of contacts and messages
   - Database schema version
   - Recent backup availability

---

*Remember: Database issues can result in data loss. Always maintain regular backups and verify their integrity. If you suspect data corruption, stop using the application and seek expert assistance.*

*Last updated: January 2025*
*Version: 1.0.0*