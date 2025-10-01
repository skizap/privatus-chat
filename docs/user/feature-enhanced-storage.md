# Enhanced Storage and Data Management

This document describes Privatus-chat's advanced storage features, including forward-secure message deletion, searchable encryption, conversation backup, profile management, and encrypted caching capabilities.

## Overview

Privatus-chat's enhanced storage system provides advanced data management capabilities while maintaining the highest levels of security and privacy. The system includes forward-secure deletion, searchable encryption, secure backup mechanisms, and comprehensive profile management.

## Key Features

### Forward-Secure Message Storage
- **Perfect forward secrecy**: Deleted messages cannot be recovered
- **Multiple security levels**: Configurable deletion strength
- **Secure key management**: Unique keys per message
- **Audit trails**: Comprehensive deletion logging

### Searchable Encryption
- **Privacy-preserving search**: Search content without decryption
- **Encrypted indexes**: Secure search token generation
- **Query privacy**: No search pattern leakage
- **Index management**: Efficient encrypted search structures

### Secure Backup System
- **Encrypted backups**: All backup data encrypted
- **Forward-secure deletion**: Secure backup removal
- **Incremental backups**: Efficient storage usage
- **Integrity verification**: Cryptographic backup validation

### Profile Management
- **Multiple profiles**: Support for multiple user identities
- **Encrypted settings**: Secure per-profile configuration
- **Zero-knowledge switching**: Private profile transitions
- **Profile isolation**: Complete separation between profiles

### Encrypted Caching
- **Performance optimization**: Fast access to frequently used data
- **Security preservation**: All cached data encrypted
- **Cache management**: Intelligent cache lifecycle management
- **Memory protection**: Secure in-memory data handling

## Forward-Secure Message Storage

### Security Levels

#### Basic Level
- **Overwrites**: Single-pass random data overwrite
- **Performance**: Fast deletion
- **Security**: Basic protection against simple recovery
- **Use case**: Low-security environments

#### Enhanced Level (Default)
- **Overwrites**: Three-pass random data overwrite
- **Performance**: Moderate deletion time
- **Security**: Strong protection against most recovery attempts
- **Use case**: Standard security requirements

#### Paranoid Level
- **Overwrites**: Seven-pass random data overwrite
- **Performance**: Slower deletion
- **Security**: Maximum protection against advanced recovery
- **Use case**: High-security environments

### Message Storage Architecture
```
Message → Unique Key Derivation → Encryption → Secure Storage → Forward-Secure Deletion
```

### Key Management
- **Per-message keys**: Unique encryption key for each message
- **Key derivation**: Cryptographically secure key generation
- **Memory protection**: Secure key handling in memory
- **Key rotation**: Optional key rotation for long-term storage

## Searchable Encryption

### Encrypted Search Process
1. **Index creation**: Generate encrypted search tokens during message storage
2. **Token storage**: Store searchable tokens with message references
3. **Query processing**: Encrypt search queries for privacy
4. **Result retrieval**: Return matching message identifiers

### Search Token Generation
- **Word tokenization**: Break messages into searchable words
- **Token encryption**: Encrypt tokens using search-specific keys
- **Duplicate handling**: Efficient storage of repeated words
- **Index maintenance**: Automatic index updates and cleanup

### Privacy Preservation
- **Query encryption**: Search queries encrypted before processing
- **Pattern hiding**: No search pattern correlation possible
- **Result privacy**: Only matching message IDs revealed
- **Access patterns**: No information about search frequency

## Secure Backup System

### Backup Types

#### Conversation Backups
- **Complete conversations**: Full message history backup
- **Selective backup**: Choose specific conversations
- **Incremental updates**: Only backup new messages
- **Compression**: Efficient storage usage

#### Full Application Backups
- **Complete data export**: All application data
- **Settings preservation**: Include all configuration
- **Key material backup**: Secure encryption key backup
- **Verification**: Cryptographic backup integrity checking

### Backup Security
- **End-to-end encryption**: All backup data encrypted
- **Unique backup keys**: Separate encryption for each backup
- **Integrity protection**: Cryptographic hash verification
- **Forward security**: Deleted backups cannot be recovered

## Profile Management

### Profile Structure
- **Profile isolation**: Complete separation between profiles
- **Encrypted settings**: All profile data encrypted
- **Key management**: Unique encryption keys per profile
- **Settings migration**: Secure transfer between profiles

### Profile Operations
- **Profile creation**: Generate new encrypted profiles
- **Profile switching**: Zero-knowledge profile transitions
- **Profile deletion**: Secure profile removal
- **Profile export**: Encrypted profile backup and transfer

## Encrypted Caching

### Cache Types

#### Message Preview Cache
- **Message snippets**: Cached message previews for UI
- **Search results**: Cached search result sets
- **Contact information**: Frequently accessed contact data
- **Conversation metadata**: Cached conversation information

#### Media Thumbnail Cache
- **Image thumbnails**: Encrypted thumbnail storage
- **Video previews**: Secure video preview caching
- **File metadata**: Encrypted file information cache
- **Media references**: Cached media location data

### Cache Security
- **Encryption at rest**: All cached data encrypted on disk
- **Memory protection**: Secure handling in memory
- **Access controls**: Proper permission checks for cached data
- **Cleanup procedures**: Secure cache entry removal

## Usage Guide

### Forward-Secure Message Deletion

#### Basic Message Deletion
1. **Select message** in conversation view
2. **Choose delete option** from context menu
3. **Confirm deletion** with security level selection
4. **Secure deletion** with overwrite protection
5. **Audit log entry** for compliance

#### Bulk Message Deletion
1. **Select multiple messages** for deletion
2. **Choose security level** for all deletions
3. **Batch deletion process** with progress indication
4. **Verification** of successful deletion
5. **Comprehensive audit trail** for all deleted messages

### Searchable Message Search

#### Basic Search
1. **Enter search query** in search field
2. **Encrypted query processing** for privacy
3. **Result display** with message previews
4. **Context navigation** to full messages
5. **Search history** (optional, encrypted)

#### Advanced Search Features
1. **Filter by contact** or conversation
2. **Date range filtering** for targeted searches
3. **Content type filtering** (text, files, media)
4. **Search within search results** for refinement

### Conversation Backup

#### Creating Backups
1. **Select conversation** for backup
2. **Choose backup options** (full or incremental)
3. **Set backup location** and encryption
4. **Create backup** with progress monitoring
5. **Verify backup integrity** automatically

#### Restoring from Backup
1. **Select backup file** for restoration
2. **Verify backup integrity** and authenticity
3. **Choose restore options** (merge or replace)
4. **Restore process** with conflict resolution
5. **Verify restored data** matches original

### Profile Management

#### Creating New Profile
1. **Access profile settings** in application preferences
2. **Create new profile** with unique name
3. **Configure profile settings** and preferences
4. **Set encryption options** for profile data
5. **Initialize profile** with secure key generation

#### Switching Profiles
1. **Select target profile** from profile list
2. **Authenticate** profile switch (if required)
3. **Zero-knowledge transition** to new profile
4. **Settings application** from new profile
5. **Secure cleanup** of previous profile data

## Configuration

### Storage Security Settings
Access via **Settings → Storage → Security**:

- **Default deletion level**: Set preferred message deletion security level
- **Key rotation interval**: Configure automatic key rotation frequency
- **Backup encryption**: Set default backup encryption strength
- **Audit logging**: Enable/disable detailed storage operation logging

### Search Settings
- **Search index updates**: Automatic or manual index maintenance
- **Search result limits**: Maximum search results returned
- **Search history**: Enable/disable encrypted search history
- **Index optimization**: Automatic index cleanup and optimization

### Backup Settings
- **Automatic backups**: Schedule regular conversation backups
- **Backup retention**: How long to keep backup files
- **Backup locations**: Configure backup storage destinations
- **Compression settings**: Balance between size and speed

### Cache Settings
- **Cache size limits**: Maximum cache storage allocation
- **Cache expiration**: Default cache entry lifetimes
- **Cache encryption**: Encryption strength for cached data
- **Cleanup frequency**: How often to clean expired cache entries

## Best Practices

### Security Best Practices
1. **Use appropriate deletion levels** for your security requirements
2. **Regularly backup** important conversations
3. **Verify backup integrity** before relying on backups
4. **Use strong encryption** for profile data
5. **Monitor storage audit logs** for suspicious activity

### Performance Best Practices
1. **Configure appropriate cache sizes** for your hardware
2. **Use incremental backups** for frequent backup operations
3. **Optimize search indexes** regularly for search performance
4. **Monitor storage usage** to prevent disk space issues

### Privacy Best Practices
1. **Use searchable encryption** for message content privacy
2. **Separate profiles** for different identity contexts
3. **Securely delete** sensitive conversation data
4. **Regularly rotate** encryption keys for enhanced security

## Troubleshooting

### Common Issues

#### Search Not Finding Messages
**Possible causes:**
- Search index not updated
- Message not yet indexed
- Search query too specific
- Index corruption

**Solutions:**
- Wait for index update or trigger manually
- Check message timestamp for indexing delay
- Try broader search terms
- Rebuild search index if corrupted

#### Backup Restoration Fails
**Possible causes:**
- Backup file corruption
- Encryption key mismatch
- Incompatible backup format
- Storage space issues

**Solutions:**
- Verify backup file integrity
- Check encryption keys and passwords
- Ensure backup format compatibility
- Free up storage space for restoration

#### Profile Switch Issues
**Possible causes:**
- Profile data corruption
- Insufficient permissions
- Key management problems
- Storage access issues

**Solutions:**
- Verify profile data integrity
- Check file permissions and access
- Review key management settings
- Test with different storage locations

## Technical Details

### Forward Security Implementation
- **Key derivation**: HKDF-based per-message key generation
- **Secure deletion**: Multiple-pass random data overwrite
- **Memory protection**: Secure key handling and cleanup
- **Audit compliance**: Comprehensive deletion logging

### Searchable Encryption Algorithm
- **Token generation**: HMAC-based deterministic token creation
- **Index structure**: Efficient encrypted search tree
- **Query processing**: Privacy-preserving query encryption
- **Result ranking**: Encrypted relevance scoring

### Backup Encryption
- **Backup key generation**: Unique keys for each backup
- **Data compression**: Zlib compression before encryption
- **Integrity protection**: SHA-256 hash verification
- **Metadata protection**: Encrypted backup metadata

## API Reference

### Enhanced Storage Manager
```python
class EnhancedStorageManager:
    def store_message_with_forward_secrecy(self, message_id: str, content: str,
                                          contact_id: str, is_outgoing: bool) -> bool:
        """Store message with forward secrecy and searchable encryption."""

    def search_messages(self, query: str) -> List[str]:
        """Search for messages using encrypted search index."""

    def delete_message_with_forward_secrecy(self, message_id: str) -> bool:
        """Delete message with forward secrecy guarantees."""

    def create_conversation_backup(self, contact_id: str) -> Optional[str]:
        """Create encrypted backup of conversation."""

    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive storage usage statistics."""
```

### Profile Manager
```python
class ProfileManager:
    def create_profile(self, name: str, settings: Dict[str, Any]) -> str:
        """Create new encrypted profile."""

    def switch_profile(self, profile_id: str) -> bool:
        """Switch to different profile with zero-knowledge transition."""

    def get_profile_settings(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Get decrypted settings for profile."""

    def delete_profile(self, profile_id: str) -> bool:
        """Securely delete profile and all associated data."""
```

## Support

For enhanced storage issues:
- Check the [Troubleshooting](#troubleshooting) section
- Review [FAQ](faq.md) for common questions
- Search [GitHub Issues](https://github.com/privatus-chat/issues)
- Ask in [Community Forum](https://forum.privatus-chat.org)

---

*Last updated: January 2025*
*Version: 1.0.0*