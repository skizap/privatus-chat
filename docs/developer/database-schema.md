# Database Schema and Data Relationships

This document defines the complete database schema for Privatus-chat, including table structures, relationships, indexes, and data integrity constraints.

## Overview

Privatus-chat uses SQLite as the primary data storage backend with encryption at rest. The schema supports contacts, messages, groups, settings, and audit trails while maintaining referential integrity and performance.

## Core Database Schema

### Database Configuration
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;
PRAGMA foreign_keys = ON;
PRAGMA encoding = 'UTF-8';
```

## Table Definitions

### Contacts Table
```sql
CREATE TABLE contacts (
    contact_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_online BOOLEAN DEFAULT FALSE,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Purpose**: Stores contact information and metadata
**Encryption**: Contact data encrypted using master key
**Indexes**: contact_id (PRIMARY), display_name, is_online

### Messages Table
```sql
CREATE TABLE messages (
    message_id TEXT PRIMARY KEY,
    contact_id TEXT NOT NULL,
    content BLOB NOT NULL,
    is_outgoing BOOLEAN NOT NULL,
    is_encrypted BOOLEAN DEFAULT TRUE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    edited_at TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (contact_id) REFERENCES contacts (contact_id) ON DELETE CASCADE
);
```

**Purpose**: Stores encrypted message content and metadata
**Encryption**: Message content encrypted with per-message keys
**Indexes**: message_id (PRIMARY), contact_id, timestamp, is_deleted

### Groups Table
```sql
CREATE TABLE groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    group_type TEXT NOT NULL CHECK (group_type IN ('public', 'private', 'secret')),
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    max_members INTEGER DEFAULT 100,
    is_anonymous BOOLEAN DEFAULT TRUE,
    settings TEXT, -- JSON encrypted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Purpose**: Stores group chat information and configuration
**Encryption**: Group settings encrypted with group key
**Indexes**: group_id (PRIMARY), group_type, created_by

### Group Members Table
```sql
CREATE TABLE group_members (
    group_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_online BOOLEAN DEFAULT FALSE,
    anonymous_id TEXT, -- For anonymous group participation
    permissions TEXT, -- JSON encrypted permissions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, contact_id),
    FOREIGN KEY (group_id) REFERENCES groups (group_id) ON DELETE CASCADE
);
```

**Purpose**: Manages group membership and roles
**Encryption**: Member permissions encrypted with group key
**Indexes**: group_id, contact_id, role, is_online

### Settings Table
```sql
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Purpose**: Stores encrypted application settings
**Encryption**: Setting values encrypted with master key
**Indexes**: key (PRIMARY), updated_at

### Audit Log Table
```sql
CREATE TABLE audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    user_id TEXT,
    resource_type TEXT,
    resource_id TEXT,
    action TEXT NOT NULL,
    details TEXT, -- JSON encrypted details
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);
```

**Purpose**: Comprehensive audit trail for security and compliance
**Encryption**: Log details encrypted for privacy
**Indexes**: timestamp, event_type, user_id, resource_type

### Key Store Table
```sql
CREATE TABLE key_store (
    key_id TEXT PRIMARY KEY,
    key_type TEXT NOT NULL,
    encrypted_key BLOB NOT NULL,
    algorithm TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    usage_count INTEGER DEFAULT 0
);
```

**Purpose**: Secure storage of encryption keys
**Encryption**: Keys encrypted with master key or HSM
**Indexes**: key_id (PRIMARY), key_type, expires_at

### File Transfers Table
```sql
CREATE TABLE file_transfers (
    transfer_id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_hash TEXT NOT NULL,
    contact_id TEXT,
    group_id TEXT,
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'paused', 'completed', 'failed', 'cancelled')),
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    FOREIGN KEY (contact_id) REFERENCES contacts (contact_id) ON DELETE SET NULL,
    FOREIGN KEY (group_id) REFERENCES groups (group_id) ON DELETE SET NULL
);
```

**Purpose**: Track file transfer operations and status
**Encryption**: File metadata encrypted
**Indexes**: transfer_id (PRIMARY), contact_id, group_id, status

## Data Relationships

### Entity Relationship Diagram
```
contacts (1) ───┬─── (many) messages
                │
                ├─── (many) file_transfers
                │
                └─── (many) group_members

groups (1) ─────┼─── (many) group_members
                │
                ├─── (many) messages (group messages)
                │
                └─── (many) file_transfers

key_store (1) ─── (many) contacts (public keys)
                │
                ├─── (many) messages (message keys)
                │
                └─── (many) groups (group keys)

settings (1) ─── (many) users (preferences)

audit_log (many) ─── (1) contacts (user actions)
                   │
                   ├─── (1) groups (group actions)
                   │
                   └─── (1) messages (message actions)
```

## Index Definitions

### Performance Indexes
```sql
-- Message retrieval performance
CREATE INDEX idx_messages_contact_timestamp ON messages(contact_id, timestamp);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
CREATE INDEX idx_messages_outgoing ON messages(is_outgoing, timestamp);

-- Contact search performance
CREATE INDEX idx_contacts_display_name ON contacts(display_name);
CREATE INDEX idx_contacts_online ON contacts(is_online, last_seen);

-- Group query performance
CREATE INDEX idx_groups_type ON groups(group_type);
CREATE INDEX idx_group_members_group_role ON group_members(group_id, role);

-- Audit log analysis
CREATE INDEX idx_audit_timestamp_type ON audit_log(timestamp, event_type);
CREATE INDEX idx_audit_user_events ON audit_log(user_id, timestamp);

-- File transfer tracking
CREATE INDEX idx_transfers_status ON file_transfers(status, created_at);
CREATE INDEX idx_transfers_contact ON file_transfers(contact_id, created_at);
```

### Security Indexes
```sql
-- Failed authentication tracking
CREATE INDEX idx_audit_failed_auth ON audit_log(event_type, success, timestamp)
WHERE event_type = 'authentication' AND success = FALSE;

-- Suspicious activity detection
CREATE INDEX idx_audit_suspicious ON audit_log(timestamp, ip_address, success)
WHERE success = FALSE;

-- Key usage monitoring
CREATE INDEX idx_keys_last_used ON key_store(last_used, usage_count);
CREATE INDEX idx_keys_expiring ON key_store(expires_at) WHERE expires_at IS NOT NULL;
```

## Data Integrity Constraints

### Referential Integrity
- **Cascade Deletes**: Messages deleted when contacts removed
- **Null Constraints**: Required fields cannot be null
- **Check Constraints**: Enum values validated at database level
- **Foreign Key Enforcement**: Maintains referential consistency

### Domain Constraints
```sql
-- Message size limits
ALTER TABLE messages ADD CONSTRAINT check_message_size
CHECK (length(content) <= 1048576); -- 1MB max message size

-- Group member limits
ALTER TABLE group_members ADD CONSTRAINT check_group_size
CHECK (
    (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = group_members.group_id) <=
    (SELECT max_members FROM groups g WHERE g.group_id = group_members.group_id)
);

-- Timestamp consistency
ALTER TABLE messages ADD CONSTRAINT check_timestamp_order
CHECK (edited_at IS NULL OR edited_at >= timestamp);
```

## Encryption Architecture

### Data Encryption Layers
```
User Data → Application Encryption → Database Encryption → Storage Encryption
```

### Encryption Key Hierarchy
- **Master Key**: Derived from user password (PBKDF2)
- **Database Key**: Encrypts entire database file
- **Table Keys**: Encrypt sensitive columns
- **Row Keys**: Encrypt individual sensitive rows

### Encrypted Columns
- **messages.content**: Message content with per-message keys
- **contacts.public_key**: Public keys with master key
- **settings.value**: Configuration data with master key
- **audit_log.details**: Audit details with master key
- **key_store.encrypted_key**: Keys with master key or HSM

## Partitioning Strategy

### Time-based Partitioning
```sql
-- Messages partitioned by month for performance
CREATE TABLE messages_202501 (LIKE messages);
CREATE TABLE messages_202502 (LIKE messages);
-- ... additional monthly partitions
```

### Size-based Partitioning
```sql
-- Large message content in separate storage
CREATE TABLE message_content (
    message_id TEXT PRIMARY KEY REFERENCES messages(message_id),
    content BLOB NOT NULL,
    compression_algorithm TEXT,
    compressed_size INTEGER,
    original_size INTEGER
);
```

## Backup and Recovery Schema

### Backup Metadata Table
```sql
CREATE TABLE backup_metadata (
    backup_id TEXT PRIMARY KEY,
    backup_type TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    total_size INTEGER,
    file_count INTEGER,
    encryption_info TEXT, -- JSON with encryption details
    integrity_hash TEXT,
    retention_until TIMESTAMP
);
```

### Backup Contents Table
```sql
CREATE TABLE backup_contents (
    backup_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    record_count INTEGER,
    data_size INTEGER,
    checksum TEXT,
    FOREIGN KEY (backup_id) REFERENCES backup_metadata(backup_id) ON DELETE CASCADE
);
```

## Performance Optimization

### Query Optimization
```sql
-- Analyze query patterns for index optimization
ANALYZE messages;
ANALYZE contacts;
ANALYZE groups;

-- Optimize database for read-heavy workload
PRAGMA optimize;
```

### Connection Pooling
```sql
-- Connection pool configuration for concurrent access
PRAGMA busy_timeout = 30000; -- 30 second timeout
PRAGMA journal_mode = WAL;   -- Write-Ahead Logging for concurrency
```

## Data Migration Schema

### Migration Tracking
```sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    checksum TEXT,
    success BOOLEAN DEFAULT TRUE
);
```

### Migration Procedures
```sql
-- Version 1.0.0: Initial schema
CREATE TABLE initial_tables AS SELECT * FROM existing_tables;

-- Version 1.1.0: Add new columns
ALTER TABLE contacts ADD COLUMN profile_picture TEXT;
ALTER TABLE messages ADD COLUMN reply_to TEXT REFERENCES messages(message_id);
```

## Monitoring and Analytics Schema

### Performance Metrics
```sql
CREATE TABLE performance_metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metric_name TEXT NOT NULL,
    metric_value REAL,
    unit TEXT,
    category TEXT,
    metadata TEXT -- JSON additional context
);
```

### Usage Statistics
```sql
CREATE TABLE usage_statistics (
    stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL,
    metric TEXT NOT NULL,
    value INTEGER DEFAULT 0,
    UNIQUE(date, metric)
);
```

## Security Schema Extensions

### Access Control Table
```sql
CREATE TABLE access_control (
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    user_id TEXT,
    permissions TEXT NOT NULL, -- JSON permissions
    granted_by TEXT,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    PRIMARY KEY (resource_type, resource_id, user_id)
);
```

### Security Events Table
```sql
CREATE TABLE security_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source_ip TEXT,
    user_id TEXT,
    description TEXT,
    raw_data TEXT, -- Encrypted raw event data
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolution TEXT
);
```

## Data Retention Policies

### Automated Cleanup Procedures
```sql
-- Clean old audit logs (retain 1 year)
DELETE FROM audit_log WHERE timestamp < date('now', '-1 year');

-- Clean expired cache entries
DELETE FROM cache_entries WHERE expires_at < datetime('now');

-- Archive old messages (move to archive table)
INSERT INTO messages_archive SELECT * FROM messages
WHERE timestamp < date('now', '-6 months');
DELETE FROM messages WHERE timestamp < date('now', '-6 months');
```

### Retention Configuration
```sql
CREATE TABLE retention_policies (
    table_name TEXT PRIMARY KEY,
    retention_days INTEGER NOT NULL,
    archive_table TEXT,
    cleanup_enabled BOOLEAN DEFAULT TRUE,
    last_cleanup TIMESTAMP
);
```

## Database Maintenance

### Integrity Checks
```sql
-- Comprehensive integrity verification
PRAGMA integrity_check;
PRAGMA foreign_key_check;
PRAGMA quick_check;

-- Statistics update
ANALYZE;
```

### Optimization Procedures
```sql
-- Rebuild indexes for performance
REINDEX messages;
REINDEX contacts;
REINDEX groups;

-- Database optimization
VACUUM;
PRAGMA optimize;
```

## Schema Evolution

### Version Management
- **Current Version**: 1.0.0
- **Migration Strategy**: Rolling migrations with rollback capability
- **Compatibility**: Backward compatibility with older versions
- **Testing**: Comprehensive migration testing

### Future Extensions
- **Vector Storage**: Support for vector databases
- **Graph Relations**: Social graph storage
- **Time Series**: Performance metrics storage
- **Document Store**: Rich content storage

## Implementation Notes

### Connection Management
- **Connection Pooling**: Reuse database connections
- **Timeout Configuration**: Appropriate timeout values
- **Error Handling**: Robust error recovery
- **Transaction Management**: Proper transaction boundaries

### Performance Considerations
- **Batch Operations**: Group multiple operations
- **Index Selection**: Appropriate index usage
- **Query Optimization**: Efficient query patterns
- **Caching Strategy**: Database result caching

## Security Considerations

### Access Control
- **File Permissions**: Restrict database file access
- **Encryption at Rest**: Database file encryption
- **Network Security**: Secure database connections
- **Audit Logging**: Comprehensive access logging

### Data Protection
- **Input Validation**: Prevent injection attacks
- **Output Encoding**: Safe data retrieval
- **Error Handling**: No sensitive data in errors
- **Memory Management**: Secure memory handling

## Conclusion

This database schema provides a solid foundation for Privatus-chat's data storage requirements while maintaining security, performance, and scalability. The schema supports all current features while allowing for future enhancements and optimizations.

The design emphasizes data integrity, security, and performance while providing comprehensive audit trails and monitoring capabilities. Regular maintenance and optimization ensure continued reliable operation.

---

*Last updated: January 2025*
*Version: 1.0.0*