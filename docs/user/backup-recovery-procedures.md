# Backup and Recovery Procedures

This document provides comprehensive procedures for backing up Privatus-chat data and recovering from various failure scenarios, ensuring data integrity and business continuity.

## Overview

Privatus-chat implements a multi-layered backup strategy with automated backups, manual procedures, and disaster recovery capabilities. The system supports full and incremental backups with encryption and integrity verification.

## Backup Strategy

### Backup Types

#### Full Backups
- **Complete system state**: All data, configuration, and metadata
- **Frequency**: Weekly on Sundays at 2:00 AM UTC
- **Retention**: 12 weeks of full backups
- **Encryption**: AES-256-GCM with unique keys per backup

#### Incremental Backups
- **Changes only**: Only modified data since last backup
- **Frequency**: Daily at 2:00 AM UTC
- **Retention**: 30 days of incremental backups
- **Efficiency**: Reduced storage and network usage

#### Real-time Replication
- **Continuous sync**: Real-time data replication to secondary site
- **RPO**: Near-zero recovery point objective
- **Geographic diversity**: Cross-region replication
- **Automatic failover**: Seamless failover capabilities

### Backup Components

#### Database Backups
- **PostgreSQL dumps**: Complete database schema and data
- **WAL archiving**: Write-ahead log shipping for point-in-time recovery
- **Connection pooling state**: PgBouncer configuration backup
- **Performance statistics**: Query statistics and performance data

#### File Storage Backups
- **User files**: All uploaded files and media
- **Application files**: Static assets and templates
- **Configuration files**: Environment and application configuration
- **SSL certificates**: TLS certificates and private keys

#### Application State Backups
- **Cache state**: Redis database dumps
- **Session data**: Active user sessions
- **DHT state**: Distributed hash table routing information
- **Metrics data**: Historical performance metrics

## Automated Backup Procedures

### Database Backup Script

#### PostgreSQL Backup
```bash
#!/bin/bash
# Automated PostgreSQL backup script

BACKUP_DIR="/opt/privatus-chat/backups/database"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=90

# Create backup directory
mkdir -p $BACKUP_DIR

# Full backup on Sundays
if [ "$(date +%u)" = "7" ]; then
    BACKUP_TYPE="full"
    pg_dump -h localhost -U privatus -Fc privatus_prod \
        -f $BACKUP_DIR/full_backup_$DATE.dump
else
    BACKUP_TYPE="incremental"
    # Incremental backup using WAL archiving
    psql -h localhost -U privatus -c \
        "SELECT pg_switch_wal();" privatus_prod
fi

# Encrypt backup
openssl enc -aes-256-gcm -salt \
    -in $BACKUP_DIR/${BACKUP_TYPE}_backup_$DATE.dump \
    -out $BACKUP_DIR/${BACKUP_TYPE}_backup_$DATE.dump.enc \
    -k $BACKUP_ENCRYPTION_KEY

# Generate integrity hash
sha256sum $BACKUP_DIR/${BACKUP_TYPE}_backup_$DATE.dump.enc \
    > $BACKUP_DIR/${BACKUP_TYPE}_backup_$DATE.dump.enc.sha256

# Cleanup old backups
find $BACKUP_DIR -type f -mtime +$RETENTION_DAYS -delete

# Log backup completion
echo "$(date): $BACKUP_TYPE backup completed successfully" \
    >> /var/log/privatus-chat/backup.log
```

#### Backup Verification
```bash
#!/bin/bash
# Backup verification script

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Verify file integrity
if ! sha256sum -c "${BACKUP_FILE}.sha256"; then
    echo "Backup integrity check failed"
    exit 1
fi

# Test backup decryption
if ! openssl enc -aes-256-gcm -d \
    -in "$BACKUP_FILE" \
    -out /tmp/test_restore.dump \
    -k $BACKUP_ENCRYPTION_KEY; then
    echo "Backup decryption failed"
    exit 1
fi

# Test backup restoration (dry run)
if ! pg_restore -l /tmp/test_restore.dump > /dev/null; then
    echo "Backup restoration test failed"
    exit 1
fi

echo "Backup verification successful"
```

### File System Backup

#### Configuration Backup
```bash
#!/bin/bash
# Configuration backup script

CONFIG_BACKUP_DIR="/opt/privatus-chat/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup application configuration
tar -czf $CONFIG_BACKUP_DIR/config_backup_$DATE.tar.gz \
    /opt/privatus-chat/config/

# Backup SSL certificates
tar -czf $CONFIG_BACKUP_DIR/ssl_backup_$DATE.tar.gz \
    /etc/ssl/certs/privatus-chat* \
    /etc/ssl/private/privatus-chat*

# Backup systemd service files
tar -czf $CONFIG_BACKUP_DIR/systemd_backup_$DATE.tar.gz \
    /etc/systemd/system/privatus-chat*

# Encrypt configuration backup
openssl enc -aes-256-gcm -salt \
    -in $CONFIG_BACKUP_DIR/config_backup_$DATE.tar.gz \
    -out $CONFIG_BACKUP_DIR/config_backup_$DATE.tar.gz.enc \
    -k $CONFIG_ENCRYPTION_KEY
```

## Recovery Procedures

### Database Recovery

#### Point-in-Time Recovery
```bash
#!/bin/bash
# Point-in-time database recovery script

RECOVERY_TIME="2025-01-15 10:30:00 UTC"
BACKUP_DIR="/opt/privatus-chat/backups/database"

# Stop application services
sudo systemctl stop privatus-chat@*

# Restore base backup
LATEST_FULL_BACKUP=$(ls -t $BACKUP_DIR/full_backup_*.dump.enc | head -1)
openssl enc -aes-256-gcm -d \
    -in $LATEST_FULL_BACKUP \
    -out /tmp/base_backup.dump \
    -k $BACKUP_ENCRYPTION_KEY

pg_restore -C -d postgres /tmp/base_backup.dump

# Apply WAL archives up to recovery point
psql -h localhost -U privatus privatus_prod -c \
    "SELECT pg_wal_replay_resume();"

# Wait for replay to reach recovery point
until psql -h localhost -U privatus privatus_prod -c \
    "SELECT now() >= '$RECOVERY_TIME'::timestamptz;" | grep -q t; do
    sleep 10
done

# Promote to primary
psql -h localhost -U privatus privatus_prod -c \
    "SELECT pg_promote();"

# Start application services
sudo systemctl start privatus-chat@*

# Verify recovery
curl -f http://localhost:8080/health
```

#### Complete Database Restoration
```bash
#!/bin/bash
# Complete database restoration script

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop all services
sudo systemctl stop privatus-chat@* postgresql redis

# Remove existing database
sudo -u postgres dropdb privatus_prod
sudo -u postgres createdb privatus_prod

# Decrypt and restore backup
openssl enc -aes-256-gcm -d \
    -in "$BACKUP_FILE" \
    -out /tmp/backup_restore.dump \
    -k $BACKUP_ENCRYPTION_KEY

sudo -u postgres pg_restore -d privatus_prod /tmp/backup_restore.dump

# Verify restoration
sudo -u postgres psql -d privatus_prod -c \
    "SELECT COUNT(*) FROM contacts;"

# Start services
sudo systemctl start postgresql redis
sleep 10
sudo systemctl start privatus-chat@*

# Final health check
curl -f http://localhost:8080/health
```

### File System Recovery

#### Configuration Recovery
```bash
#!/bin/bash
# Configuration recovery script

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <config_backup_file>"
    exit 1
fi

# Stop services
sudo systemctl stop privatus-chat@*

# Decrypt and extract configuration
openssl enc -aes-256-gcm -d \
    -in "$BACKUP_FILE" \
    -out /tmp/config_restore.tar.gz \
    -k $CONFIG_ENCRYPTION_KEY

tar -xzf /tmp/config_restore.tar.gz -C /

# Restore SSL certificates
sudo tar -xzf /tmp/ssl_restore.tar.gz -C /

# Set proper permissions
sudo chown -R privatus:privatus /opt/privatus-chat/config
sudo chmod -R 750 /opt/privatus-chat/config
sudo chmod 600 /opt/privatus-chat/config/.env

# Start services
sudo systemctl start privatus-chat@*

# Verify SSL certificates
sudo systemctl reload nginx
```

### Disaster Recovery

#### Complete System Recovery
```bash
#!/bin/bash
# Complete disaster recovery script

# 1. Provision new server
echo "Provisioning new server..."
# ... infrastructure provisioning code ...

# 2. Install base software
echo "Installing base software..."
sudo apt update
sudo apt install postgresql redis nginx docker

# 3. Restore configuration
echo "Restoring configuration..."
./restore_config.sh $CONFIG_BACKUP

# 4. Restore database
echo "Restoring database..."
./restore_database.sh $DATABASE_BACKUP

# 5. Restore application
echo "Deploying application..."
cd /opt/privatus-chat/app
git pull origin main
pip install -r requirements.txt

# 6. Start services
echo "Starting services..."
sudo systemctl start postgresql redis
sudo systemctl start privatus-chat@*
sudo systemctl reload nginx

# 7. Verify recovery
echo "Verifying recovery..."
if curl -f http://localhost:8080/health; then
    echo "Recovery successful"
else
    echo "Recovery failed - manual intervention required"
    exit 1
fi
```

## Backup Monitoring and Testing

### Backup Health Monitoring

#### Automated Backup Verification
```python
def verify_backup_integrity():
    """Verify backup integrity and completeness"""

    # Check backup file existence
    backup_files = list_backup_files()

    for backup_file in backup_files:
        # Verify file integrity
        if not verify_file_hash(backup_file):
            trigger_alert('BACKUP_CORRUPTION', {
                'file': backup_file,
                'issue': 'hash_mismatch'
            })
            continue

        # Test backup restoration (dry run)
        if not test_backup_restoration(backup_file):
            trigger_alert('BACKUP_UNUSABLE', {
                'file': backup_file,
                'issue': 'restoration_failed'
            })
            continue

        # Verify backup completeness
        if not verify_backup_completeness(backup_file):
            trigger_alert('BACKUP_INCOMPLETE', {
                'file': backup_file,
                'issue': 'missing_data'
            })
```

#### Backup Success Rate Monitoring
```python
def monitor_backup_success():
    """Monitor backup operation success rates"""

    # Calculate success rate over time windows
    daily_success = calculate_success_rate('24h')
    weekly_success = calculate_success_rate('7d')

    if daily_success < 0.95:  # Less than 95% success rate
        trigger_alert('BACKUP_RELIABILITY', {
            'period': '24h',
            'success_rate': daily_success,
            'threshold': 0.95
        })

    if weekly_success < 0.99:  # Less than 99% success rate
        trigger_alert('BACKUP_RELIABILITY', {
            'period': '7d',
            'success_rate': weekly_success,
            'threshold': 0.99
        })
```

### Recovery Testing

#### Automated Recovery Testing
```bash
#!/bin/bash
# Automated recovery testing script

TEST_ENVIRONMENT="recovery-test"
RECOVERY_TIME=$(date +%Y%m%d_%H%M%S)

# Create test environment
docker run -d --name postgres-test \
    -e POSTGRES_DB=privatus_test \
    postgres:13

# Wait for database to be ready
sleep 10

# Test database recovery
echo "Testing database recovery..."
if ./test_database_recovery.sh; then
    echo "Database recovery test: PASSED"
else
    echo "Database recovery test: FAILED"
    exit 1
fi

# Test configuration recovery
echo "Testing configuration recovery..."
if ./test_config_recovery.sh; then
    echo "Configuration recovery test: PASSED"
else
    echo "Configuration recovery test: FAILED"
    exit 1
fi

# Cleanup test environment
docker stop postgres-test
docker rm postgres-test

echo "All recovery tests passed"
```

#### Recovery Time Testing
```python
def test_recovery_times():
    """Test and monitor recovery time objectives"""

    # Test database recovery time
    db_recovery_time = measure_db_recovery_time()

    if db_recovery_time > MAX_DB_RTO:
        trigger_alert('RTO_EXCEEDED', {
            'component': 'database',
            'recovery_time': db_recovery_time,
            'target_rto': MAX_DB_RTO
        })

    # Test application recovery time
    app_recovery_time = measure_app_recovery_time()

    if app_recovery_time > MAX_APP_RTO:
        trigger_alert('RTO_EXCEEDED', {
            'component': 'application',
            'recovery_time': app_recovery_time,
            'target_rto': MAX_APP_RTO
        })
```

## Data Integrity and Validation

### Backup Integrity Checks

#### Cryptographic Verification
```python
def verify_backup_integrity(backup_path: str) -> bool:
    """Verify backup file integrity"""

    # Verify file hash
    expected_hash = read_hash_file(backup_path + '.sha256')
    actual_hash = calculate_file_hash(backup_path)

    if not hmac.compare_digest(expected_hash, actual_hash):
        return False

    # Verify encryption key validity
    try:
        decrypt_backup_header(backup_path)
        return True
    except InvalidTag:
        return False
```

#### Content Validation
```python
def validate_backup_content(backup_path: str) -> Dict[str, Any]:
    """Validate backup content and structure"""

    validation_results = {
        'schema_version': check_schema_version(backup_path),
        'table_integrity': check_table_integrity(backup_path),
        'reference_integrity': check_reference_integrity(backup_path),
        'data_consistency': check_data_consistency(backup_path)
    }

    return validation_results
```

### Recovery Validation

#### Post-Recovery Verification
```python
def verify_post_recovery():
    """Verify system state after recovery"""

    checks = {
        'database_connectivity': test_database_connection(),
        'application_health': test_application_health(),
        'data_integrity': verify_data_integrity(),
        'service_availability': test_service_availability(),
        'ssl_certificates': verify_ssl_certificates(),
        'configuration': verify_configuration()
    }

    all_checks_passed = all(checks.values())

    if not all_checks_passed:
        failed_checks = [k for k, v in checks.items() if not v]
        trigger_alert('RECOVERY_INCOMPLETE', {
            'failed_checks': failed_checks,
            'timestamp': datetime.utcnow().isoformat()
        })

    return all_checks_passed
```

## Security Considerations

### Secure Backup Handling

#### Encryption Key Management
- **Key Rotation**: Regular rotation of backup encryption keys
- **Access Control**: Restrict access to backup encryption keys
- **Key Escrow**: Secure key escrow for disaster recovery
- **Audit Logging**: Log all backup key access

#### Secure Storage
- **Encrypted Backups**: All backups encrypted before storage
- **Access Logging**: Log access to backup files
- **Retention Compliance**: Meet data retention requirements
- **Secure Deletion**: Cryptographic erasure of old backups

### Recovery Security

#### Secure Recovery Process
- **Authentication**: Verify identity before allowing recovery
- **Authorization**: Ensure proper permissions for recovery operations
- **Network Security**: Secure communication during recovery
- **Audit Trail**: Log all recovery operations

## Performance Optimization

### Backup Performance

#### Parallel Backup Processing
```python
def parallel_backup():
    """Perform backup operations in parallel"""

    # Parallel database dump
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(backup_table, table)
            for table in get_large_tables()
        ]

        for future in as_completed(futures):
            try:
                result = future.result()
                log_backup_progress(result)
            except Exception as e:
                log_backup_error(e)
```

#### Incremental Backup Optimization
```python
def optimize_incremental_backup():
    """Optimize incremental backup performance"""

    # Identify changed data blocks
    changed_blocks = identify_changed_blocks()

    # Compress changed blocks
    compressed_blocks = compress_data_blocks(changed_blocks)

    # Encrypt and store
    encrypted_backup = encrypt_backup_data(compressed_blocks)
    store_backup_increment(encrypted_backup)
```

### Recovery Performance

#### Recovery Time Optimization
```python
def optimize_recovery_time():
    """Optimize recovery time for RTO requirements"""

    # Parallel recovery operations
    parallel_operations = [
        'restore_database_schema',
        'restore_database_data',
        'restore_configuration',
        'restore_ssl_certificates'
    ]

    # Execute in parallel where possible
    with ThreadPoolExecutor(max_workers=len(parallel_operations)) as executor:
        futures = [
            executor.submit(operation)
            for operation in parallel_operations
        ]

        # Wait for critical operations first
        critical_operations = ['restore_database_schema', 'restore_configuration']
        for future in as_completed(futures):
            if future in critical_operations:
                result = future.result()
                if not result:
                    raise RecoveryError("Critical operation failed")
```

## Compliance and Reporting

### Backup Compliance

#### GDPR Compliance
- **Data Subject Rights**: Support for data export and deletion
- **Data Processing Records**: Maintain processing activity records
- **Security Measures**: Document security measures for backups
- **Breach Notification**: Procedures for breach reporting

#### HIPAA Compliance (if applicable)
- **PHI Protection**: Protected health information handling
- **Access Controls**: Role-based access to medical data
- **Audit Logs**: Comprehensive audit trail for medical data
- **Encryption**: FIPS 140-2 validated encryption

### Backup Reporting

#### Automated Backup Reports
```python
def generate_backup_report():
    """Generate comprehensive backup report"""

    report = {
        'report_date': datetime.utcnow().isoformat(),
        'backup_summary': get_backup_summary(),
        'recovery_testing': get_recovery_test_results(),
        'data_growth': calculate_data_growth(),
        'compliance_status': check_compliance_status(),
        'recommendations': generate_recommendations()
    }

    # Send report to stakeholders
    send_email_report(report, 'backup-team@privatus-chat.org')
    store_report(report, 'backup_reports')
```

## Troubleshooting

### Common Backup Issues

#### Backup Failures
**Symptoms**: Backup process fails or produces incomplete backups
**Troubleshooting**:
1. Check available disk space
2. Verify database connectivity
3. Check file permissions
4. Review system resource usage
5. Examine application logs

#### Recovery Failures
**Symptoms**: Recovery process fails or produces inconsistent state
**Troubleshooting**:
1. Verify backup file integrity
2. Check encryption keys
3. Validate system compatibility
4. Review recovery logs
5. Test with known good backup

#### Performance Issues
**Symptoms**: Backups take too long or impact production performance
**Solutions**:
1. Optimize backup scheduling
2. Use incremental backups
3. Parallelize backup operations
4. Increase system resources
5. Archive old data

## Maintenance Procedures

### Regular Maintenance

#### Daily Tasks
- Verify backup completion
- Check backup file integrity
- Monitor storage usage
- Review backup logs

#### Weekly Tasks
- Test backup restoration procedures
- Verify recovery time objectives
- Update backup documentation
- Review and optimize backup performance

#### Monthly Tasks
- Full disaster recovery testing
- Backup strategy review
- Compliance audit preparation
- Capacity planning updates

### Emergency Maintenance

#### Immediate Response
1. **Assess Impact**: Determine scope of data loss or corruption
2. **Activate Recovery**: Initiate appropriate recovery procedures
3. **Notify Stakeholders**: Inform affected parties
4. **Document Incident**: Record all recovery actions

#### Post-Incident Review
1. **Root Cause Analysis**: Identify cause of incident
2. **Process Improvement**: Update procedures based on lessons learned
3. **Testing Updates**: Modify testing procedures as needed
4. **Documentation Updates**: Update documentation with findings

## Support and Escalation

### Backup Support Levels

#### Level 1: Self-Service
- Check backup status and logs
- Verify backup file integrity
- Test basic recovery procedures
- Review documentation

#### Level 2: Technical Support
- Database backup and recovery issues
- Configuration and setup problems
- Performance optimization
- Integration issues

#### Level 3: Engineering Support
- Complex recovery scenarios
- Custom backup solutions
- Performance tuning
- Security and compliance issues

### Escalation Procedures

#### Backup Failure Escalation
1. **Initial Detection**: Automated monitoring detects failure
2. **Self-Service**: Attempt basic troubleshooting
3. **Technical Support**: Escalate to technical support team
4. **Engineering**: Escalate to engineering if needed
5. **Emergency Response**: Activate emergency procedures if critical

## Conclusion

This backup and recovery procedures document provides comprehensive guidance for ensuring Privatus-chat data protection and business continuity. The procedures cover automated backup processes, manual recovery steps, testing procedures, and operational best practices.

Regular testing, monitoring, and maintenance ensure the backup and recovery systems remain effective and reliable. The procedures are designed to meet enterprise requirements for data protection, compliance, and disaster recovery.

---

*Last updated: January 2025*
*Version: 1.0.0*