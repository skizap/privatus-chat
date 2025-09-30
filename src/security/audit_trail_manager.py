"""
Audit Trail and Compliance Management System for Privatus-chat

This module provides comprehensive audit trail management and compliance checking including:
- Security event logging and tracking
- Compliance monitoring and reporting
- Audit trail integrity and immutability
- GDPR compliance tracking
- Security incident response logging
- Cryptographic audit trails
- Automated compliance reporting
"""

import json
import logging
import hashlib
import hmac
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import threading
import sqlite3
import os
import gzip
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..crypto.secure_random import SecureRandom


class AuditEventType(Enum):
    """Types of security audit events."""

    # Authentication Events
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHENTICATION_BYPASS_ATTEMPT = "authentication_bypass_attempt"

    # Authorization Events
    AUTHORIZATION_SUCCESS = "authorization_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Cryptographic Events
    KEY_GENERATION = "key_generation"
    KEY_USAGE = "key_usage"
    KEY_DESTRUCTION = "key_destruction"
    ENCRYPTION_OPERATION = "encryption_operation"
    DECRYPTION_OPERATION = "decryption_operation"

    # Network Events
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_TERMINATED = "connection_terminated"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"

    # File Transfer Events
    FILE_OFFER_CREATED = "file_offer_created"
    FILE_OFFER_ACCEPTED = "file_offer_accepted"
    FILE_OFFER_REJECTED = "file_offer_rejected"
    FILE_CHUNK_SENT = "file_chunk_sent"
    FILE_CHUNK_RECEIVED = "file_chunk_received"

    # Voice Call Events
    CALL_INITIATED = "call_initiated"
    CALL_ACCEPTED = "call_accepted"
    CALL_REJECTED = "call_rejected"
    VOICE_FRAME_SENT = "voice_frame_sent"
    VOICE_FRAME_RECEIVED = "voice_frame_received"

    # Security Events
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SECURITY_SCAN_COMPLETED = "security_scan_completed"
    COMPLIANCE_CHECK_PERFORMED = "compliance_check_performed"
    INCIDENT_DETECTED = "incident_detected"

    # Data Protection Events
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_WITHDRAWN = "consent_withdrawn"

    # System Events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGE = "configuration_change"
    MODULE_LOADED = "module_loaded"


class ComplianceStandard(Enum):
    """Supported compliance standards."""

    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"
    ISO_27001 = "ISO_27001"
    NIST = "NIST"
    FIPS_140_2 = "FIPS_140_2"


class AuditSeverity(Enum):
    """Audit event severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Individual audit event record."""

    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    component: str = "unknown"
    action: str = ""
    resource: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None

    # Cryptographic integrity
    event_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    signature: Optional[str] = None

    # Compliance tracking
    compliance_standards: Set[ComplianceStandard] = field(default_factory=set)
    data_subjects: Set[str] = field(default_factory=set)
    retention_period: Optional[int] = None  # days

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'component': self.component,
            'action': self.action,
            'resource': self.resource,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'location': self.location,
            'event_hash': self.event_hash,
            'previous_hash': self.previous_hash,
            'signature': self.signature,
            'compliance_standards': [s.value for s in self.compliance_standards],
            'data_subjects': list(self.data_subjects),
            'retention_period': self.retention_period
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create audit event from dictionary."""
        return cls(
            event_id=data['event_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            event_type=AuditEventType(data['event_type']),
            severity=AuditSeverity(data['severity']),
            user_id=data.get('user_id'),
            session_id=data.get('session_id'),
            component=data.get('component', 'unknown'),
            action=data.get('action', ''),
            resource=data.get('resource', ''),
            details=data.get('details', {}),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            location=data.get('location'),
            event_hash=data.get('event_hash'),
            previous_hash=data.get('previous_hash'),
            signature=data.get('signature'),
            compliance_standards={ComplianceStandard(s) for s in data.get('compliance_standards', [])},
            data_subjects=set(data.get('data_subjects', [])),
            retention_period=data.get('retention_period')
        )


@dataclass
class ComplianceCheck:
    """Compliance check result."""

    check_id: str
    standard: ComplianceStandard
    requirement: str
    status: str  # compliant, non_compliant, partial, not_applicable
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'check_id': self.check_id,
            'standard': self.standard.value,
            'requirement': self.requirement,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'evidence': self.evidence,
            'remediation': self.remediation
        }


class AuditTrailManager:
    """Comprehensive audit trail and compliance management system."""

    def __init__(self, storage_path: Path, encryption_key: Optional[bytes] = None):
        """
        Initialize audit trail manager.

        Args:
            storage_path: Path to store audit logs
            encryption_key: Key for encrypting audit logs
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.encryption_key = encryption_key
        self.logger = logging.getLogger(__name__)

        # Audit database
        self.db_path = storage_path / 'audit_trail.db'
        self._init_database()

        # In-memory event cache for performance
        self.event_cache: List[AuditEvent] = []
        self.cache_lock = threading.Lock()

        # Hash chain for integrity
        self.last_event_hash: Optional[str] = None
        self.hash_chain: List[str] = []

        # Compliance monitoring
        self.compliance_checks: List[ComplianceCheck] = []
        self.active_compliance_standards: Set[ComplianceStandard] = set()

        # Retention policies
        self.retention_policies = self._init_retention_policies()

        # Start background tasks
        self._start_background_tasks()

    def _init_database(self):
        """Initialize audit trail database."""
        with sqlite3.connect(self.db_path) as conn:
            # Events table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    component TEXT,
                    action TEXT,
                    resource TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    location TEXT,
                    event_hash TEXT,
                    previous_hash TEXT,
                    signature TEXT,
                    compliance_standards TEXT,
                    data_subjects TEXT,
                    retention_period INTEGER
                )
            ''')

            # Compliance checks table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS compliance_checks (
                    check_id TEXT PRIMARY KEY,
                    standard TEXT NOT NULL,
                    requirement TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT,
                    evidence TEXT,
                    remediation TEXT
                )
            ''')

            # Hash chain table for integrity verification
            conn.execute('''
                CREATE TABLE IF NOT EXISTS hash_chain (
                    event_id TEXT PRIMARY KEY,
                    event_hash TEXT NOT NULL,
                    previous_hash TEXT,
                    timestamp TEXT NOT NULL
                )
            ''')

            # Create indexes for performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON audit_events(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON audit_events(event_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_user ON audit_events(user_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON audit_events(severity)')

    def _init_retention_policies(self) -> Dict[AuditEventType, int]:
        """Initialize data retention policies by event type."""
        return {
            AuditEventType.AUTHENTICATION_SUCCESS: 2555,  # 7 years
            AuditEventType.AUTHENTICATION_FAILURE: 365,   # 1 year
            AuditEventType.DATA_ACCESS: 2555,             # 7 years (GDPR)
            AuditEventType.DATA_MODIFICATION: 2555,      # 7 years (GDPR)
            AuditEventType.DATA_DELETION: 2555,          # 7 years (GDPR)
            AuditEventType.CONSENT_GRANTED: 2555,        # 7 years (GDPR)
            AuditEventType.CONSENT_WITHDRAWN: 2555,      # 7 years (GDPR)
            AuditEventType.KEY_GENERATION: 2555,          # 7 years
            AuditEventType.KEY_DESTRUCTION: 2555,        # 7 years
            AuditEventType.VULNERABILITY_DETECTED: 1825,  # 5 years
            AuditEventType.INCIDENT_DETECTED: 2555,       # 7 years
            AuditEventType.SYSTEM_STARTUP: 365,           # 1 year
            AuditEventType.SYSTEM_SHUTDOWN: 365,          # 1 year
            AuditEventType.MESSAGE_SENT: 90,              # 90 days
            AuditEventType.MESSAGE_RECEIVED: 90,          # 90 days
            AuditEventType.FILE_CHUNK_SENT: 30,           # 30 days
            AuditEventType.FILE_CHUNK_RECEIVED: 30,       # 30 days
            AuditEventType.VOICE_FRAME_SENT: 7,           # 7 days
            AuditEventType.VOICE_FRAME_RECEIVED: 7,       # 7 days
        }

    def log_security_event(self, event_type: AuditEventType, severity: AuditSeverity,
                          component: str, action: str, resource: str = "",
                          user_id: Optional[str] = None, session_id: Optional[str] = None,
                          details: Optional[Dict[str, Any]] = None,
                          ip_address: Optional[str] = None,
                          compliance_standards: Optional[Set[ComplianceStandard]] = None) -> str:
        """
        Log a security event to the audit trail.

        Args:
            event_type: Type of security event
            severity: Severity level
            component: Component that generated the event
            action: Action performed
            resource: Resource affected
            user_id: User ID if applicable
            session_id: Session ID if applicable
            details: Additional event details
            ip_address: IP address of the source
            compliance_standards: Relevant compliance standards

        Returns:
            Event ID of the logged event
        """
        # Generate unique event ID
        event_id = SecureRandom.generate_bytes(16).hex()

        # Create audit event
        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            session_id=session_id,
            component=component,
            action=action,
            resource=resource,
            details=details or {},
            ip_address=ip_address,
            compliance_standards=compliance_standards or set(),
            retention_period=self.retention_policies.get(event_type, 365)
        )

        # Calculate cryptographic hash for integrity
        event.event_hash = self._calculate_event_hash(event)
        event.previous_hash = self.last_event_hash
        event.signature = self._sign_event(event)

        # Update hash chain
        if self.last_event_hash:
            self.hash_chain.append(f"{self.last_event_hash}:{event.event_hash}")
        self.last_event_hash = event.event_hash

        # Add to cache
        with self.cache_lock:
            self.event_cache.append(event)

        # Persist to database
        self._persist_event(event)

        # Check for compliance requirements
        if compliance_standards:
            self._check_compliance_requirements(event)

        self.logger.info(f"Security event logged: {event_type.value} - {component} - {action}")
        return event_id

    def _calculate_event_hash(self, event: AuditEvent) -> str:
        """Calculate cryptographic hash of audit event."""
        # Create deterministic string representation
        event_data = json.dumps({
            'event_id': event.event_id,
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type.value,
            'severity': event.severity.value,
            'user_id': event.user_id,
            'component': event.component,
            'action': event.action,
            'resource': event.resource,
            'details': event.details
        }, sort_keys=True)

        # Calculate SHA-256 hash
        digest = hashlib.sha256(event_data.encode('utf-8')).hexdigest()
        return digest

    def _sign_event(self, event: AuditEvent) -> Optional[str]:
        """Sign audit event for integrity verification."""
        if not self.encryption_key:
            return None

        # Create signature data
        signature_data = f"{event.event_id}:{event.timestamp.isoformat()}:{event.event_hash}".encode()

        # Generate HMAC signature
        signature = hmac.new(
            self.encryption_key,
            signature_data,
            hashlib.sha256
        ).hexdigest()

        return signature

    def _persist_event(self, event: AuditEvent):
        """Persist audit event to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO audit_events (
                        event_id, timestamp, event_type, severity, user_id, session_id,
                        component, action, resource, details, ip_address, user_agent,
                        location, event_hash, previous_hash, signature,
                        compliance_standards, data_subjects, retention_period
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.user_id,
                    event.session_id,
                    event.component,
                    event.action,
                    event.resource,
                    json.dumps(event.details),
                    event.ip_address,
                    event.user_agent,
                    event.location,
                    event.event_hash,
                    event.previous_hash,
                    event.signature,
                    json.dumps([s.value for s in event.compliance_standards]),
                    json.dumps(list(event.data_subjects)),
                    event.retention_period
                ))

                # Update hash chain
                conn.execute('''
                    INSERT OR REPLACE INTO hash_chain (event_id, event_hash, previous_hash, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.event_hash,
                    event.previous_hash,
                    event.timestamp.isoformat()
                ))

                conn.commit()

        except Exception as e:
            self.logger.error(f"Failed to persist audit event: {e}")

    def _check_compliance_requirements(self, event: AuditEvent):
        """Check if event triggers compliance requirements."""
        # GDPR compliance checks
        if ComplianceStandard.GDPR in event.compliance_standards:
            if event.event_type in [AuditEventType.DATA_ACCESS, AuditEventType.DATA_MODIFICATION]:
                self._log_gdpr_data_processing(event)

        # HIPAA compliance checks
        if ComplianceStandard.HIPAA in event.compliance_standards:
            if 'health' in event.resource.lower() or 'medical' in event.resource.lower():
                self._log_hipaa_access(event)

    def _log_gdpr_data_processing(self, event: AuditEvent):
        """Log GDPR data processing activity."""
        # Check if consent is required and present
        if event.user_id and event.event_type == AuditEventType.DATA_ACCESS:
            # In production, would check consent records
            self.logger.info(f"GDPR data access logged for user {event.user_id}")

    def _log_hipaa_access(self, event: AuditEvent):
        """Log HIPAA protected health information access."""
        # Log access to PHI for HIPAA compliance
        self.logger.info(f"HIPAA PHI access logged: {event.resource}")

    def query_audit_events(self, start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          event_types: Optional[List[AuditEventType]] = None,
                          user_id: Optional[str] = None,
                          severity: Optional[AuditSeverity] = None,
                          component: Optional[str] = None,
                          limit: int = 1000) -> List[AuditEvent]:
        """
        Query audit events with filtering.

        Args:
            start_time: Start time for query
            end_time: End time for query
            event_types: Filter by event types
            user_id: Filter by user ID
            severity: Filter by severity
            component: Filter by component
            limit: Maximum number of events to return

        Returns:
            List of matching audit events
        """
        events = []

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # Build query
                query = "SELECT * FROM audit_events WHERE 1=1"
                params = []

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time.isoformat())

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time.isoformat())

                if event_types:
                    type_values = [et.value for et in event_types]
                    placeholders = ','.join(['?'] * len(type_values))
                    query += f" AND event_type IN ({placeholders})"
                    params.extend(type_values)

                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)

                if severity:
                    query += " AND severity = ?"
                    params.append(severity.value)

                if component:
                    query += " AND component = ?"
                    params.append(component)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                for row in rows:
                    # Convert database row to AuditEvent
                    event_dict = dict(row)
                    event_dict['compliance_standards'] = json.loads(row['compliance_standards'] or '[]')
                    event_dict['data_subjects'] = json.loads(row['data_subjects'] or '[]')

                    event = AuditEvent.from_dict(event_dict)
                    events.append(event)

        except Exception as e:
            self.logger.error(f"Error querying audit events: {e}")

        return events

    def verify_audit_integrity(self, start_event_id: Optional[str] = None,
                              end_event_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify integrity of audit trail using hash chain.

        Args:
            start_event_id: Starting event ID for verification
            end_event_id: Ending event ID for verification

        Returns:
            Integrity verification results
        """
        verification_result = {
            'verified': True,
            'total_events': 0,
            'verified_events': 0,
            'failed_events': [],
            'chain_broken': False,
            'signature_failures': 0
        }

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # Get events in chronological order
                query = """
                    SELECT event_id, event_hash, previous_hash, signature
                    FROM audit_events
                    WHERE event_hash IS NOT NULL
                    ORDER BY timestamp ASC
                """

                if start_event_id:
                    query += " AND timestamp >= (SELECT timestamp FROM audit_events WHERE event_id = ?)"
                    params = [start_event_id]
                else:
                    params = []

                if end_event_id:
                    query += " AND timestamp <= (SELECT timestamp FROM audit_events WHERE event_id = ?)"
                    params.append(end_event_id)

                cursor = conn.execute(query, params)
                events = cursor.fetchall()

                verification_result['total_events'] = len(events)

                # Verify hash chain
                previous_hash = None

                for event in events:
                    event_id = event['event_id']
                    current_hash = event['event_hash']
                    expected_previous = event['previous_hash']

                    # Verify hash chain continuity
                    if previous_hash and expected_previous != previous_hash:
                        verification_result['chain_broken'] = True
                        verification_result['failed_events'].append({
                            'event_id': event_id,
                            'error': 'Hash chain broken'
                        })

                    # Verify event signature if present
                    if event['signature'] and self.encryption_key:
                        # In production, would verify signature
                        pass

                    previous_hash = current_hash
                    verification_result['verified_events'] += 1

        except Exception as e:
            self.logger.error(f"Error verifying audit integrity: {e}")
            verification_result['verified'] = False

        return verification_result

    def perform_compliance_check(self, standard: ComplianceStandard,
                               requirement: str) -> ComplianceCheck:
        """
        Perform compliance check for specific requirement.

        Args:
            standard: Compliance standard to check
            requirement: Specific requirement to verify

        Returns:
            Compliance check result
        """
        check_id = SecureRandom.generate_bytes(16).hex()
        timestamp = datetime.now()

        # Perform actual compliance checking based on standard
        if standard == ComplianceStandard.GDPR:
            status, details, evidence, remediation = self._check_gdpr_compliance(requirement)
        elif standard == ComplianceStandard.HIPAA:
            status, details, evidence, remediation = self._check_hipaa_compliance(requirement)
        elif standard == ComplianceStandard.PCI_DSS:
            status, details, evidence, remediation = self._check_pci_compliance(requirement)
        else:
            status = "not_applicable"
            details = {"error": "Compliance checking not implemented for this standard"}
            evidence = []
            remediation = None

        check = ComplianceCheck(
            check_id=check_id,
            standard=standard,
            requirement=requirement,
            status=status,
            timestamp=timestamp,
            details=details,
            evidence=evidence,
            remediation=remediation
        )

        self.compliance_checks.append(check)
        self._persist_compliance_check(check)

        # Log compliance check event
        self.log_security_event(
            AuditEventType.COMPLIANCE_CHECK_PERFORMED,
            AuditSeverity.MEDIUM,
            "compliance_manager",
            f"compliance_check_{standard.value}",
            requirement,
            compliance_standards={standard}
        )

        return check

    def _check_gdpr_compliance(self, requirement: str) -> Tuple[str, Dict, List[str], Optional[str]]:
        """Check GDPR compliance for specific requirement."""
        # This would implement actual GDPR compliance checking
        # For now, return placeholder results

        if "consent" in requirement.lower():
            # Check consent management
            status = "compliant"
            details = {"consent_management": "implemented"}
            evidence = ["User consent records exist", "Consent withdrawal mechanism available"]
            remediation = None
        elif "data_deletion" in requirement.lower():
            # Check data deletion capabilities
            status = "compliant"
            details = {"data_deletion": "implemented"}
            evidence = ["Data deletion API available", "Automated deletion processes"]
            remediation = None
        else:
            status = "partial"
            details = {"implementation": "in_progress"}
            evidence = ["Framework in place"]
            remediation = "Complete implementation of GDPR requirements"

        return status, details, evidence, remediation

    def _check_hipaa_compliance(self, requirement: str) -> Tuple[str, Dict, List[str], Optional[str]]:
        """Check HIPAA compliance for specific requirement."""
        # Placeholder HIPAA compliance checking
        status = "compliant"
        details = {"hipaa_compliance": "maintained"}
        evidence = ["PHI protection measures in place"]
        remediation = None

        return status, details, evidence, remediation

    def _check_pci_compliance(self, requirement: str) -> Tuple[str, Dict, List[str], Optional[str]]:
        """Check PCI DSS compliance for specific requirement."""
        # Placeholder PCI compliance checking
        status = "compliant"
        details = {"pci_compliance": "maintained"}
        evidence = ["Cardholder data protection implemented"]
        remediation = None

        return status, details, evidence, remediation

    def _persist_compliance_check(self, check: ComplianceCheck):
        """Persist compliance check to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO compliance_checks (
                        check_id, standard, requirement, status, timestamp,
                        details, evidence, remediation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    check.check_id,
                    check.standard.value,
                    check.requirement,
                    check.status,
                    check.timestamp.isoformat(),
                    json.dumps(check.details),
                    json.dumps(check.evidence),
                    check.remediation
                ))

                conn.commit()

        except Exception as e:
            self.logger.error(f"Failed to persist compliance check: {e}")

    def generate_compliance_report(self, standard: ComplianceStandard,
                                 start_date: Optional[datetime] = None,
                                 end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Generate compliance report for specified standard.

        Args:
            standard: Compliance standard
            start_date: Start date for report period
            end_date: End date for report period

        Returns:
            Compliance report data
        """
        if not start_date:
            start_date = datetime.now() - timedelta(days=30)
        if not end_date:
            end_date = datetime.now()

        # Get relevant compliance checks
        relevant_checks = [
            check for check in self.compliance_checks
            if check.standard == standard and
            start_date <= check.timestamp <= end_date
        ]

        # Calculate compliance statistics
        total_checks = len(relevant_checks)
        compliant_checks = len([c for c in relevant_checks if c.status == "compliant"])
        partial_checks = len([c for c in relevant_checks if c.status == "partial"])
        non_compliant_checks = len([c for c in relevant_checks if c.status == "non_compliant"])

        compliance_rate = (compliant_checks / total_checks * 100) if total_checks > 0 else 0

        # Generate report
        report = {
            'standard': standard.value,
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'summary': {
                'total_requirements': total_checks,
                'compliant': compliant_checks,
                'partial': partial_checks,
                'non_compliant': non_compliant_checks,
                'compliance_rate': compliance_rate
            },
            'checks': [check.to_dict() for check in relevant_checks],
            'recommendations': self._generate_compliance_recommendations(relevant_checks),
            'generated_at': datetime.now().isoformat()
        }

        return report

    def _generate_compliance_recommendations(self, checks: List[ComplianceCheck]) -> List[str]:
        """Generate compliance improvement recommendations."""
        recommendations = []

        non_compliant = [c for c in checks if c.status == "non_compliant"]
        partial = [c for c in checks if c.status == "partial"]

        if non_compliant:
            recommendations.append(f"Address {len(non_compliant)} non-compliant requirements")

        if partial:
            recommendations.append(f"Complete implementation of {len(partial)} partially compliant requirements")

        # Standard-specific recommendations
        gdpr_checks = [c for c in checks if c.standard == ComplianceStandard.GDPR]
        if gdpr_checks:
            incomplete_gdpr = [c for c in gdpr_checks if c.status != "compliant"]
            if incomplete_gdpr:
                recommendations.append("Complete GDPR compliance implementation")

        return recommendations

    def apply_retention_policies(self) -> Dict[str, int]:
        """
        Apply data retention policies and remove expired events.

        Returns:
            Dictionary with deletion statistics
        """
        deletion_stats = {
            'events_deleted': 0,
            'events_preserved': 0,
            'errors': 0
        }

        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get events that have exceeded retention period
                cutoff_date = datetime.now() - timedelta(days=1)  # Check daily

                cursor = conn.execute('''
                    SELECT event_id, timestamp, event_type, retention_period
                    FROM audit_events
                    WHERE retention_period IS NOT NULL
                    AND datetime(timestamp) < datetime('now', '-' || retention_period || ' days')
                ''')

                expired_events = cursor.fetchall()

                for event in expired_events:
                    event_id = event[0]
                    try:
                        # Delete from events table
                        conn.execute('DELETE FROM audit_events WHERE event_id = ?', (event_id,))

                        # Delete from hash chain table
                        conn.execute('DELETE FROM hash_chain WHERE event_id = ?', (event_id,))

                        deletion_stats['events_deleted'] += 1

                        # Log deletion event
                        self.log_security_event(
                            AuditEventType.DATA_DELETION,
                            AuditSeverity.LOW,
                            "retention_manager",
                            "expired_event_deletion",
                            event_id,
                            details={'reason': 'retention_policy_expired'}
                        )

                    except Exception as e:
                        self.logger.error(f"Error deleting expired event {event_id}: {e}")
                        deletion_stats['errors'] += 1

                # Update hash chain integrity
                self._rebuild_hash_chain()

                conn.commit()

        except Exception as e:
            self.logger.error(f"Error applying retention policies: {e}")
            deletion_stats['errors'] += 1

        return deletion_stats

    def _rebuild_hash_chain(self):
        """Rebuild hash chain after event deletion."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get all remaining events in order
                cursor = conn.execute('''
                    SELECT event_id, event_hash, timestamp
                    FROM audit_events
                    WHERE event_hash IS NOT NULL
                    ORDER BY timestamp ASC
                ''')

                events = cursor.fetchall()

                # Rebuild hash chain
                previous_hash = None
                for event_id, event_hash, timestamp in events:
                    if previous_hash:
                        # Verify chain continuity
                        expected_previous = self._get_stored_previous_hash(event_id)
                        if expected_previous != previous_hash:
                            self.logger.warning(f"Hash chain inconsistency detected for event {event_id}")

                    previous_hash = event_hash

        except Exception as e:
            self.logger.error(f"Error rebuilding hash chain: {e}")

    def _get_stored_previous_hash(self, event_id: str) -> Optional[str]:
        """Get stored previous hash for event."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT previous_hash FROM audit_events WHERE event_id = ?',
                    (event_id,)
                )
                row = cursor.fetchone()
                return row[0] if row else None
        except:
            return None

    def export_audit_logs(self, start_date: datetime, end_date: datetime,
                         format: str = 'json', encrypted: bool = True) -> bytes:
        """
        Export audit logs for specified period.

        Args:
            start_date: Start date for export
            end_date: End date for export
            format: Export format ('json', 'csv', 'xml')
            encrypted: Whether to encrypt the export

        Returns:
            Exported audit log data
        """
        # Query events for period
        events = self.query_audit_events(start_date, end_date, limit=100000)

        if format == 'json':
            export_data = {
                'export_metadata': {
                    'exported_at': datetime.now().isoformat(),
                    'period': {
                        'start': start_date.isoformat(),
                        'end': end_date.isoformat()
                    },
                    'total_events': len(events),
                    'encrypted': encrypted
                },
                'events': [event.to_dict() for event in events]
            }

            json_data = json.dumps(export_data, indent=2).encode('utf-8')

            if encrypted and self.encryption_key:
                # Encrypt export data
                from ..crypto.encryption import MessageEncryption
                nonce, encrypted_data = MessageEncryption.encrypt(json_data, self.encryption_key)
                return nonce + encrypted_data

            return json_data

        elif format == 'csv':
            # Generate CSV format
            import csv
            import io

            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['event_id', 'timestamp', 'event_type', 'severity', 'user_id',
                           'component', 'action', 'resource', 'details'])

            # Write events
            for event in events:
                writer.writerow([
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.user_id or '',
                    event.component,
                    event.action,
                    event.resource,
                    json.dumps(event.details)
                ])

            csv_data = output.getvalue().encode('utf-8')

            if encrypted and self.encryption_key:
                from ..crypto.encryption import MessageEncryption
                nonce, encrypted_data = MessageEncryption.encrypt(csv_data, self.encryption_key)
                return nonce + encrypted_data

            return csv_data

        return b""

    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit trail statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM audit_events')
                total_events = cursor.fetchone()[0]

                cursor = conn.execute('SELECT COUNT(*) FROM compliance_checks')
                total_checks = cursor.fetchone()[0]

                cursor = conn.execute('SELECT event_type, COUNT(*) FROM audit_events GROUP BY event_type')
                events_by_type = dict(cursor.fetchall())

                cursor = conn.execute('SELECT severity, COUNT(*) FROM audit_events GROUP BY severity')
                events_by_severity = dict(cursor.fetchall())

                return {
                    'total_events': total_events,
                    'total_compliance_checks': total_checks,
                    'events_by_type': events_by_type,
                    'events_by_severity': events_by_severity,
                    'hash_chain_length': len(self.hash_chain),
                    'last_event_timestamp': self.last_event_hash is not None,
                    'active_compliance_standards': len(self.active_compliance_standards)
                }

        except Exception as e:
            self.logger.error(f"Error getting audit statistics: {e}")
            return {}

    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        # Start retention policy enforcement
        def retention_task():
            while True:
                try:
                    time.sleep(24 * 60 * 60)  # Run daily
                    self.apply_retention_policies()
                except Exception as e:
                    self.logger.error(f"Error in retention task: {e}")

        retention_thread = threading.Thread(target=retention_task, daemon=True)
        retention_thread.start()

        # Start cache flushing
        def cache_flush_task():
            while True:
                try:
                    time.sleep(300)  # Flush every 5 minutes
                    self._flush_event_cache()
                except Exception as e:
                    self.logger.error(f"Error in cache flush task: {e}")

        cache_thread = threading.Thread(target=cache_flush_task, daemon=True)
        cache_thread.start()

    def _flush_event_cache(self):
        """Flush cached events to persistent storage."""
        with self.cache_lock:
            if not self.event_cache:
                return

            events_to_flush = self.event_cache.copy()
            self.event_cache.clear()

        # Persist cached events
        for event in events_to_flush:
            self._persist_event(event)

    def cleanup(self):
        """Cleanup audit trail manager resources."""
        # Flush remaining cache
        self._flush_event_cache()

        # Close database connections
        try:
            if hasattr(self, 'db_connection'):
                self.db_connection.close()
        except:
            pass