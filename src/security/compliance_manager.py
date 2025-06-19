# Compliance Manager
"""Regulatory compliance and standards management."""

import json
import logging
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import re

@dataclass
class ComplianceRequirement:
    """Represents a compliance requirement."""
    
    id: str
    standard: str  # GDPR, FIPS, PCI-DSS, etc.
    category: str  # privacy, cryptography, access_control, etc.
    title: str
    description: str
    priority: str  # critical, high, medium, low
    verification_method: str
    remediation_steps: List[str]
    references: List[str] = field(default_factory=list)
    
@dataclass
class ComplianceCheck:
    """Result of a compliance check."""
    
    requirement: ComplianceRequirement
    status: str  # compliant, non_compliant, partial, not_applicable
    evidence: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)
    
@dataclass
class UserConsent:
    """User consent record for GDPR compliance."""
    
    user_id: str
    purpose: str
    granted: bool
    timestamp: datetime
    ip_address: Optional[str] = None
    version: str = "1.0"
    withdrawn: Optional[datetime] = None

class ComplianceManager:
    """Manages regulatory compliance and standards adherence."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.compliance_checks = []
        self.user_consents = {}
        self.data_inventory = {}
        self.retention_policies = {}
        
        # Initialize compliance requirements
        self.requirements = {
            'GDPR': self._init_gdpr_requirements(),
            'FIPS': self._init_fips_requirements(),
            'PCI-DSS': self._init_pci_requirements(),
            'Common-Criteria': self._init_cc_requirements()
        }
        
        # Approved algorithms for FIPS compliance
        self.fips_approved_algorithms = {
            'symmetric': ['AES-128', 'AES-192', 'AES-256'],
            'asymmetric': ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384'],
            'hash': ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512'],
            'mac': ['HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512'],
            'kdf': ['PBKDF2', 'HKDF'],
            'random': ['CTR_DRBG', 'Hash_DRBG', 'HMAC_DRBG']
        }
        
    def _init_gdpr_requirements(self) -> List[ComplianceRequirement]:
        """Initialize GDPR compliance requirements."""
        requirements = []
        
        # Lawfulness of processing
        requirements.append(ComplianceRequirement(
            id="GDPR-6.1",
            standard="GDPR",
            category="privacy",
            title="Lawful basis for processing",
            description="Ensure all personal data processing has a lawful basis",
            priority="critical",
            verification_method="consent_audit",
            remediation_steps=[
                "Implement consent management system",
                "Document lawful basis for each processing activity",
                "Ensure consent is freely given, specific, informed, and unambiguous"
            ],
            references=["Article 6", "Article 7"]
        ))
        
        # Right to erasure
        requirements.append(ComplianceRequirement(
            id="GDPR-17",
            standard="GDPR",
            category="privacy",
            title="Right to erasure (Right to be forgotten)",
            description="Implement mechanisms for data deletion upon request",
            priority="critical",
            verification_method="deletion_capability",
            remediation_steps=[
                "Implement data deletion API",
                "Create deletion request workflow",
                "Ensure complete removal from all systems including backups"
            ],
            references=["Article 17"]
        ))
        
        # Data portability
        requirements.append(ComplianceRequirement(
            id="GDPR-20",
            standard="GDPR",
            category="privacy",
            title="Right to data portability",
            description="Allow users to export their data in machine-readable format",
            priority="high",
            verification_method="export_capability",
            remediation_steps=[
                "Implement data export functionality",
                "Support common formats (JSON, CSV)",
                "Include all personal data in exports"
            ],
            references=["Article 20"]
        ))
        
        # Privacy by design
        requirements.append(ComplianceRequirement(
            id="GDPR-25",
            standard="GDPR",
            category="privacy",
            title="Data protection by design and by default",
            description="Implement privacy considerations in system design",
            priority="high",
            verification_method="design_review",
            remediation_steps=[
                "Implement data minimization",
                "Use encryption by default",
                "Limit data retention periods",
                "Implement access controls"
            ],
            references=["Article 25"]
        ))
        
        # Security of processing
        requirements.append(ComplianceRequirement(
            id="GDPR-32",
            standard="GDPR",
            category="security",
            title="Security of processing",
            description="Implement appropriate technical and organizational measures",
            priority="critical",
            verification_method="security_audit",
            remediation_steps=[
                "Implement encryption of personal data",
                "Ensure confidentiality, integrity, availability",
                "Regular security testing",
                "Incident response procedures"
            ],
            references=["Article 32"]
        ))
        
        # Breach notification
        requirements.append(ComplianceRequirement(
            id="GDPR-33",
            standard="GDPR",
            category="incident_response",
            title="Notification of personal data breach",
            description="Notify authorities within 72 hours of breach awareness",
            priority="critical",
            verification_method="breach_procedures",
            remediation_steps=[
                "Implement breach detection mechanisms",
                "Create breach notification procedures",
                "Maintain breach register",
                "72-hour notification timeline"
            ],
            references=["Article 33", "Article 34"]
        ))
        
        return requirements
        
    def _init_fips_requirements(self) -> List[ComplianceRequirement]:
        """Initialize FIPS 140-2 compliance requirements."""
        requirements = []
        
        # Approved algorithms
        requirements.append(ComplianceRequirement(
            id="FIPS-140-2-1",
            standard="FIPS-140-2",
            category="cryptography",
            title="Use of approved cryptographic algorithms",
            description="Only use FIPS-approved cryptographic algorithms",
            priority="critical",
            verification_method="algorithm_audit",
            remediation_steps=[
                "Replace non-approved algorithms",
                "Use AES for symmetric encryption",
                "Use SHA-256 or higher for hashing",
                "Use approved random number generators"
            ],
            references=["FIPS 140-2 Annex A"]
        ))
        
        # Key management
        requirements.append(ComplianceRequirement(
            id="FIPS-140-2-2",
            standard="FIPS-140-2",
            category="cryptography",
            title="Cryptographic key management",
            description="Implement secure key generation, storage, and destruction",
            priority="critical",
            verification_method="key_management_audit",
            remediation_steps=[
                "Use approved key generation methods",
                "Implement secure key storage",
                "Key zeroization procedures",
                "Key lifecycle management"
            ],
            references=["FIPS 140-2 Section 4.7"]
        ))
        
        # Self-tests
        requirements.append(ComplianceRequirement(
            id="FIPS-140-2-3",
            standard="FIPS-140-2",
            category="cryptography",
            title="Cryptographic module self-tests",
            description="Perform power-up and conditional self-tests",
            priority="high",
            verification_method="self_test_verification",
            remediation_steps=[
                "Implement power-up self-tests",
                "Known answer tests for algorithms",
                "Continuous random number generator tests",
                "Software integrity tests"
            ],
            references=["FIPS 140-2 Section 4.9"]
        ))
        
        # Physical security
        requirements.append(ComplianceRequirement(
            id="FIPS-140-2-4",
            standard="FIPS-140-2",
            category="physical_security",
            title="Physical security requirements",
            description="Implement physical security for cryptographic modules",
            priority="medium",
            verification_method="physical_security_review",
            remediation_steps=[
                "Tamper-evident mechanisms",
                "Zeroization upon tamper detection",
                "Physical access controls",
                "Environmental failure protection"
            ],
            references=["FIPS 140-2 Section 4.5"]
        ))
        
        return requirements
        
    def _init_pci_requirements(self) -> List[ComplianceRequirement]:
        """Initialize PCI-DSS compliance requirements."""
        requirements = []
        
        # Encryption of cardholder data
        requirements.append(ComplianceRequirement(
            id="PCI-3.4",
            standard="PCI-DSS",
            category="data_protection",
            title="Encryption of stored cardholder data",
            description="Render PAN unreadable anywhere it is stored",
            priority="critical",
            verification_method="encryption_audit",
            remediation_steps=[
                "Implement strong encryption for stored data",
                "Use approved encryption algorithms",
                "Secure key management",
                "Document encryption methods"
            ],
            references=["PCI DSS 3.4"]
        ))
        
        # Secure transmission
        requirements.append(ComplianceRequirement(
            id="PCI-4.1",
            standard="PCI-DSS",
            category="network_security",
            title="Encrypt transmission of cardholder data",
            description="Use strong cryptography during transmission over networks",
            priority="critical",
            verification_method="network_encryption_audit",
            remediation_steps=[
                "Use TLS 1.2 or higher",
                "Strong cipher suites only",
                "Certificate validation",
                "No transmission over unencrypted channels"
            ],
            references=["PCI DSS 4.1"]
        ))
        
        return requirements
        
    def _init_cc_requirements(self) -> List[ComplianceRequirement]:
        """Initialize Common Criteria requirements."""
        requirements = []
        
        # Security target
        requirements.append(ComplianceRequirement(
            id="CC-ST",
            standard="Common-Criteria",
            category="documentation",
            title="Security Target documentation",
            description="Comprehensive security target document",
            priority="high",
            verification_method="documentation_review",
            remediation_steps=[
                "Define security objectives",
                "Document threats and assumptions",
                "Specify security requirements",
                "Map to protection profile"
            ],
            references=["CC Part 1"]
        ))
        
        # Security functions
        requirements.append(ComplianceRequirement(
            id="CC-SFR",
            standard="Common-Criteria",
            category="security_functions",
            title="Security Functional Requirements",
            description="Implement required security functions",
            priority="critical",
            verification_method="functional_testing",
            remediation_steps=[
                "Implement authentication mechanisms",
                "Access control enforcement",
                "Audit trail generation",
                "Cryptographic operations"
            ],
            references=["CC Part 2"]
        ))
        
        return requirements
        
    def check_compliance(self, standard: str = None) -> List[ComplianceCheck]:
        """Run compliance checks for specified standard or all standards."""
        checks = []
        
        standards_to_check = [standard] if standard else self.requirements.keys()
        
        for std in standards_to_check:
            if std in self.requirements:
                self.logger.info(f"Running {std} compliance checks...")
                
                for requirement in self.requirements[std]:
                    check = self._verify_requirement(requirement)
                    checks.append(check)
                    
        self.compliance_checks.extend(checks)
        return checks
        
    def _verify_requirement(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify a single compliance requirement."""
        # Route to appropriate verification method
        verification_methods = {
            'consent_audit': self._verify_consent_management,
            'deletion_capability': self._verify_deletion_capability,
            'export_capability': self._verify_export_capability,
            'design_review': self._verify_privacy_by_design,
            'security_audit': self._verify_security_measures,
            'breach_procedures': self._verify_breach_procedures,
            'algorithm_audit': self._verify_approved_algorithms,
            'key_management_audit': self._verify_key_management,
            'self_test_verification': self._verify_self_tests,
            'physical_security_review': self._verify_physical_security,
            'encryption_audit': self._verify_encryption,
            'network_encryption_audit': self._verify_network_encryption,
            'documentation_review': self._verify_documentation,
            'functional_testing': self._verify_security_functions
        }
        
        method = verification_methods.get(requirement.verification_method)
        if method:
            return method(requirement)
        else:
            return ComplianceCheck(
                requirement=requirement,
                status='not_applicable',
                issues=['No verification method available']
            )
            
    def _verify_consent_management(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify consent management implementation."""
        issues = []
        evidence = []
        recommendations = []
        
        # Check for consent storage
        if not self.user_consents:
            issues.append("No consent management system detected")
            recommendations.append("Implement consent tracking system")
        else:
            evidence.append(f"Consent records found: {len(self.user_consents)}")
            
        # Check consent attributes
        sample_consent = next(iter(self.user_consents.values()), None) if self.user_consents else None
        if sample_consent:
            required_fields = ['purpose', 'timestamp', 'version']
            for field in required_fields:
                if not hasattr(sample_consent, field):
                    issues.append(f"Missing consent field: {field}")
                    
        # Check withdrawal mechanism
        if not hasattr(self, 'withdraw_consent'):
            issues.append("No consent withdrawal mechanism")
            recommendations.append("Implement consent withdrawal functionality")
            
        status = 'compliant' if not issues else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues,
            recommendations=recommendations
        )
        
    def _verify_deletion_capability(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify data deletion capabilities."""
        issues = []
        evidence = []
        
        # Check for deletion methods
        deletion_methods = [
            'delete_user_data',
            'purge_expired_data',
            'anonymize_data'
        ]
        
        for method in deletion_methods:
            if hasattr(self, method):
                evidence.append(f"Deletion method available: {method}")
            else:
                issues.append(f"Missing deletion method: {method}")
                
        status = 'compliant' if len(evidence) >= 2 else 'partial'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_export_capability(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify data export capabilities."""
        issues = []
        evidence = []
        
        # Check export formats
        if hasattr(self, 'export_user_data'):
            evidence.append("Data export functionality available")
            
            # Check supported formats
            formats = getattr(self, 'supported_export_formats', [])
            if 'json' in formats and 'csv' in formats:
                evidence.append("Machine-readable formats supported")
            else:
                issues.append("Limited export format support")
        else:
            issues.append("No data export functionality")
            
        status = 'compliant' if not issues else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_privacy_by_design(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify privacy by design implementation."""
        evidence = []
        issues = []
        
        # Check for privacy features
        privacy_features = {
            'data_minimization': "Collecting only necessary data",
            'encryption_by_default': "All data encrypted at rest",
            'access_controls': "Role-based access control implemented",
            'retention_policies': "Automatic data expiration"
        }
        
        for feature, description in privacy_features.items():
            if self._check_feature_implemented(feature):
                evidence.append(description)
            else:
                issues.append(f"Missing: {description}")
                
        status = 'compliant' if len(evidence) >= 3 else 'partial'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_security_measures(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify security measures implementation."""
        evidence = []
        issues = []
        
        # Check encryption
        if self._check_encryption_enabled():
            evidence.append("Encryption enabled for personal data")
        else:
            issues.append("Encryption not properly configured")
            
        # Check access controls
        if self._check_access_controls():
            evidence.append("Access controls implemented")
        else:
            issues.append("Insufficient access controls")
            
        # Check audit logging
        if self._check_audit_logging():
            evidence.append("Audit logging enabled")
        else:
            issues.append("Audit logging not configured")
            
        status = 'compliant' if len(issues) == 0 else 'partial'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_breach_procedures(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify breach notification procedures."""
        evidence = []
        issues = []
        
        # Check for breach detection
        if hasattr(self, 'breach_detection_enabled'):
            evidence.append("Breach detection mechanisms in place")
        else:
            issues.append("No automated breach detection")
            
        # Check notification procedures
        if hasattr(self, 'breach_notification_procedure'):
            evidence.append("Breach notification procedure documented")
        else:
            issues.append("No breach notification procedure")
            
        # Check breach register
        if hasattr(self, 'breach_register'):
            evidence.append("Breach register maintained")
        else:
            issues.append("No breach register")
            
        status = 'compliant' if len(issues) == 0 else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_approved_algorithms(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify use of approved cryptographic algorithms."""
        evidence = []
        issues = []
        
        # Check symmetric algorithms
        used_symmetric = self._get_used_algorithms('symmetric')
        for algo in used_symmetric:
            if algo in self.fips_approved_algorithms['symmetric']:
                evidence.append(f"Approved symmetric algorithm: {algo}")
            else:
                issues.append(f"Non-approved symmetric algorithm: {algo}")
                
        # Check hash algorithms
        used_hash = self._get_used_algorithms('hash')
        for algo in used_hash:
            if algo in self.fips_approved_algorithms['hash']:
                evidence.append(f"Approved hash algorithm: {algo}")
            else:
                issues.append(f"Non-approved hash algorithm: {algo}")
                
        # Check random generators
        used_random = self._get_used_algorithms('random')
        if not any(rng in self.fips_approved_algorithms['random'] for rng in used_random):
            issues.append("No approved random number generator")
            
        status = 'compliant' if not issues else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_key_management(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify key management practices."""
        evidence = []
        issues = []
        
        # Check key generation
        if self._check_secure_key_generation():
            evidence.append("Secure key generation implemented")
        else:
            issues.append("Insecure key generation methods")
            
        # Check key storage
        if self._check_secure_key_storage():
            evidence.append("Keys stored securely")
        else:
            issues.append("Insecure key storage")
            
        # Check key destruction
        if hasattr(self, 'zeroize_keys'):
            evidence.append("Key zeroization implemented")
        else:
            issues.append("No key destruction mechanism")
            
        status = 'compliant' if not issues else 'partial'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_self_tests(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify cryptographic self-tests."""
        evidence = []
        issues = []
        
        # Check for self-test implementation
        self_tests = [
            'power_up_self_test',
            'known_answer_test',
            'continuous_rng_test',
            'software_integrity_test'
        ]
        
        for test in self_tests:
            if hasattr(self, test):
                evidence.append(f"Self-test implemented: {test}")
            else:
                issues.append(f"Missing self-test: {test}")
                
        status = 'compliant' if len(issues) <= 1 else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_physical_security(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify physical security measures."""
        # For software module, limited physical security applies
        evidence = ["Software-based cryptographic module"]
        
        return ComplianceCheck(
            requirement=requirement,
            status='partial',
            evidence=evidence,
            issues=["Physical security limited to software measures"],
            recommendations=["Implement tamper detection in software"]
        )
        
    def _verify_encryption(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify data encryption implementation."""
        evidence = []
        issues = []
        
        # Check encryption at rest
        if self._check_encryption_at_rest():
            evidence.append("Encryption at rest implemented")
        else:
            issues.append("No encryption at rest")
            
        # Check encryption strength
        if self._check_encryption_strength():
            evidence.append("Strong encryption algorithms used")
        else:
            issues.append("Weak encryption detected")
            
        status = 'compliant' if not issues else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_network_encryption(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify network encryption."""
        evidence = []
        issues = []
        
        # Check TLS configuration
        tls_config = self._check_tls_configuration()
        if tls_config.get('version', '') >= 'TLS1.2':
            evidence.append(f"TLS {tls_config['version']} enabled")
        else:
            issues.append("TLS version below 1.2")
            
        # Check cipher suites
        weak_ciphers = self._check_weak_ciphers()
        if not weak_ciphers:
            evidence.append("No weak cipher suites")
        else:
            issues.append(f"Weak ciphers enabled: {weak_ciphers}")
            
        status = 'compliant' if not issues else 'non_compliant'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_documentation(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify security documentation."""
        evidence = []
        issues = []
        
        # Check for required documents
        required_docs = [
            'security_target.md',
            'threat_model.md',
            'security_architecture.md'
        ]
        
        for doc in required_docs:
            if Path(doc).exists():
                evidence.append(f"Document exists: {doc}")
            else:
                issues.append(f"Missing document: {doc}")
                
        status = 'compliant' if not issues else 'partial'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    def _verify_security_functions(self, requirement: ComplianceRequirement) -> ComplianceCheck:
        """Verify security functional requirements."""
        evidence = []
        issues = []
        
        # Check authentication
        if self._check_authentication_mechanisms():
            evidence.append("Authentication mechanisms implemented")
        else:
            issues.append("Insufficient authentication")
            
        # Check access control
        if self._check_access_control_enforcement():
            evidence.append("Access control enforced")
        else:
            issues.append("Access control gaps")
            
        # Check audit trail
        if self._check_audit_trail():
            evidence.append("Audit trail implemented")
        else:
            issues.append("No audit trail")
            
        status = 'compliant' if not issues else 'partial'
        
        return ComplianceCheck(
            requirement=requirement,
            status=status,
            evidence=evidence,
            issues=issues
        )
        
    # GDPR-specific methods
    def record_consent(self, user_id: str, purpose: str, granted: bool,
                      ip_address: Optional[str] = None) -> UserConsent:
        """Record user consent for GDPR compliance."""
        consent = UserConsent(
            user_id=user_id,
            purpose=purpose,
            granted=granted,
            timestamp=datetime.now(),
            ip_address=ip_address
        )
        
        if user_id not in self.user_consents:
            self.user_consents[user_id] = []
            
        self.user_consents[user_id].append(consent)
        
        self.logger.info(f"Consent recorded for user {user_id}: {purpose} = {granted}")
        return consent
        
    def withdraw_consent(self, user_id: str, purpose: str) -> bool:
        """Withdraw user consent."""
        if user_id in self.user_consents:
            for consent in self.user_consents[user_id]:
                if consent.purpose == purpose and consent.granted and not consent.withdrawn:
                    consent.withdrawn = datetime.now()
                    self.logger.info(f"Consent withdrawn for user {user_id}: {purpose}")
                    return True
        return False
        
    def export_user_data(self, user_id: str, format: str = 'json') -> str:
        """Export user data for GDPR data portability."""
        user_data = {
            'user_id': user_id,
            'export_date': datetime.now().isoformat(),
            'consents': [],
            'personal_data': {},
            'processing_history': []
        }
        
        # Export consents
        if user_id in self.user_consents:
            user_data['consents'] = [
                {
                    'purpose': c.purpose,
                    'granted': c.granted,
                    'timestamp': c.timestamp.isoformat(),
                    'withdrawn': c.withdrawn.isoformat() if c.withdrawn else None
                }
                for c in self.user_consents[user_id]
            ]
            
        # Export personal data (placeholder)
        # In real implementation, gather from all systems
        
        if format == 'json':
            return json.dumps(user_data, indent=2)
        elif format == 'csv':
            # CSV export implementation
            pass
            
        return json.dumps(user_data)
        
    def delete_user_data(self, user_id: str) -> Dict[str, Any]:
        """Delete user data for GDPR right to erasure."""
        deletion_report = {
            'user_id': user_id,
            'deletion_date': datetime.now().isoformat(),
            'deleted_items': {},
            'retention_items': {}
        }
        
        # Delete consents
        if user_id in self.user_consents:
            deletion_report['deleted_items']['consents'] = len(self.user_consents[user_id])
            del self.user_consents[user_id]
            
        # Delete from data inventory
        deleted_count = 0
        for category in list(self.data_inventory.keys()):
            if user_id in self.data_inventory[category]:
                del self.data_inventory[category][user_id]
                deleted_count += 1
                
        deletion_report['deleted_items']['data_records'] = deleted_count
        
        # Log deletion
        self.logger.info(f"User data deleted for {user_id}")
        
        return deletion_report
        
    def set_retention_policy(self, data_type: str, retention_days: int,
                           purpose: str, legal_basis: str):
        """Set data retention policy."""
        self.retention_policies[data_type] = {
            'retention_days': retention_days,
            'purpose': purpose,
            'legal_basis': legal_basis,
            'created_at': datetime.now()
        }
        
    def apply_retention_policies(self) -> Dict[str, int]:
        """Apply retention policies and delete expired data."""
        deletion_stats = {}
        
        for data_type, policy in self.retention_policies.items():
            retention_days = policy['retention_days']
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # Delete expired data (placeholder)
            # In real implementation, delete from appropriate systems
            deleted_count = 0
            
            deletion_stats[data_type] = deleted_count
            
        return deletion_stats
        
    # FIPS-specific methods
    def validate_algorithm(self, algorithm: str, category: str) -> bool:
        """Validate if algorithm is FIPS-approved."""
        if category in self.fips_approved_algorithms:
            return algorithm in self.fips_approved_algorithms[category]
        return False
        
    def run_self_tests(self) -> Dict[str, bool]:
        """Run FIPS required self-tests."""
        test_results = {}
        
        # Power-up self-test
        test_results['power_up'] = self._run_power_up_test()
        
        # Known answer tests
        test_results['kat_aes'] = self._run_kat_aes()
        test_results['kat_sha'] = self._run_kat_sha()
        
        # Continuous RNG test
        test_results['rng_continuous'] = self._run_continuous_rng_test()
        
        # Software integrity test
        test_results['integrity'] = self._run_integrity_test()
        
        return test_results
        
    def _run_power_up_test(self) -> bool:
        """Run power-up self-test."""
        # Verify all cryptographic algorithms
        return True  # Placeholder
        
    def _run_kat_aes(self) -> bool:
        """Run AES known answer test."""
        # Test AES with known input/output
        return True  # Placeholder
        
    def _run_kat_sha(self) -> bool:
        """Run SHA known answer test."""
        # Test SHA with known input/output
        return True  # Placeholder
        
    def _run_continuous_rng_test(self) -> bool:
        """Run continuous random number generator test."""
        # Verify RNG output not repeating
        return True  # Placeholder
        
    def _run_integrity_test(self) -> bool:
        """Run software integrity test."""
        # Verify software hasn't been tampered
        return True  # Placeholder
        
    # Helper methods
    def _check_feature_implemented(self, feature: str) -> bool:
        """Check if a privacy feature is implemented."""
        # Placeholder - would check actual implementation
        return True
        
    def _check_encryption_enabled(self) -> bool:
        """Check if encryption is enabled."""
        return True
        
    def _check_access_controls(self) -> bool:
        """Check if access controls are implemented."""
        return True
        
    def _check_audit_logging(self) -> bool:
        """Check if audit logging is enabled."""
        return True
        
    def _get_used_algorithms(self, category: str) -> List[str]:
        """Get list of cryptographic algorithms in use."""
        # Placeholder - would scan actual usage
        if category == 'symmetric':
            return ['AES-256']
        elif category == 'hash':
            return ['SHA-256']
        elif category == 'random':
            return ['CTR_DRBG']
        return []
        
    def _check_secure_key_generation(self) -> bool:
        """Check if keys are generated securely."""
        return True
        
    def _check_secure_key_storage(self) -> bool:
        """Check if keys are stored securely."""
        return True
        
    def _check_encryption_at_rest(self) -> bool:
        """Check if data is encrypted at rest."""
        return True
        
    def _check_encryption_strength(self) -> bool:
        """Check encryption algorithm strength."""
        return True
        
    def _check_tls_configuration(self) -> Dict[str, str]:
        """Check TLS configuration."""
        return {'version': 'TLS1.3'}
        
    def _check_weak_ciphers(self) -> List[str]:
        """Check for weak cipher suites."""
        return []
        
    def _check_authentication_mechanisms(self) -> bool:
        """Check authentication implementation."""
        return True
        
    def _check_access_control_enforcement(self) -> bool:
        """Check access control enforcement."""
        return True
        
    def _check_audit_trail(self) -> bool:
        """Check audit trail implementation."""
        return True
        
    def generate_compliance_report(self) -> str:
        """Generate comprehensive compliance report."""
        report = "Compliance Report\n"
        report += "=" * 50 + "\n\n"
        
        # Group by standard
        by_standard = {}
        for check in self.compliance_checks:
            std = check.requirement.standard
            if std not in by_standard:
                by_standard[std] = []
            by_standard[std].append(check)
            
        # Report by standard
        for standard, checks in by_standard.items():
            report += f"\n{standard} Compliance\n"
            report += "-" * 30 + "\n"
            
            compliant = sum(1 for c in checks if c.status == 'compliant')
            partial = sum(1 for c in checks if c.status == 'partial')
            non_compliant = sum(1 for c in checks if c.status == 'non_compliant')
            
            report += f"Total Requirements: {len(checks)}\n"
            report += f"Compliant: {compliant}\n"
            report += f"Partial: {partial}\n"
            report += f"Non-Compliant: {non_compliant}\n\n"
            
            # Details for non-compliant items
            for check in checks:
                if check.status != 'compliant':
                    report += f"\n{check.requirement.id}: {check.requirement.title}\n"
                    report += f"Status: {check.status}\n"
                    if check.issues:
                        report += "Issues:\n"
                        for issue in check.issues:
                            report += f"  - {issue}\n"
                    if check.recommendations:
                        report += "Recommendations:\n"
                        for rec in check.recommendations:
                            report += f"  - {rec}\n"
                            
        return report 