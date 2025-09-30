"""
Security Infrastructure Tests for Privatus-chat
Week 9: Security Hardening

Test suite for the security components including vulnerability scanning, protocol fuzzing,
security auditing, compliance management, and bug bounty management.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from src.security.security_auditor import SecurityAuditor, AuditSeverity
from src.security.vulnerability_scanner import VulnerabilityScanner, VulnerabilityType
from src.security.protocol_fuzzer import ProtocolFuzzer, FuzzingStrategy
from src.security.compliance_manager import ComplianceManager, ComplianceStandard
from src.security.bug_bounty_manager import BugBountyManager, BountyStatus
from src.crypto.key_management import KeyManager


class TestSecurityAuditor:
    """Test security auditing functionality"""

    @pytest.fixture
    async def security_auditor(self):
        """Create security auditor for testing"""
        auditor = SecurityAuditor()
        await auditor.start()
        yield auditor
        await auditor.stop()

    def test_audit_initialization(self, security_auditor):
        """Test security audit initialization"""
        assert security_auditor is not None
        assert hasattr(security_auditor, 'audit_rules')
        assert hasattr(security_auditor, 'findings')

    def test_code_audit(self, security_auditor):
        """Test code security auditing"""
        # Mock code snippet
        code_snippet = """
        def insecure_function(password):
            # This is insecure - storing password in plain text
            with open('passwords.txt', 'w') as f:
                f.write(password)
        """

        findings = security_auditor.audit_code(code_snippet)

        assert len(findings) > 0
        assert any("password" in finding['description'].lower() for finding in findings)

    def test_configuration_audit(self, security_auditor):
        """Test configuration security auditing"""
        config = {
            'debug_mode': True,
            'ssl_enabled': False,
            'password_min_length': 4,
            'session_timeout': 3600
        }

        findings = security_auditor.audit_configuration(config)

        assert len(findings) > 0
        # Should flag debug mode enabled and SSL disabled

    def test_dependency_audit(self, security_auditor):
        """Test dependency vulnerability auditing"""
        dependencies = [
            {'name': 'insecure-lib', 'version': '1.0.0', 'vulnerabilities': ['CVE-2023-12345']},
            {'name': 'safe-lib', 'version': '2.1.0', 'vulnerabilities': []}
        ]

        findings = security_auditor.audit_dependencies(dependencies)

        assert len(findings) == 1
        assert 'CVE-2023-12345' in findings[0]['description']

    def test_audit_report_generation(self, security_auditor):
        """Test audit report generation"""
        # Add some mock findings
        security_auditor.findings = [
            {'severity': AuditSeverity.HIGH, 'description': 'Critical vulnerability'},
            {'severity': AuditSeverity.MEDIUM, 'description': 'Medium risk issue'}
        ]

        report = security_auditor.generate_audit_report()

        assert 'timestamp' in report
        assert 'findings' in report
        assert 'severity_summary' in report
        assert 'recommendations' in report
        assert len(report['findings']) == 2

    def test_audit_severity_levels(self):
        """Test audit severity level definitions"""
        assert AuditSeverity.CRITICAL.value == "critical"
        assert AuditSeverity.HIGH.value == "high"
        assert AuditSeverity.MEDIUM.value == "medium"
        assert AuditSeverity.LOW.value == "low"
        assert AuditSeverity.INFO.value == "info"


class TestVulnerabilityScanner:
    """Test vulnerability scanning functionality"""

    @pytest.fixture
    async def vuln_scanner(self):
        """Create vulnerability scanner for testing"""
        scanner = VulnerabilityScanner()
        await scanner.start()
        yield scanner
        await scanner.stop()

    @pytest.mark.asyncio
    async def test_network_vulnerability_scan(self, vuln_scanner):
        """Test network vulnerability scanning"""
        target = "127.0.0.1"
        ports = [80, 443, 8080]

        vulnerabilities = await vuln_scanner.scan_network(target, ports)

        # Should return results (may be empty in test environment)
        assert isinstance(vulnerabilities, list)

    def test_code_vulnerability_scan(self, vuln_scanner):
        """Test code vulnerability scanning"""
        code = """
        import os
        def dangerous_function():
            os.system('rm -rf /')  # Command injection vulnerability
            eval(user_input)       # Code injection vulnerability
        """

        vulnerabilities = vuln_scanner.scan_code(code)

        assert len(vulnerabilities) >= 2  # Should find command and code injection
        assert any('command injection' in v['description'].lower() for v in vulnerabilities)
        assert any('code injection' in v['description'].lower() for v in vulnerabilities)

    def test_dependency_vulnerability_scan(self, vuln_scanner):
        """Test dependency vulnerability scanning"""
        dependencies = {
            'requests': '2.25.0',  # Known vulnerable version
            'cryptography': '3.4.0'  # Should be safe
        }

        vulnerabilities = vuln_scanner.scan_dependencies(dependencies)

        # May find vulnerabilities depending on database
        assert isinstance(vulnerabilities, list)

    def test_vulnerability_types(self):
        """Test vulnerability type definitions"""
        assert VulnerabilityType.BUFFER_OVERFLOW.value == "buffer_overflow"
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
        assert VulnerabilityType.XSS.value == "xss"
        assert VulnerabilityType.CSRF.value == "csrf"

    def test_scan_report_generation(self, vuln_scanner):
        """Test vulnerability scan report generation"""
        # Mock some vulnerabilities
        vuln_scanner.vulnerabilities = [
            {'type': VulnerabilityType.SQL_INJECTION, 'severity': 'high', 'description': 'SQL injection found'},
            {'type': VulnerabilityType.XSS, 'severity': 'medium', 'description': 'XSS vulnerability'}
        ]

        report = vuln_scanner.generate_scan_report()

        assert 'scan_timestamp' in report
        assert 'vulnerabilities_found' in report
        assert 'severity_breakdown' in report
        assert 'risk_assessment' in report


class TestProtocolFuzzer:
    """Test protocol fuzzing functionality"""

    @pytest.fixture
    async def protocol_fuzzer(self):
        """Create protocol fuzzer for testing"""
        fuzzer = ProtocolFuzzer()
        await fuzzer.start()
        yield fuzzer
        await fuzzer.stop()

    @pytest.mark.asyncio
    async def test_fuzzing_campaign(self, protocol_fuzzer):
        """Test fuzzing campaign execution"""
        target_protocol = "test_protocol"
        test_cases = 100

        results = await protocol_fuzzer.run_fuzzing_campaign(target_protocol, test_cases)

        assert 'campaign_id' in results
        assert 'test_cases_run' in results
        assert 'crashes_found' in results
        assert 'exceptions_found' in results

    def test_fuzzing_strategies(self, protocol_fuzzer):
        """Test different fuzzing strategies"""
        strategies = [
            FuzzingStrategy.RANDOM,
            FuzzingStrategy.MUTATION,
            FuzzingStrategy.GENERATION
        ]

        for strategy in strategies:
            test_data = protocol_fuzzer.generate_fuzz_data(strategy, 100)
            assert len(test_data) == 100
            assert all(isinstance(d, bytes) for d in test_data)

    def test_crash_detection(self, protocol_fuzzer):
        """Test crash detection in fuzzed inputs"""
        # Mock a crash scenario
        def mock_handler(data):
            if b'CRASH' in data:
                raise Exception("Simulated crash")
            return b"OK"

        protocol_fuzzer.protocol_handler = mock_handler

        # Test crash detection
        crash_data = b"CRASH_TEST"
        is_crash = protocol_fuzzer.test_for_crash(crash_data)

        assert is_crash is True

        # Test normal operation
        normal_data = b"NORMAL_TEST"
        is_crash = protocol_fuzzer.test_for_crash(normal_data)

        assert is_crash is False

    def test_fuzzing_coverage(self, protocol_fuzzer):
        """Test fuzzing coverage metrics"""
        # Run some fuzzing tests
        protocol_fuzzer.fuzzing_stats = {
            'paths_explored': 150,
            'total_paths': 200,
            'edge_coverage': 0.75
        }

        coverage = protocol_fuzzer.get_fuzzing_coverage()

        assert coverage['paths_explored'] == 150
        assert coverage['edge_coverage'] == 0.75

    def test_fuzzing_report(self, protocol_fuzzer):
        """Test fuzzing report generation"""
        # Mock fuzzing results
        protocol_fuzzer.crashes = [
            {'input': b'crash_input', 'exception': 'Buffer overflow'},
            {'input': b'another_crash', 'exception': 'Null pointer'}
        ]

        report = protocol_fuzzer.generate_fuzzing_report()

        assert 'fuzzing_session' in report
        assert 'crashes_discovered' in report
        assert 'coverage_achieved' in report
        assert 'recommendations' in report
        assert len(report['crashes_discovered']) == 2


class TestComplianceManager:
    """Test compliance management functionality"""

    @pytest.fixture
    async def compliance_manager(self):
        """Create compliance manager for testing"""
        manager = ComplianceManager()
        await manager.start()
        yield manager
        await manager.stop()

    def test_compliance_standards(self):
        """Test compliance standard definitions"""
        assert ComplianceStandard.GDPR.value == "gdpr"
        assert ComplianceStandard.HIPAA.value == "hipaa"
        assert ComplianceStandard.PCI_DSS.value == "pci_dss"
        assert ComplianceStandard.SOC2.value == "soc2"

    def test_compliance_check(self, compliance_manager):
        """Test compliance checking"""
        system_config = {
            'encryption_enabled': True,
            'audit_logging': True,
            'data_retention_days': 2555,  # GDPR compliant
            'anonymization': True
        }

        gdpr_compliance = compliance_manager.check_compliance(system_config, ComplianceStandard.GDPR)

        assert 'compliant' in gdpr_compliance
        assert 'violations' in gdpr_compliance
        assert 'recommendations' in gdpr_compliance

    def test_data_handling_compliance(self, compliance_manager):
        """Test data handling compliance"""
        data_operations = [
            {'type': 'collection', 'purpose': 'legitimate interest', 'consent': True},
            {'type': 'processing', 'purpose': 'contract fulfillment', 'consent': False},
            {'type': 'storage', 'retention_days': 2555, 'encrypted': True}
        ]

        compliance_result = compliance_manager.audit_data_handling(data_operations)

        assert 'compliant_operations' in compliance_result
        assert 'violations' in compliance_result

    def test_privacy_policy_audit(self, compliance_manager):
        """Test privacy policy auditing"""
        privacy_policy = """
        We collect personal data for providing services.
        Data is stored securely and deleted after 2 years.
        Users have right to access and delete their data.
        """

        audit_result = compliance_manager.audit_privacy_policy(privacy_policy)

        assert 'compliance_score' in audit_result
        assert 'missing_elements' in audit_result
        assert 'recommendations' in audit_result

    def test_compliance_reporting(self, compliance_manager):
        """Test compliance report generation"""
        # Mock compliance data
        compliance_manager.compliance_status = {
            ComplianceStandard.GDPR: {'compliant': True, 'score': 0.95},
            ComplianceStandard.HIPAA: {'compliant': False, 'score': 0.78}
        }

        report = compliance_manager.generate_compliance_report()

        assert 'overall_compliance' in report
        assert 'standard_status' in report
        assert 'risk_assessment' in report
        assert 'action_items' in report


class TestBugBountyManager:
    """Test bug bounty management functionality"""

    @pytest.fixture
    async def bounty_manager(self):
        """Create bug bounty manager for testing"""
        manager = BugBountyManager()
        await manager.start()
        yield manager
        await manager.stop()

    def test_bounty_submission(self, bounty_manager):
        """Test bug bounty submission"""
        submission = {
            'researcher_id': 'researcher123',
            'vulnerability_type': 'SQL injection',
            'severity': 'high',
            'description': 'Found SQL injection in login form',
            'proof_of_concept': 'SELECT * FROM users;',
            'impact': 'Data breach possible'
        }

        submission_id = bounty_manager.submit_bounty(submission)

        assert submission_id is not None
        assert submission_id in bounty_manager.submissions

    def test_bounty_validation(self, bounty_manager):
        """Test bounty submission validation"""
        # Valid submission
        valid_submission = {
            'researcher_id': 'researcher123',
            'vulnerability_type': 'XSS',
            'severity': 'medium',
            'description': 'XSS in chat input',
            'proof_of_concept': '<script>alert(1)</script>',
            'impact': 'Session hijacking'
        }

        assert bounty_manager.validate_bounty_submission(valid_submission)

        # Invalid submission - missing required fields
        invalid_submission = {
            'researcher_id': 'researcher123',
            'description': 'Missing other fields'
        }

        assert not bounty_manager.validate_bounty_submission(invalid_submission)

    def test_bounty_triaging(self, bounty_manager):
        """Test bounty triaging process"""
        submission_id = 'bounty_123'

        # Submit bounty
        bounty_manager.submit_bounty({
            'researcher_id': 'researcher123',
            'vulnerability_type': 'RCE',
            'severity': 'critical',
            'description': 'Remote code execution',
            'proof_of_concept': 'exploit code',
            'impact': 'Full system compromise'
        })

        # Triage bounty
        triage_result = bounty_manager.triage_bounty(submission_id)

        assert 'severity_assessment' in triage_result
        assert 'priority' in triage_result
        assert 'estimated_reward' in triage_result

    def test_bounty_status_tracking(self):
        """Test bounty status tracking"""
        assert BountyStatus.SUBMITTED.value == "submitted"
        assert BountyStatus.TRIAGED.value == "triaged"
        assert BountyStatus.VERIFIED.value == "verified"
        assert BountyStatus.REWARDED.value == "rewarded"
        assert BountyStatus.REJECTED.value == "rejected"

    def test_bounty_statistics(self, bounty_manager):
        """Test bounty program statistics"""
        # Add some mock bounties
        bounty_manager.submissions = {
            'bounty1': {'status': BountyStatus.VERIFIED, 'severity': 'high', 'reward': 5000},
            'bounty2': {'status': BountyStatus.REJECTED, 'severity': 'low', 'reward': 0},
            'bounty3': {'status': BountyStatus.SUBMITTED, 'severity': 'medium', 'reward': 0}
        }

        stats = bounty_manager.get_bounty_statistics()

        assert 'total_submissions' in stats
        assert 'verified_bounties' in stats
        assert 'total_rewards_paid' in stats
        assert 'average_resolution_time' in stats
        assert stats['verified_bounties'] == 1
        assert stats['total_rewards_paid'] == 5000


# Integration tests
class TestSecurityIntegration:
    """Integration tests for security components"""

    @pytest.mark.asyncio
    async def test_comprehensive_security_audit(self):
        """Test comprehensive security audit"""
        auditor = SecurityAuditor()
        await auditor.start()

        scanner = VulnerabilityScanner()
        await scanner.start()

        try:
            # Run comprehensive audit
            audit_results = await auditor.run_comprehensive_audit()

            assert 'code_audit' in audit_results
            assert 'config_audit' in audit_results
            assert 'dependency_audit' in audit_results
            assert 'network_scan' in audit_results

            # Generate combined report
            combined_report = auditor.generate_combined_security_report([
                audit_results,
                scanner.generate_scan_report()
            ])

            assert 'overall_security_score' in combined_report
            assert 'critical_findings' in combined_report
            assert 'action_plan' in combined_report

        finally:
            await auditor.stop()
            await scanner.stop()

    @pytest.mark.asyncio
    async def test_security_hardening_pipeline(self):
        """Test security hardening pipeline"""
        auditor = SecurityAuditor()
        await auditor.start()

        fuzzer = ProtocolFuzzer()
        await fuzzer.start()

        try:
            # Run security hardening steps
            hardening_results = []

            # 1. Initial audit
            initial_audit = await auditor.run_comprehensive_audit()
            hardening_results.append(('initial_audit', initial_audit))

            # 2. Fuzzing
            fuzz_results = await fuzzer.run_fuzzing_campaign('main_protocol', 50)
            hardening_results.append(('fuzzing', fuzz_results))

            # 3. Generate hardening report
            hardening_report = auditor.generate_hardening_report(hardening_results)

            assert 'hardening_steps' in hardening_report
            assert 'improvements_made' in hardening_report
            assert 'remaining_risks' in hardening_report

        finally:
            await auditor.stop()
            await fuzzer.stop()

    def test_compliance_monitoring(self):
        """Test ongoing compliance monitoring"""
        compliance_mgr = ComplianceManager()

        # Setup monitoring
        compliance_mgr.setup_continuous_monitoring()

        # Simulate system changes
        system_state = {
            'encryption_enabled': True,
            'audit_enabled': True,
            'data_retention_compliant': True
        }

        # Check compliance
        monitoring_results = compliance_mgr.monitor_compliance(system_state)

        assert 'current_compliance' in monitoring_results
        assert 'drift_detected' in monitoring_results
        assert 'alerts' in monitoring_results


if __name__ == "__main__":
    pytest.main([__file__, "-v"])