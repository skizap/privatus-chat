#!/usr/bin/env python3
"""
Phase 9: Security Auditing & Compliance Demo
Demonstrates professional security review, automated testing, and compliance management.
"""

import sys
import asyncio
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security.security_auditor import SecurityAuditor, SecurityIssue
from src.security.vulnerability_scanner import VulnerabilityScanner
from src.security.protocol_fuzzer import ProtocolFuzzer
from src.security.compliance_manager import ComplianceManager
from src.security.bug_bounty_manager import BugBountyManager, VulnerabilitySeverity

async def main():
    print("=" * 80)
    print("PRIVATUS-CHAT PHASE 9: SECURITY AUDITING & COMPLIANCE DEMO")
    print("=" * 80)
    
    # 1. Security Auditor Demo
    print("\n1. SECURITY AUDITOR")
    print("-" * 40)
    
    auditor = SecurityAuditor()
    
    # Start comprehensive audit
    audit_scope = {
        'source_dir': 'src',
        'include_patterns': ['*.py'],
        'exclude_patterns': ['test_*', '*_test.py']
    }
    
    print("Starting comprehensive security audit...")
    audit_id = auditor.start_audit(audit_scope)
    print(f"Audit ID: {audit_id}")
    
    # Get audit report
    report = auditor.get_report(audit_id)
    if report:
        summary = report.get_summary()
        print(f"\nAudit Summary:")
        print(f"  Total Issues: {summary['total_issues']}")
        print(f"  Critical: {summary['critical_issues']}")
        print(f"  High: {summary['severity_counts']['high']}")
        print(f"  Medium: {summary['severity_counts']['medium']}")
        print(f"  Low: {summary['severity_counts']['low']}")
        
        # Show top issues
        if report.issues:
            print("\nTop Security Issues Found:")
            for issue in report.issues[:5]:
                if not issue.false_positive:
                    print(f"  - [{issue.severity.upper()}] {issue.title}")
                    print(f"    File: {issue.file_path}")
                    print(f"    CWE: {issue.cwe_id}")
    
    # Export report
    print("\nExporting audit report...")
    json_report = auditor.export_report(audit_id, format='json')
    print(f"Report size: {len(json_report)} bytes")
    
    # 2. Vulnerability Scanner Demo
    print("\n\n2. VULNERABILITY SCANNER")
    print("-" * 40)
    
    scanner = VulnerabilityScanner()
    
    # Scan codebase
    print("Scanning codebase for vulnerabilities...")
    code_vulns = await scanner.scan_codebase('src')
    print(f"Found {len(code_vulns)} potential vulnerabilities")
    
    # Show vulnerability distribution
    if code_vulns:
        severity_dist = {}
        for vuln in code_vulns:
            sev = vuln.get('severity', 'unknown')
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
        
        print("\nVulnerability Distribution:")
        for sev, count in severity_dist.items():
            print(f"  {sev}: {count}")
    
    # Scan dependencies
    print("\nScanning dependencies...")
    dep_vulns = scanner.scan_dependencies('requirements.txt')
    if dep_vulns:
        print(f"Found {len(dep_vulns)} vulnerable dependencies")
        for vuln in dep_vulns[:3]:
            print(f"  - {vuln['package']} {vuln['installed_version']}: {vuln['cve']}")
    else:
        print("No vulnerable dependencies found")
    
    # Network scan (demo mode - won't actually scan)
    print("\nNetwork vulnerability scan (demo mode)...")
    # scanner.scan_network('localhost', [80, 443, 8080])
    print("  [Demo] Would scan for open ports and service vulnerabilities")
    
    # 3. Protocol Fuzzer Demo
    print("\n\n3. PROTOCOL FUZZER")
    print("-" * 40)
    
    fuzzer = ProtocolFuzzer()
    
    print("Protocol fuzzing capabilities:")
    print("  - HTTP protocol fuzzing")
    print("  - Custom protocol fuzzing")
    print("  - Mutation strategies: bit flip, overflow, injection")
    print("  - Crash detection and reproduction")
    
    # Demo fuzz case generation
    from src.security.protocol_fuzzer import FuzzCase
    demo_case = FuzzCase(
        name="demo_overflow",
        description="Demo buffer overflow test",
        payload=b"A" * 1000,
        expected_behavior="Connection close",
        category="overflow"
    )
    
    print(f"\nExample fuzz case: {demo_case.name}")
    print(f"  Payload size: {len(demo_case.payload)} bytes")
    print(f"  Category: {demo_case.category}")
    
    # 4. Compliance Manager Demo
    print("\n\n4. COMPLIANCE MANAGER")
    print("-" * 40)
    
    compliance = ComplianceManager()
    
    # Check GDPR compliance
    print("Checking GDPR compliance...")
    gdpr_checks = compliance.check_compliance('GDPR')
    
    gdpr_summary = {
        'compliant': 0,
        'partial': 0,
        'non_compliant': 0
    }
    
    for check in gdpr_checks:
        gdpr_summary[check.status] += 1
    
    print(f"\nGDPR Compliance Status:")
    print(f"  Compliant: {gdpr_summary['compliant']}")
    print(f"  Partial: {gdpr_summary['partial']}")
    print(f"  Non-Compliant: {gdpr_summary['non_compliant']}")
    
    # Show specific requirements
    print("\nKey GDPR Requirements:")
    for check in gdpr_checks[:3]:
        print(f"  - {check.requirement.title}: {check.status.upper()}")
    
    # Check FIPS compliance
    print("\n\nChecking FIPS 140-2 compliance...")
    fips_checks = compliance.check_compliance('FIPS-140-2')
    
    print(f"FIPS 140-2 Compliance: {len([c for c in fips_checks if c.status == 'compliant'])}/{len(fips_checks)}")
    
    # Demonstrate GDPR features
    print("\n\nGDPR Feature Demo:")
    
    # Record consent
    consent = compliance.record_consent(
        user_id="demo_user_123",
        purpose="analytics",
        granted=True,
        ip_address="192.168.1.1"
    )
    print(f"  ✓ Consent recorded: {consent.purpose}")
    
    # Export user data
    user_data = compliance.export_user_data("demo_user_123", format='json')
    print(f"  ✓ User data export: {len(user_data)} bytes")
    
    # Set retention policy
    compliance.set_retention_policy(
        data_type="chat_messages",
        retention_days=365,
        purpose="Service provision",
        legal_basis="Legitimate interest"
    )
    print("  ✓ Retention policy set: chat_messages (365 days)")
    
    # Run FIPS self-tests
    print("\n\nFIPS Self-Tests:")
    test_results = compliance.run_self_tests()
    for test, result in test_results.items():
        status = "PASS" if result else "FAIL"
        print(f"  {test}: {status}")
    
    # 5. Bug Bounty Manager Demo
    print("\n\n5. BUG BOUNTY PROGRAM")
    print("-" * 40)
    
    bounty = BugBountyManager()
    
    # Register researcher
    researcher = bounty.register_researcher("security_researcher", "researcher@example.com")
    print(f"Registered researcher: {researcher.username}")
    
    # Submit vulnerability report
    report_data = {
        'title': 'XSS in Chat Message Display',
        'description': 'Stored XSS vulnerability in message rendering',
        'severity': 'high',
        'category': 'xss',
        'affected_components': ['message_display.py'],
        'steps_to_reproduce': [
            '1. Send message with payload: <script>alert(1)</script>',
            '2. Message executes JavaScript when displayed',
            '3. All users viewing the message are affected'
        ],
        'proof_of_concept': '<script>alert(document.cookie)</script>',
        'suggested_fix': 'Implement proper HTML escaping for user messages'
    }
    
    vuln_report = bounty.submit_report(researcher.id, report_data)
    print(f"\nVulnerability report submitted: {vuln_report.id}")
    print(f"  Title: {vuln_report.title}")
    print(f"  Severity: {vuln_report.severity.value}")
    
    # Triage report
    triaged = bounty.triage_report(vuln_report.id, 'confirm', 'Valid XSS vulnerability')
    print(f"\nReport triaged: {triaged.status.value}")
    print(f"  Reward: ${triaged.reward_amount}")
    
    # Show bug bounty statistics
    stats = bounty.get_program_statistics()
    print("\n\nBug Bounty Program Statistics:")
    print(f"  Total Reports: {stats['total_reports']}")
    print(f"  Total Rewards: ${stats['total_rewards']}")
    print(f"  Active Researchers: {stats['active_researchers']}")
    
    # Show reward tiers
    print("\nReward Tiers:")
    for severity, tier in bounty.reward_tiers.items():
        print(f"  {severity.value}: ${tier.min_amount} - ${tier.max_amount}")
    
    # Create security challenge
    challenge_id = bounty.create_security_challenge({
        'title': 'Find the Hidden Vulnerability',
        'description': 'Can you find the authentication bypass?',
        'difficulty': 'medium',
        'reward': 500.0,
        'hints': ['Check the JWT implementation'],
        'flag': 'FLAG{jwt_none_algorithm_bypass}'
    })
    print(f"\nSecurity challenge created: {challenge_id}")
    
    # 6. Generate Reports
    print("\n\n6. SECURITY REPORTS")
    print("-" * 40)
    
    # Generate compliance report
    compliance_report = compliance.generate_compliance_report()
    print("Generated compliance report:")
    print(compliance_report[:500] + "...")
    
    # Generate HTML audit report
    if report:
        html_report = auditor._generate_html_report(report)
        print(f"\nGenerated HTML audit report: {len(html_report)} bytes")
    
    # Security metrics summary
    print("\n\n7. SECURITY METRICS SUMMARY")
    print("-" * 40)
    
    print("Security Posture Overview:")
    print(f"  ✓ Automated security scanning: ACTIVE")
    print(f"  ✓ Compliance monitoring: GDPR, FIPS")
    print(f"  ✓ Bug bounty program: ACTIVE")
    print(f"  ✓ Vulnerability disclosure: COORDINATED")
    print(f"  ✓ Security testing: CONTINUOUS")
    
    print("\nSecurity Capabilities:")
    print("  • Static code analysis")
    print("  • Dynamic vulnerability scanning")
    print("  • Protocol fuzzing")
    print("  • Dependency checking")
    print("  • Compliance validation")
    print("  • Security challenge system")
    print("  • Responsible disclosure")
    
    print("\n" + "=" * 80)
    print("PHASE 9 COMPLETE: Security Auditing & Compliance Implemented")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main()) 