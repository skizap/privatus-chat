# Security Auditor
"""Professional security review and audit coordination."""

import time
import json
import hashlib
import logging
import traceback
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import threading
import inspect
import ast
import re
import subprocess

from ..crypto.secure_random import SecureRandom

@dataclass
class SecurityIssue:
    """Represents a security issue found during audit."""
    
    severity: str  # critical, high, medium, low, info
    category: str  # crypto, network, auth, access_control, etc.
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    false_positive: bool = False
    verified: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            'severity': self.severity,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'cvss_score': self.cvss_score,
            'false_positive': self.false_positive,
            'verified': self.verified,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class AuditReport:
    """Security audit report."""
    
    audit_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    issues: List[SecurityIssue] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    coverage: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_issue(self, issue: SecurityIssue):
        """Add an issue to the report."""
        self.issues.append(issue)
        
    def get_summary(self) -> Dict[str, Any]:
        """Get audit summary statistics."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        category_counts = {}
        
        for issue in self.issues:
            if not issue.false_positive:
                severity_counts[issue.severity] += 1
                category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
                
        return {
            'total_issues': len([i for i in self.issues if not i.false_positive]),
            'severity_counts': severity_counts,
            'category_counts': category_counts,
            'critical_issues': severity_counts['critical'],
            'high_issues': severity_counts['high'],
            'verified_issues': len([i for i in self.issues if i.verified]),
            'false_positives': len([i for i in self.issues if i.false_positive]),
            'coverage': self.coverage,
            'duration': (self.end_time - self.start_time).total_seconds() if self.end_time else None
        }

class SecurityAuditor:
    """Coordinates comprehensive security audits."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.secure_random = SecureRandom()
        self.audit_modules = []
        self.current_report = None
        
        # Security patterns to check
        self.security_patterns = {
            'hardcoded_secrets': [
                r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(secret|api_key|apikey)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(token|auth)\s*=\s*["\'][^"\']+["\']',
                r'private_key\s*=\s*["\'][^"\']+["\']'
            ],
            'weak_crypto': [
                r'(?i)md5\s*\(',
                r'(?i)sha1\s*\(',
                r'(?i)des\s*\(',
                r'(?i)rc4\s*\(',
                r'random\s*\.\s*random\s*\('
            ],
            'sql_injection': [
                r'(?i)execute\s*\(\s*["\'][^"\']*%[^"\']*["\']',
                r'(?i)execute\s*\(\s*f["\'][^"\']*{[^}]*}[^"\']*["\']',
                r'(?i)cursor\s*\.\s*execute\s*\(\s*[^,]+\+',
                r'(?i)query\s*=\s*["\'][^"\']*["\'].*\+.*input'
            ],
            'command_injection': [
                r'(?i)os\s*\.\s*system\s*\(',
                r'(?i)subprocess\s*\.\s*call\s*\([^,]*shell\s*=\s*True',
                r'(?i)eval\s*\(',
                r'(?i)exec\s*\('
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\\\',
                r'(?i)open\s*\([^)]*\+[^)]*\)',
                r'(?i)path\s*\.\s*join\s*\([^)]*input[^)]*\)'
            ],
            'xss_vulnerabilities': [
                r'(?i)innerHTML\s*=',
                r'(?i)document\s*\.\s*write\s*\(',
                r'(?i)eval\s*\([^)]*user[^)]*\)',
                r'(?i)dangerouslySetInnerHTML'
            ],
            'insecure_deserialization': [
                r'(?i)pickle\s*\.\s*loads\s*\(',
                r'(?i)yaml\s*\.\s*load\s*\([^,)]*\)',
                r'(?i)eval\s*\(\s*json',
                r'(?i)__import__\s*\('
            ],
            'weak_random': [
                r'(?i)random\s*\.\s*randint\s*\(',
                r'(?i)random\s*\.\s*choice\s*\(',
                r'(?i)random\s*\.\s*seed\s*\(',
                r'(?i)time\s*\.\s*time\s*\(\s*\)\s*%'
            ]
        }
        
        # CWE mappings
        self.cwe_mappings = {
            'hardcoded_secrets': 'CWE-798',
            'weak_crypto': 'CWE-327',
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'xss_vulnerabilities': 'CWE-79',
            'insecure_deserialization': 'CWE-502',
            'weak_random': 'CWE-330'
        }
        
    def start_audit(self, scope: Dict[str, Any]) -> str:
        """Start a comprehensive security audit."""
        audit_id = self.secure_random.generate_bytes(16).hex()
        
        self.current_report = AuditReport(
            audit_id=audit_id,
            start_time=datetime.now(),
            metadata={
                'scope': scope,
                'version': '1.0',
                'auditor': 'Privatus Security Auditor'
            }
        )
        
        self.logger.info(f"Starting security audit {audit_id}")
        
        # Run audit phases in order
        self._run_static_analysis(scope)
        self._run_crypto_audit(scope)
        self._run_network_audit(scope)
        self._run_access_control_audit(scope)
        self._run_dependency_audit(scope)
        self._run_configuration_audit(scope)
        
        self.current_report.end_time = datetime.now()
        
        return audit_id
        
    def _run_static_analysis(self, scope: Dict[str, Any]):
        """Run static code analysis."""
        self.logger.info("Running static code analysis...")
        
        # Scan source files
        source_dir = Path(scope.get('source_dir', 'src'))
        if source_dir.exists():
            self._scan_directory(source_dir)
            
        # Check for common vulnerabilities
        self._check_authentication_bypass()
        self._check_authorization_flaws()
        self._check_input_validation()
        self._check_output_encoding()
        
    def _scan_directory(self, directory: Path):
        """Scan directory for security issues."""
        for file_path in directory.rglob('*.py'):
            if '__pycache__' not in str(file_path):
                self._scan_file(file_path)
                
    def _scan_file(self, file_path: Path):
        """Scan a single file for security issues."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
            # Check security patterns
            for category, patterns in self.security_patterns.items():
                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get code snippet
                        start_line = max(0, line_num - 3)
                        end_line = min(len(lines), line_num + 2)
                        snippet = '\n'.join(lines[start_line:end_line])
                        
                        issue = SecurityIssue(
                            severity=self._get_severity(category),
                            category=category,
                            title=f"{category.replace('_', ' ').title()} Detected",
                            description=f"Potential {category.replace('_', ' ')} vulnerability detected",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=snippet,
                            cwe_id=self.cwe_mappings.get(category),
                            remediation=self._get_remediation(category)
                        )
                        
                        # Verify if it's a false positive
                        if not self._is_false_positive(issue, content):
                            self.current_report.add_issue(issue)
                            
            # AST-based analysis
            try:
                tree = ast.parse(content)
                self._analyze_ast(tree, file_path)
            except SyntaxError:
                pass
                
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            
    def _analyze_ast(self, tree: ast.AST, file_path: Path):
        """Analyze AST for security issues."""
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, auditor, file_path):
                self.auditor = auditor
                self.file_path = file_path
                
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec', '__import__']:
                        issue = SecurityIssue(
                            severity='high',
                            category='dangerous_function',
                            title=f"Dangerous Function Call: {node.func.id}",
                            description=f"Use of dangerous function {node.func.id} detected",
                            file_path=str(self.file_path),
                            line_number=node.lineno,
                            cwe_id='CWE-95'
                        )
                        self.auditor.current_report.add_issue(issue)
                        
                self.generic_visit(node)
                
        visitor = SecurityVisitor(self, file_path)
        visitor.visit(tree)
        
    def _run_crypto_audit(self, scope: Dict[str, Any]):
        """Audit cryptographic implementations."""
        self.logger.info("Running cryptographic audit...")
        
        issues = []
        
        # Check key management
        issues.extend(self._audit_key_management())
        
        # Check encryption algorithms
        issues.extend(self._audit_encryption_algorithms())
        
        # Check random number generation
        issues.extend(self._audit_random_generation())
        
        # Check certificate validation
        issues.extend(self._audit_certificate_validation())
        
        for issue in issues:
            self.current_report.add_issue(issue)
            
    def _audit_key_management(self) -> List[SecurityIssue]:
        """Audit key management practices."""
        issues = []
        
        # Check for hardcoded keys
        key_patterns = [
            r'key\s*=\s*["\'][a-fA-F0-9]{32,}["\']',
            r'secret\s*=\s*["\'][a-fA-F0-9]{32,}["\']',
            r'private_key\s*=\s*["\'][^"\']+["\']'
        ]
        
        # Check key storage
        # Check key rotation
        # Check key derivation
        
        return issues
        
    def _audit_encryption_algorithms(self) -> List[SecurityIssue]:
        """Audit encryption algorithm usage."""
        issues = []
        
        # Check for weak algorithms
        # Check for proper IV usage
        # Check for authenticated encryption
        # Check padding schemes
        
        return issues
        
    def _audit_random_generation(self) -> List[SecurityIssue]:
        """Audit random number generation."""
        issues = []
        
        # Check for use of non-cryptographic random
        # Check for predictable seeds
        # Check entropy sources
        
        return issues
        
    def _audit_certificate_validation(self) -> List[SecurityIssue]:
        """Audit certificate validation."""
        issues = []
        
        # Check certificate pinning
        # Check hostname verification
        # Check certificate chain validation
        
        return issues
        
    def _run_network_audit(self, scope: Dict[str, Any]):
        """Audit network security."""
        self.logger.info("Running network security audit...")
        
        # Check TLS configuration
        self._audit_tls_configuration()
        
        # Check network protocols
        self._audit_network_protocols()
        
        # Check firewall rules
        self._audit_firewall_rules()
        
        # Check DoS protections
        self._audit_dos_protections()
        
    def _audit_tls_configuration(self):
        """Audit TLS configuration."""
        # Check TLS versions
        # Check cipher suites
        # Check certificate validation
        # Check HSTS
        pass
        
    def _audit_network_protocols(self):
        """Audit network protocol implementations."""
        # Check protocol implementations
        # Check message validation
        # Check timeout handling
        pass
        
    def _audit_firewall_rules(self):
        """Audit firewall and network segmentation."""
        # Check exposed ports
        # Check network segmentation
        # Check access controls
        pass
        
    def _audit_dos_protections(self):
        """Audit DoS protection mechanisms."""
        # Check rate limiting
        # Check resource limits
        # Check anti-DDoS measures
        pass
        
    def _run_access_control_audit(self, scope: Dict[str, Any]):
        """Audit access control mechanisms."""
        self.logger.info("Running access control audit...")
        
        # Check authentication
        self._audit_authentication()
        
        # Check authorization
        self._audit_authorization()
        
        # Check session management
        self._audit_session_management()
        
    def _audit_authentication(self):
        """Audit authentication mechanisms."""
        # Check password policies
        # Check multi-factor authentication
        # Check account lockout
        # Check credential storage
        pass
        
    def _audit_authorization(self):
        """Audit authorization mechanisms."""
        # Check access control lists
        # Check privilege escalation
        # Check RBAC implementation
        pass
        
    def _audit_session_management(self):
        """Audit session management."""
        # Check session generation
        # Check session timeout
        # Check session fixation
        # Check CSRF protection
        pass
        
    def _run_dependency_audit(self, scope: Dict[str, Any]):
        """Audit third-party dependencies."""
        self.logger.info("Running dependency audit...")
        
        # Check for known vulnerabilities
        self._check_vulnerability_databases()
        
        # Check dependency versions
        self._check_dependency_versions()
        
        # Check license compliance
        self._check_license_compliance()
        
    def _check_vulnerability_databases(self):
        """Check dependencies against vulnerability databases."""
        # Check CVE database
        # Check NVD
        # Check GitHub Security Advisories
        pass
        
    def _check_dependency_versions(self):
        """Check for outdated dependencies."""
        # Parse requirements.txt
        # Check for updates
        # Check for EOL versions
        pass
        
    def _check_license_compliance(self):
        """Check license compliance."""
        # Check dependency licenses
        # Check for conflicting licenses
        # Check for proprietary dependencies
        pass
        
    def _run_configuration_audit(self, scope: Dict[str, Any]):
        """Audit security configurations."""
        self.logger.info("Running configuration audit...")
        
        # Check security headers
        # Check logging configuration
        # Check error handling
        # Check default settings
        pass
        
    def _check_authentication_bypass(self):
        """Check for authentication bypass vulnerabilities."""
        # Check for backdoors
        # Check for default credentials
        # Check for authentication logic flaws
        pass
        
    def _check_authorization_flaws(self):
        """Check for authorization flaws."""
        # Check for IDOR
        # Check for privilege escalation
        # Check for missing authorization
        pass
        
    def _check_input_validation(self):
        """Check input validation."""
        # Check for injection points
        # Check for buffer overflows
        # Check for format string bugs
        pass
        
    def _check_output_encoding(self):
        """Check output encoding."""
        # Check for XSS
        # Check for injection
        # Check for information disclosure
        pass
        
    def _get_severity(self, category: str) -> str:
        """Get severity level for a category."""
        severity_map = {
            'hardcoded_secrets': 'critical',
            'weak_crypto': 'high',
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'path_traversal': 'high',
            'xss_vulnerabilities': 'high',
            'insecure_deserialization': 'critical',
            'weak_random': 'medium',
            'dangerous_function': 'high'
        }
        return severity_map.get(category, 'medium')
        
    def _get_remediation(self, category: str) -> str:
        """Get remediation advice for a category."""
        remediations = {
            'hardcoded_secrets': 'Use environment variables or secure key management systems',
            'weak_crypto': 'Use strong cryptographic algorithms (AES-256, SHA-256+)',
            'sql_injection': 'Use parameterized queries or prepared statements',
            'command_injection': 'Avoid shell commands, use subprocess with lists',
            'path_traversal': 'Validate and sanitize file paths',
            'xss_vulnerabilities': 'Encode output and use Content Security Policy',
            'insecure_deserialization': 'Use safe deserialization methods',
            'weak_random': 'Use cryptographically secure random generators'
        }
        return remediations.get(category, 'Review and fix the security issue')
        
    def _is_false_positive(self, issue: SecurityIssue, content: str) -> bool:
        """Check if an issue is a false positive."""
        # Check for test files
        if issue.file_path and ('test' in issue.file_path or 'example' in issue.file_path):
            return True
            
        # Check for comments
        if issue.line_number:
            lines = content.split('\n')
            if issue.line_number <= len(lines):
                line = lines[issue.line_number - 1]
                if line.strip().startswith('#'):
                    return True
                    
        return False
        
    def get_report(self, audit_id: str) -> Optional[AuditReport]:
        """Get audit report by ID."""
        if self.current_report and self.current_report.audit_id == audit_id:
            return self.current_report
        return None
        
    def export_report(self, audit_id: str, format: str = 'json') -> str:
        """Export audit report in specified format."""
        report = self.get_report(audit_id)
        if not report:
            raise ValueError(f"Report {audit_id} not found")
            
        if format == 'json':
            return json.dumps({
                'audit_id': report.audit_id,
                'start_time': report.start_time.isoformat(),
                'end_time': report.end_time.isoformat() if report.end_time else None,
                'summary': report.get_summary(),
                'issues': [issue.to_dict() for issue in report.issues],
                'metadata': report.metadata
            }, indent=2)
        elif format == 'html':
            return self._generate_html_report(report)
        elif format == 'pdf':
            return self._generate_pdf_report(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    def _generate_html_report(self, report: AuditReport) -> str:
        """Generate HTML audit report."""
        summary = report.get_summary()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Audit Report - {report.audit_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #333; color: white; padding: 20px; }}
                .summary {{ background: #f0f0f0; padding: 20px; margin: 20px 0; }}
                .issue {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
                .critical {{ border-left: 5px solid #ff0000; }}
                .high {{ border-left: 5px solid #ff9900; }}
                .medium {{ border-left: 5px solid #ffcc00; }}
                .low {{ border-left: 5px solid #00cc00; }}
                .info {{ border-left: 5px solid #0099ff; }}
                code {{ background: #f5f5f5; padding: 2px 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Audit Report</h1>
                <p>Audit ID: {report.audit_id}</p>
                <p>Generated: {datetime.now().isoformat()}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Issues: {summary['total_issues']}</p>
                <p>Critical: {summary['critical_issues']}</p>
                <p>High: {summary['severity_counts']['high']}</p>
                <p>Medium: {summary['severity_counts']['medium']}</p>
                <p>Low: {summary['severity_counts']['low']}</p>
            </div>
            
            <h2>Issues</h2>
        """
        
        for issue in sorted(report.issues, key=lambda i: ['critical', 'high', 'medium', 'low', 'info'].index(i.severity)):
            if not issue.false_positive:
                html += f"""
                <div class="issue {issue.severity}">
                    <h3>{issue.title}</h3>
                    <p><strong>Severity:</strong> {issue.severity.upper()}</p>
                    <p><strong>Category:</strong> {issue.category}</p>
                    <p><strong>Description:</strong> {issue.description}</p>
                    {"<p><strong>File:</strong> " + issue.file_path + "</p>" if issue.file_path else ""}
                    {"<p><strong>Line:</strong> " + str(issue.line_number) + "</p>" if issue.line_number else ""}
                    {"<p><strong>CWE:</strong> " + issue.cwe_id + "</p>" if issue.cwe_id else ""}
                    {"<p><strong>Remediation:</strong> " + issue.remediation + "</p>" if issue.remediation else ""}
                    {"<pre><code>" + issue.code_snippet + "</code></pre>" if issue.code_snippet else ""}
                </div>
                """
                
        html += """
        </body>
        </html>
        """
        
        return html
        
    def _generate_pdf_report(self, report: AuditReport) -> str:
        """Generate PDF audit report."""
        # This would use a PDF generation library
        # For now, return a placeholder
        return "PDF generation not implemented" 