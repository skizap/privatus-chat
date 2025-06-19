# Bug Bounty Manager
"""Bug bounty program management and vulnerability disclosure."""

import json
import uuid
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading

class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class SubmissionStatus(Enum):
    """Bug bounty submission status."""
    NEW = "new"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NOT_APPLICABLE = "not_applicable"
    RESOLVED = "resolved"
    DISCLOSED = "disclosed"

@dataclass
class Researcher:
    """Security researcher profile."""
    
    id: str
    username: str
    email: str
    reputation_score: int = 0
    reports_submitted: int = 0
    reports_accepted: int = 0
    total_rewards: float = 0.0
    badges: List[str] = field(default_factory=list)
    join_date: datetime = field(default_factory=datetime.now)
    
    def calculate_acceptance_rate(self) -> float:
        """Calculate report acceptance rate."""
        if self.reports_submitted == 0:
            return 0.0
        return self.reports_accepted / self.reports_submitted

@dataclass
class VulnerabilityReport:
    """Bug bounty vulnerability report."""
    
    id: str
    researcher_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    category: str
    affected_components: List[str]
    steps_to_reproduce: List[str]
    proof_of_concept: Optional[str] = None
    suggested_fix: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    status: SubmissionStatus = SubmissionStatus.NEW
    submitted_at: datetime = field(default_factory=datetime.now)
    triaged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    disclosed_at: Optional[datetime] = None
    reward_amount: Optional[float] = None
    internal_notes: List[str] = field(default_factory=list)
    public_disclosure: bool = False
    cve_id: Optional[str] = None
    
@dataclass
class RewardTier:
    """Reward tier for bug bounty program."""
    
    severity: VulnerabilitySeverity
    min_amount: float
    max_amount: float
    guidelines: List[str]

class BugBountyManager:
    """Manages bug bounty program and responsible disclosure."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.researchers = {}
        self.reports = {}
        self.reward_tiers = self._init_reward_tiers()
        self.program_scope = self._init_program_scope()
        self.disclosure_policy = self._init_disclosure_policy()
        self.hall_of_fame = []
        self.statistics = {
            'total_reports': 0,
            'total_rewards': 0.0,
            'average_triage_time': 0.0,
            'average_resolution_time': 0.0
        }
        
        # Challenge system
        self.security_challenges = []
        self.challenge_submissions = {}
        
        # Rate limiting
        self.submission_limits = {
            'per_hour': 10,
            'per_day': 50
        }
        self.submission_tracker = {}
        
    def _init_reward_tiers(self) -> Dict[VulnerabilitySeverity, RewardTier]:
        """Initialize reward tiers."""
        return {
            VulnerabilitySeverity.CRITICAL: RewardTier(
                severity=VulnerabilitySeverity.CRITICAL,
                min_amount=5000.0,
                max_amount=20000.0,
                guidelines=[
                    "Remote code execution",
                    "Authentication bypass",
                    "Privilege escalation to admin",
                    "Cryptographic vulnerabilities compromising user data"
                ]
            ),
            VulnerabilitySeverity.HIGH: RewardTier(
                severity=VulnerabilitySeverity.HIGH,
                min_amount=1000.0,
                max_amount=5000.0,
                guidelines=[
                    "SQL injection",
                    "Cross-site scripting (stored)",
                    "Access control bypass",
                    "Information disclosure of sensitive data"
                ]
            ),
            VulnerabilitySeverity.MEDIUM: RewardTier(
                severity=VulnerabilitySeverity.MEDIUM,
                min_amount=250.0,
                max_amount=1000.0,
                guidelines=[
                    "Cross-site scripting (reflected)",
                    "CSRF on sensitive actions",
                    "Information disclosure of non-sensitive data",
                    "Denial of service"
                ]
            ),
            VulnerabilitySeverity.LOW: RewardTier(
                severity=VulnerabilitySeverity.LOW,
                min_amount=50.0,
                max_amount=250.0,
                guidelines=[
                    "Missing security headers",
                    "Weak password requirements",
                    "Information disclosure in error messages",
                    "Minor security misconfigurations"
                ]
            ),
            VulnerabilitySeverity.INFORMATIONAL: RewardTier(
                severity=VulnerabilitySeverity.INFORMATIONAL,
                min_amount=0.0,
                max_amount=50.0,
                guidelines=[
                    "Best practice violations",
                    "Minor information leaks",
                    "Outdated dependencies without known vulnerabilities"
                ]
            )
        }
        
    def _init_program_scope(self) -> Dict[str, Any]:
        """Initialize bug bounty program scope."""
        return {
            'in_scope': {
                'applications': [
                    'Privatus Chat Desktop Application',
                    'Privatus Chat Protocol Implementation',
                    'Cryptographic Components',
                    'Network Communication Layer'
                ],
                'vulnerability_types': [
                    'Authentication and authorization flaws',
                    'Cryptographic vulnerabilities',
                    'Remote code execution',
                    'SQL/NoSQL injection',
                    'Cross-site scripting',
                    'Information disclosure',
                    'Business logic errors',
                    'Race conditions',
                    'Memory corruption'
                ]
            },
            'out_of_scope': {
                'applications': [
                    'Third-party dependencies (unless vulnerability is in our usage)',
                    'Social engineering attacks',
                    'Physical attacks',
                    'Attacks requiring physical access'
                ],
                'vulnerability_types': [
                    'Denial of service without proof of impact',
                    'Spam or social engineering',
                    'Missing best practices without security impact',
                    'Recently disclosed vulnerabilities (< 30 days)'
                ]
            },
            'testing_guidelines': [
                'Do not access or modify other users\' data',
                'Do not perform denial of service attacks',
                'Do not use automated scanning tools excessively',
                'Create test accounts for testing',
                'Report vulnerabilities promptly'
            ]
        }
        
    def _init_disclosure_policy(self) -> Dict[str, Any]:
        """Initialize responsible disclosure policy."""
        return {
            'timeline': {
                'initial_response': '24 hours',
                'triage_completion': '7 days',
                'fix_timeline': '90 days',
                'disclosure_delay': '30 days after fix'
            },
            'researcher_guidelines': [
                'Allow reasonable time for patching',
                'Coordinate disclosure timeline',
                'Provide sufficient detail for reproduction',
                'Do not disclose publicly before coordination'
            ],
            'our_commitments': [
                'Respond to all valid reports promptly',
                'Keep researchers updated on progress',
                'Credit researchers (unless anonymity requested)',
                'Not pursue legal action for good-faith research'
            ]
        }
        
    def register_researcher(self, username: str, email: str) -> Researcher:
        """Register a new security researcher."""
        researcher_id = str(uuid.uuid4())
        
        researcher = Researcher(
            id=researcher_id,
            username=username,
            email=email
        )
        
        self.researchers[researcher_id] = researcher
        self.logger.info(f"Registered new researcher: {username}")
        
        return researcher
        
    def submit_report(self, researcher_id: str, report_data: Dict[str, Any]) -> VulnerabilityReport:
        """Submit a vulnerability report."""
        # Check rate limits
        if not self._check_rate_limit(researcher_id):
            raise ValueError("Rate limit exceeded. Please wait before submitting more reports.")
            
        # Validate researcher
        if researcher_id not in self.researchers:
            raise ValueError("Invalid researcher ID")
            
        # Create report
        report_id = str(uuid.uuid4())
        
        report = VulnerabilityReport(
            id=report_id,
            researcher_id=researcher_id,
            title=report_data['title'],
            description=report_data['description'],
            severity=VulnerabilitySeverity(report_data['severity']),
            category=report_data['category'],
            affected_components=report_data['affected_components'],
            steps_to_reproduce=report_data['steps_to_reproduce'],
            proof_of_concept=report_data.get('proof_of_concept'),
            suggested_fix=report_data.get('suggested_fix'),
            attachments=report_data.get('attachments', [])
        )
        
        self.reports[report_id] = report
        
        # Update researcher stats
        researcher = self.researchers[researcher_id]
        researcher.reports_submitted += 1
        
        # Update program statistics
        self.statistics['total_reports'] += 1
        
        # Log submission
        self.logger.info(f"New vulnerability report submitted: {report_id} by {researcher.username}")
        
        # Start triage process
        self._initiate_triage(report)
        
        return report
        
    def _check_rate_limit(self, researcher_id: str) -> bool:
        """Check if researcher is within rate limits."""
        now = datetime.now()
        
        if researcher_id not in self.submission_tracker:
            self.submission_tracker[researcher_id] = []
            
        # Clean old submissions
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        self.submission_tracker[researcher_id] = [
            ts for ts in self.submission_tracker[researcher_id]
            if ts > day_ago
        ]
        
        # Count recent submissions
        hour_submissions = sum(1 for ts in self.submission_tracker[researcher_id] if ts > hour_ago)
        day_submissions = len(self.submission_tracker[researcher_id])
        
        if hour_submissions >= self.submission_limits['per_hour']:
            return False
        if day_submissions >= self.submission_limits['per_day']:
            return False
            
        # Record submission
        self.submission_tracker[researcher_id].append(now)
        
        return True
        
    def _initiate_triage(self, report: VulnerabilityReport):
        """Initiate triage process for a report."""
        report.status = SubmissionStatus.TRIAGING
        report.triaged_at = datetime.now()
        
        # In production, this would notify security team
        self.logger.info(f"Initiating triage for report {report.id}")
        
    def triage_report(self, report_id: str, decision: str, notes: str = None) -> VulnerabilityReport:
        """Triage a vulnerability report."""
        if report_id not in self.reports:
            raise ValueError("Invalid report ID")
            
        report = self.reports[report_id]
        
        # Update status based on decision
        status_map = {
            'confirm': SubmissionStatus.CONFIRMED,
            'duplicate': SubmissionStatus.DUPLICATE,
            'informative': SubmissionStatus.INFORMATIVE,
            'not_applicable': SubmissionStatus.NOT_APPLICABLE
        }
        
        if decision not in status_map:
            raise ValueError("Invalid triage decision")
            
        report.status = status_map[decision]
        
        # Add internal notes
        if notes:
            report.internal_notes.append(f"[TRIAGE] {notes}")
            
        # Update researcher stats if confirmed
        if report.status == SubmissionStatus.CONFIRMED:
            researcher = self.researchers[report.researcher_id]
            researcher.reports_accepted += 1
            
            # Calculate initial reward
            self._calculate_reward(report)
            
        self.logger.info(f"Report {report_id} triaged as {decision}")
        
        return report
        
    def _calculate_reward(self, report: VulnerabilityReport) -> float:
        """Calculate reward amount for a report."""
        tier = self.reward_tiers.get(report.severity)
        if not tier:
            return 0.0
            
        # Base reward calculation
        base_reward = (tier.min_amount + tier.max_amount) / 2
        
        # Adjustments based on quality
        quality_multiplier = 1.0
        
        # Clear reproduction steps
        if len(report.steps_to_reproduce) >= 3:
            quality_multiplier += 0.1
            
        # Proof of concept provided
        if report.proof_of_concept:
            quality_multiplier += 0.2
            
        # Suggested fix provided
        if report.suggested_fix:
            quality_multiplier += 0.1
            
        # First reporter bonus
        if not self._is_duplicate(report):
            quality_multiplier += 0.2
            
        final_reward = base_reward * quality_multiplier
        
        # Cap at maximum
        final_reward = min(final_reward, tier.max_amount)
        
        report.reward_amount = final_reward
        
        return final_reward
        
    def _is_duplicate(self, report: VulnerabilityReport) -> bool:
        """Check if report is a duplicate."""
        # Simple duplicate detection based on affected components and category
        for existing_report in self.reports.values():
            if existing_report.id == report.id:
                continue
                
            if (existing_report.category == report.category and
                set(existing_report.affected_components) & set(report.affected_components) and
                existing_report.status == SubmissionStatus.CONFIRMED):
                return True
                
        return False
        
    def resolve_report(self, report_id: str, resolution_notes: str) -> VulnerabilityReport:
        """Mark a report as resolved."""
        if report_id not in self.reports:
            raise ValueError("Invalid report ID")
            
        report = self.reports[report_id]
        
        if report.status != SubmissionStatus.CONFIRMED:
            raise ValueError("Can only resolve confirmed reports")
            
        report.status = SubmissionStatus.RESOLVED
        report.resolved_at = datetime.now()
        report.internal_notes.append(f"[RESOLVED] {resolution_notes}")
        
        # Process reward
        if report.reward_amount:
            self._process_reward(report)
            
        # Update statistics
        if report.triaged_at:
            resolution_time = (report.resolved_at - report.triaged_at).total_seconds() / 86400  # days
            self._update_average_resolution_time(resolution_time)
            
        self.logger.info(f"Report {report_id} resolved")
        
        return report
        
    def _process_reward(self, report: VulnerabilityReport):
        """Process reward payment."""
        researcher = self.researchers[report.researcher_id]
        researcher.total_rewards += report.reward_amount
        
        # Update statistics
        self.statistics['total_rewards'] += report.reward_amount
        
        # In production, this would trigger actual payment
        self.logger.info(f"Processed reward of ${report.reward_amount} for report {report.id}")
        
    def _update_average_resolution_time(self, new_time: float):
        """Update average resolution time statistic."""
        current_avg = self.statistics['average_resolution_time']
        total_resolved = sum(1 for r in self.reports.values() if r.status == SubmissionStatus.RESOLVED)
        
        if total_resolved == 1:
            self.statistics['average_resolution_time'] = new_time
        else:
            # Calculate new average
            self.statistics['average_resolution_time'] = (
                (current_avg * (total_resolved - 1) + new_time) / total_resolved
            )
            
    def disclose_report(self, report_id: str, cve_id: Optional[str] = None) -> VulnerabilityReport:
        """Publicly disclose a resolved vulnerability."""
        if report_id not in self.reports:
            raise ValueError("Invalid report ID")
            
        report = self.reports[report_id]
        
        if report.status != SubmissionStatus.RESOLVED:
            raise ValueError("Can only disclose resolved reports")
            
        # Check disclosure timeline
        if report.resolved_at:
            days_since_resolution = (datetime.now() - report.resolved_at).days
            if days_since_resolution < 30:
                self.logger.warning("Disclosing before 30-day delay period")
                
        report.status = SubmissionStatus.DISCLOSED
        report.disclosed_at = datetime.now()
        report.public_disclosure = True
        
        if cve_id:
            report.cve_id = cve_id
            
        # Add to hall of fame
        self._add_to_hall_of_fame(report)
        
        self.logger.info(f"Report {report_id} publicly disclosed")
        
        return report
        
    def _add_to_hall_of_fame(self, report: VulnerabilityReport):
        """Add researcher to hall of fame."""
        researcher = self.researchers[report.researcher_id]
        
        hall_of_fame_entry = {
            'researcher': researcher.username,
            'report_id': report.id,
            'severity': report.severity.value,
            'title': report.title,
            'disclosed_at': report.disclosed_at.isoformat(),
            'cve_id': report.cve_id
        }
        
        self.hall_of_fame.append(hall_of_fame_entry)
        
        # Award badge
        severity_badges = {
            VulnerabilitySeverity.CRITICAL: "Critical Hunter",
            VulnerabilitySeverity.HIGH: "High Impact",
            VulnerabilitySeverity.MEDIUM: "Security Contributor"
        }
        
        badge = severity_badges.get(report.severity)
        if badge and badge not in researcher.badges:
            researcher.badges.append(badge)
            
    def create_security_challenge(self, challenge_data: Dict[str, Any]) -> str:
        """Create a security challenge for researchers."""
        challenge = {
            'id': str(uuid.uuid4()),
            'title': challenge_data['title'],
            'description': challenge_data['description'],
            'difficulty': challenge_data['difficulty'],
            'reward': challenge_data['reward'],
            'hints': challenge_data.get('hints', []),
            'flag': challenge_data['flag'],  # Hidden from researchers
            'created_at': datetime.now(),
            'solved_by': []
        }
        
        self.security_challenges.append(challenge)
        
        self.logger.info(f"Created security challenge: {challenge['title']}")
        
        return challenge['id']
        
    def submit_challenge_solution(self, researcher_id: str, challenge_id: str, 
                                 flag: str) -> bool:
        """Submit solution to a security challenge."""
        # Find challenge
        challenge = next((c for c in self.security_challenges if c['id'] == challenge_id), None)
        if not challenge:
            raise ValueError("Invalid challenge ID")
            
        # Check if already solved by this researcher
        if researcher_id in challenge['solved_by']:
            return False
            
        # Verify flag
        if flag == challenge['flag']:
            challenge['solved_by'].append(researcher_id)
            
            # Award reward
            researcher = self.researchers[researcher_id]
            researcher.total_rewards += challenge['reward']
            
            # Award badge
            difficulty_badges = {
                'easy': "Challenge Solver",
                'medium': "Challenge Master",
                'hard': "Challenge Elite"
            }
            
            badge = difficulty_badges.get(challenge['difficulty'])
            if badge and badge not in researcher.badges:
                researcher.badges.append(badge)
                
            self.logger.info(f"Challenge {challenge_id} solved by {researcher.username}")
            
            return True
            
        return False
        
    def get_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get researcher leaderboard."""
        # Sort researchers by various metrics
        researchers_list = list(self.researchers.values())
        
        # Sort by total rewards
        researchers_list.sort(key=lambda r: r.total_rewards, reverse=True)
        
        leaderboard = []
        for i, researcher in enumerate(researchers_list[:limit]):
            leaderboard.append({
                'rank': i + 1,
                'username': researcher.username,
                'reputation_score': researcher.reputation_score,
                'reports_accepted': researcher.reports_accepted,
                'total_rewards': researcher.total_rewards,
                'badges': researcher.badges,
                'acceptance_rate': researcher.calculate_acceptance_rate()
            })
            
        return leaderboard
        
    def get_program_statistics(self) -> Dict[str, Any]:
        """Get bug bounty program statistics."""
        stats = self.statistics.copy()
        
        # Add more statistics
        stats['active_researchers'] = len(self.researchers)
        stats['reports_by_status'] = {}
        stats['reports_by_severity'] = {}
        
        for report in self.reports.values():
            # By status
            status = report.status.value
            stats['reports_by_status'][status] = stats['reports_by_status'].get(status, 0) + 1
            
            # By severity
            severity = report.severity.value
            stats['reports_by_severity'][severity] = stats['reports_by_severity'].get(severity, 0) + 1
            
        # Hall of fame size
        stats['hall_of_fame_size'] = len(self.hall_of_fame)
        
        # Average reward by severity
        severity_rewards = {}
        severity_counts = {}
        
        for report in self.reports.values():
            if report.reward_amount:
                severity = report.severity.value
                severity_rewards[severity] = severity_rewards.get(severity, 0) + report.reward_amount
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
        stats['average_reward_by_severity'] = {
            sev: severity_rewards[sev] / severity_counts[sev]
            for sev in severity_rewards
        }
        
        return stats
        
    def export_report(self, report_id: str, include_internal: bool = False) -> Dict[str, Any]:
        """Export a vulnerability report."""
        if report_id not in self.reports:
            raise ValueError("Invalid report ID")
            
        report = self.reports[report_id]
        researcher = self.researchers[report.researcher_id]
        
        exported = {
            'id': report.id,
            'title': report.title,
            'researcher': researcher.username,
            'severity': report.severity.value,
            'status': report.status.value,
            'submitted_at': report.submitted_at.isoformat(),
            'category': report.category,
            'affected_components': report.affected_components
        }
        
        # Public information
        if report.public_disclosure:
            exported.update({
                'description': report.description,
                'steps_to_reproduce': report.steps_to_reproduce,
                'proof_of_concept': report.proof_of_concept,
                'suggested_fix': report.suggested_fix,
                'cve_id': report.cve_id,
                'disclosed_at': report.disclosed_at.isoformat() if report.disclosed_at else None
            })
            
        # Internal information
        if include_internal:
            exported.update({
                'reward_amount': report.reward_amount,
                'internal_notes': report.internal_notes,
                'triaged_at': report.triaged_at.isoformat() if report.triaged_at else None,
                'resolved_at': report.resolved_at.isoformat() if report.resolved_at else None
            })
            
        return exported
        
    def generate_disclosure_timeline(self, report_id: str) -> str:
        """Generate disclosure timeline for a report."""
        if report_id not in self.reports:
            raise ValueError("Invalid report ID")
            
        report = self.reports[report_id]
        researcher = self.researchers[report.researcher_id]
        
        timeline = f"Disclosure Timeline for {report.title}\n"
        timeline += "=" * 50 + "\n\n"
        
        events = []
        
        # Submission
        events.append((report.submitted_at, f"Report submitted by {researcher.username}"))
        
        # Triage
        if report.triaged_at:
            events.append((report.triaged_at, f"Report triaged as {report.status.value}"))
            
        # Resolution
        if report.resolved_at:
            events.append((report.resolved_at, "Vulnerability fixed and verified"))
            
        # Disclosure
        if report.disclosed_at:
            events.append((report.disclosed_at, "Public disclosure"))
            
        # Sort events
        events.sort(key=lambda x: x[0])
        
        # Format timeline
        for timestamp, description in events:
            timeline += f"{timestamp.strftime('%Y-%m-%d')}: {description}\n"
            
        # Add time metrics
        if report.triaged_at and report.submitted_at:
            triage_time = (report.triaged_at - report.submitted_at).days
            timeline += f"\nTime to triage: {triage_time} days\n"
            
        if report.resolved_at and report.triaged_at:
            resolution_time = (report.resolved_at - report.triaged_at).days
            timeline += f"Time to resolution: {resolution_time} days\n"
            
        if report.disclosed_at and report.resolved_at:
            disclosure_delay = (report.disclosed_at - report.resolved_at).days
            timeline += f"Disclosure delay: {disclosure_delay} days\n"
            
        return timeline 