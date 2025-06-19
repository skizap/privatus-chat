"""
Privacy Controls for Privatus-chat
Week 4: Anonymous Messaging and Onion Routing

This module provides user-friendly privacy controls and interfaces that allow
users to configure their desired level of anonymity and privacy protection.

Key Features:
- Privacy settings interfaces with clear explanations
- Anonymity level indicators and controls
- Privacy audit tools and recommendations
- Real-time privacy status monitoring
- Educational privacy guidance
"""

import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import logging

from .onion_routing import OnionRoutingManager
from .traffic_analysis import TrafficAnalysisResistance, TrafficPattern
from .anonymous_identity import AnonymousIdentityManager, IdentityType

logger = logging.getLogger(__name__)

class PrivacyLevel(Enum):
    """Privacy protection levels"""
    MINIMAL = "minimal"        # Basic encryption only
    STANDARD = "standard"      # Standard privacy protections
    HIGH = "high"             # Enhanced privacy with traffic analysis resistance
    MAXIMUM = "maximum"       # Maximum anonymity with onion routing

class AnonymityStatus(Enum):
    """Current anonymity status"""
    NONE = "none"             # No anonymity protection
    PSEUDONYMOUS = "pseudonymous"  # Using pseudonymous identity
    ANONYMOUS = "anonymous"    # Using onion routing
    UNTRACEABLE = "untraceable"  # Maximum protection active

@dataclass
class PrivacySettings:
    """User privacy configuration settings"""
    privacy_level: PrivacyLevel = PrivacyLevel.STANDARD
    
    # Identity settings
    use_anonymous_identities: bool = True
    auto_rotate_identities: bool = True
    identity_lifetime_hours: int = 24
    
    # Onion routing settings
    use_onion_routing: bool = False
    circuit_length: int = 3
    circuit_lifetime_minutes: int = 60
    
    # Traffic analysis resistance
    message_padding: bool = True
    timing_obfuscation: bool = True
    dummy_traffic: bool = False
    dummy_traffic_pattern: TrafficPattern = TrafficPattern.RANDOM
    
    # Advanced settings
    cover_traffic_rate: float = 0.1  # Messages per second
    max_message_delay: float = 2.0   # Seconds
    metadata_protection: bool = True
    
    # UI preferences
    show_anonymity_warnings: bool = True
    show_privacy_tips: bool = True
    detailed_privacy_status: bool = False

@dataclass
class PrivacyAuditResult:
    """Result of privacy audit"""
    overall_score: float  # 0.0 to 1.0
    anonymity_level: AnonymityStatus
    vulnerabilities: List[str]
    recommendations: List[str]
    protection_details: Dict[str, Any]

class PrivacyController:
    """Main privacy control system"""
    
    def __init__(self, 
                 onion_manager: Optional[OnionRoutingManager] = None,
                 traffic_resistance: Optional[TrafficAnalysisResistance] = None,
                 identity_manager: Optional[AnonymousIdentityManager] = None):
        
        self.onion_manager = onion_manager
        self.traffic_resistance = traffic_resistance
        self.identity_manager = identity_manager
        
        # Current settings
        self.settings = PrivacySettings()
        self.current_anonymity_status = AnonymityStatus.NONE
        
        # Privacy monitoring
        self.privacy_events: List[Dict[str, Any]] = []
        self.last_audit_time = 0
        self.audit_interval = 300  # 5 minutes
        
        # Status callbacks
        self.status_callbacks: List[Callable[[AnonymityStatus], None]] = []
        
        # Privacy tips and warnings
        self.privacy_tips = [
            "Use different identities for different conversations",
            "Enable onion routing for maximum anonymity",
            "Regular identity rotation improves privacy",
            "Cover traffic helps hide communication patterns",
            "Avoid patterns in your messaging behavior"
        ]
        
        self.privacy_warnings = {
            AnonymityStatus.NONE: "No anonymity protection active",
            AnonymityStatus.PSEUDONYMOUS: "Using pseudonymous identity only",
            AnonymityStatus.ANONYMOUS: "Good anonymity protection",
            AnonymityStatus.UNTRACEABLE: "Maximum anonymity protection active"
        }
        
    def configure_privacy_level(self, level: PrivacyLevel):
        """Configure privacy settings based on predefined level"""
        logger.info(f"Configuring privacy level: {level.value}")
        
        if level == PrivacyLevel.MINIMAL:
            self.settings = PrivacySettings(
                privacy_level=level,
                use_anonymous_identities=False,
                use_onion_routing=False,
                message_padding=False,
                timing_obfuscation=False,
                dummy_traffic=False
            )
            
        elif level == PrivacyLevel.STANDARD:
            self.settings = PrivacySettings(
                privacy_level=level,
                use_anonymous_identities=True,
                auto_rotate_identities=False,
                use_onion_routing=False,
                message_padding=True,
                timing_obfuscation=False,
                dummy_traffic=False
            )
            
        elif level == PrivacyLevel.HIGH:
            self.settings = PrivacySettings(
                privacy_level=level,
                use_anonymous_identities=True,
                auto_rotate_identities=True,
                use_onion_routing=False,
                message_padding=True,
                timing_obfuscation=True,
                dummy_traffic=True,
                dummy_traffic_pattern=TrafficPattern.RANDOM
            )
            
        elif level == PrivacyLevel.MAXIMUM:
            self.settings = PrivacySettings(
                privacy_level=level,
                use_anonymous_identities=True,
                auto_rotate_identities=True,
                identity_lifetime_hours=1,  # Rotate hourly
                use_onion_routing=True,
                circuit_length=3,
                message_padding=True,
                timing_obfuscation=True,
                dummy_traffic=True,
                dummy_traffic_pattern=TrafficPattern.MIMICRY,
                cover_traffic_rate=0.2
            )
        
        # Apply settings to components
        self._apply_settings()
        
        # Update status
        self._update_anonymity_status()
        
        # Log privacy event
        self._log_privacy_event("privacy_level_changed", {
            'new_level': level.value,
            'timestamp': time.time()
        })
    
    async def start(self):
        """Start the privacy control system"""
        # Apply current settings
        self._apply_settings()
        self._update_anonymity_status()
        
        logger.info("Privacy control system started")
    
    async def stop(self):
        """Stop the privacy control system"""
        logger.info("Privacy control system stopped")
    
    def _apply_settings(self):
        """Apply current settings to privacy components"""
        # Configure traffic analysis resistance
        if self.traffic_resistance:
            self.traffic_resistance.configure_protection(
                padding=self.settings.message_padding,
                timing=self.settings.timing_obfuscation,
                cover_traffic=self.settings.dummy_traffic,
                cover_pattern=self.settings.dummy_traffic_pattern
            )
        
        # Configure identity manager
        if self.identity_manager:
            self.identity_manager.auto_rotate_identities = self.settings.auto_rotate_identities
        
        logger.debug("Applied privacy settings to components")
    
    def _update_anonymity_status(self):
        """Update current anonymity status based on active protections"""
        old_status = self.current_anonymity_status
        
        if self.settings.use_onion_routing and self._is_onion_routing_active():
            if self.settings.dummy_traffic and self.settings.timing_obfuscation:
                self.current_anonymity_status = AnonymityStatus.UNTRACEABLE
            else:
                self.current_anonymity_status = AnonymityStatus.ANONYMOUS
        elif self.settings.use_anonymous_identities:
            self.current_anonymity_status = AnonymityStatus.PSEUDONYMOUS
        else:
            self.current_anonymity_status = AnonymityStatus.NONE
        
        # Notify callbacks if status changed
        if old_status != self.current_anonymity_status:
            for callback in self.status_callbacks:
                try:
                    callback(self.current_anonymity_status)
                except Exception as e:
                    logger.error(f"Error in status callback: {e}")
            
            logger.info(f"Anonymity status changed: {old_status.value} -> "
                       f"{self.current_anonymity_status.value}")
    
    def _is_onion_routing_active(self) -> bool:
        """Check if onion routing is currently active"""
        if not self.onion_manager:
            return False
        
        stats = self.onion_manager.get_circuit_statistics()
        return stats.get('active_circuits', 0) > 0
    
    def register_status_callback(self, callback: Callable[[AnonymityStatus], None]):
        """Register callback for anonymity status changes"""
        self.status_callbacks.append(callback)
    
    def get_privacy_status(self) -> Dict[str, Any]:
        """Get comprehensive privacy status information"""
        status = {
            'privacy_level': self.settings.privacy_level.value,
            'anonymity_status': self.current_anonymity_status.value,
            'timestamp': time.time(),
            'protections_active': {
                'anonymous_identities': self.settings.use_anonymous_identities,
                'onion_routing': self.settings.use_onion_routing,
                'message_padding': self.settings.message_padding,
                'timing_obfuscation': self.settings.timing_obfuscation,
                'dummy_traffic': self.settings.dummy_traffic
            }
        }
        
        # Add component-specific status
        if self.onion_manager:
            circuit_stats = self.onion_manager.get_circuit_statistics()
            status['onion_routing_stats'] = circuit_stats
        
        if self.traffic_resistance:
            traffic_stats = self.traffic_resistance.get_traffic_statistics()
            status['traffic_analysis_stats'] = traffic_stats
        
        if self.identity_manager:
            identity_stats = self.identity_manager.get_identity_statistics()
            status['identity_stats'] = identity_stats
        
        return status
    
    def perform_privacy_audit(self) -> PrivacyAuditResult:
        """Perform comprehensive privacy audit"""
        logger.info("Performing privacy audit")
        
        vulnerabilities = []
        recommendations = []
        protection_details = {}
        
        # Audit identity protection
        if not self.settings.use_anonymous_identities:
            vulnerabilities.append("Real identity exposed in communications")
            recommendations.append("Enable anonymous identities")
        else:
            protection_details['identity_protection'] = 'active'
            
            if not self.settings.auto_rotate_identities:
                vulnerabilities.append("Identity rotation disabled")
                recommendations.append("Enable automatic identity rotation")
        
        # Audit network anonymity
        if not self.settings.use_onion_routing:
            vulnerabilities.append("Network traffic not anonymized")
            recommendations.append("Enable onion routing for network anonymity")
        else:
            protection_details['network_anonymity'] = 'active'
            
            if self.onion_manager:
                stats = self.onion_manager.get_circuit_statistics()
                if stats.get('active_circuits', 0) == 0:
                    vulnerabilities.append("No active onion circuits")
                    recommendations.append("Ensure onion circuits are established")
        
        # Audit traffic analysis resistance
        if not self.settings.message_padding:
            vulnerabilities.append("Message sizes not obfuscated")
            recommendations.append("Enable message padding")
        
        if not self.settings.timing_obfuscation:
            vulnerabilities.append("Message timing patterns exposed")
            recommendations.append("Enable timing obfuscation")
        
        if not self.settings.dummy_traffic:
            vulnerabilities.append("No cover traffic protection")
            recommendations.append("Enable dummy traffic generation")
        else:
            protection_details['traffic_analysis_resistance'] = 'active'
        
        # Calculate overall score
        total_checks = 6  # Number of privacy checks
        failed_checks = len(vulnerabilities)
        overall_score = max(0.0, 1.0 - (failed_checks / total_checks))
        
        result = PrivacyAuditResult(
            overall_score=overall_score,
            anonymity_level=self.current_anonymity_status,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            protection_details=protection_details
        )
        
        self.last_audit_time = time.time()
        
        # Log audit result
        self._log_privacy_event("privacy_audit", {
            'score': overall_score,
            'vulnerabilities_count': len(vulnerabilities),
            'anonymity_level': self.current_anonymity_status.value
        })
        
        logger.info(f"Privacy audit completed. Score: {overall_score:.2f}")
        return result
    
    def get_privacy_recommendations(self) -> List[str]:
        """Get personalized privacy recommendations"""
        recommendations = []
        
        # Based on current settings
        if self.settings.privacy_level == PrivacyLevel.MINIMAL:
            recommendations.append("Consider upgrading to Standard privacy level")
        
        if not self.settings.use_anonymous_identities:
            recommendations.append("Enable anonymous identities to protect your real identity")
        
        if not self.settings.use_onion_routing:
            recommendations.append("Enable onion routing for network anonymity")
        
        # Based on usage patterns
        if self.identity_manager:
            stats = self.identity_manager.get_identity_statistics()
            if stats.get('identity_rotations', 0) == 0:
                recommendations.append("Consider rotating your identities periodically")
        
        if self.traffic_resistance:
            traffic_analysis = self.traffic_resistance.analyze_traffic_patterns()
            if traffic_analysis.get('analysis') == 'complete':
                vulnerability_score = traffic_analysis.get('vulnerability_score', 0)
                if vulnerability_score > 0.7:
                    recommendations.append("Your messaging patterns may be predictable")
                    recommendations.extend(traffic_analysis.get('recommendations', []))
        
        # Add random privacy tips
        if len(recommendations) < 3:
            import secrets
            available_tips = [tip for tip in self.privacy_tips if tip not in recommendations]
            if available_tips:
                tip = secrets.choice(available_tips)
                recommendations.append(tip)
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def _log_privacy_event(self, event_type: str, data: Dict[str, Any]):
        """Log privacy-related event"""
        event = {
            'type': event_type,
            'timestamp': time.time(),
            'data': data
        }
        
        self.privacy_events.append(event)
        
        # Limit event history
        if len(self.privacy_events) > 1000:
            self.privacy_events = self.privacy_events[-500:]
    
    def get_privacy_metrics(self) -> Dict[str, Any]:
        """Get privacy metrics and statistics"""
        current_time = time.time()
        
        # Calculate uptime for different protection levels
        protection_uptime = {}
        last_time = current_time - 86400  # Last 24 hours
        
        for event in self.privacy_events:
            if event['timestamp'] > last_time:
                event_type = event['type']
                if event_type == 'privacy_level_changed':
                    level = event['data'].get('new_level')
                    if level not in protection_uptime:
                        protection_uptime[level] = 0
        
        return {
            'current_privacy_level': self.settings.privacy_level.value,
            'current_anonymity_status': self.current_anonymity_status.value,
            'privacy_events_24h': len([
                e for e in self.privacy_events 
                if e['timestamp'] > current_time - 86400
            ]),
            'last_audit_time': self.last_audit_time,
            'protection_uptime': protection_uptime,
            'privacy_score': self.perform_privacy_audit().overall_score
        }
    
    def export_privacy_settings(self) -> Dict[str, Any]:
        """Export privacy settings for backup/sharing"""
        return {
            'privacy_level': self.settings.privacy_level.value,
            'use_anonymous_identities': self.settings.use_anonymous_identities,
            'auto_rotate_identities': self.settings.auto_rotate_identities,
            'identity_lifetime_hours': self.settings.identity_lifetime_hours,
            'use_onion_routing': self.settings.use_onion_routing,
            'circuit_length': self.settings.circuit_length,
            'circuit_lifetime_minutes': self.settings.circuit_lifetime_minutes,
            'message_padding': self.settings.message_padding,
            'timing_obfuscation': self.settings.timing_obfuscation,
            'dummy_traffic': self.settings.dummy_traffic,
            'dummy_traffic_pattern': self.settings.dummy_traffic_pattern.value,
            'cover_traffic_rate': self.settings.cover_traffic_rate,
            'max_message_delay': self.settings.max_message_delay,
            'metadata_protection': self.settings.metadata_protection
        }
    
    def import_privacy_settings(self, settings_data: Dict[str, Any]) -> bool:
        """Import privacy settings from backup/sharing"""
        try:
            self.settings = PrivacySettings(
                privacy_level=PrivacyLevel(settings_data['privacy_level']),
                use_anonymous_identities=settings_data['use_anonymous_identities'],
                auto_rotate_identities=settings_data['auto_rotate_identities'],
                identity_lifetime_hours=settings_data['identity_lifetime_hours'],
                use_onion_routing=settings_data['use_onion_routing'],
                circuit_length=settings_data['circuit_length'],
                circuit_lifetime_minutes=settings_data['circuit_lifetime_minutes'],
                message_padding=settings_data['message_padding'],
                timing_obfuscation=settings_data['timing_obfuscation'],
                dummy_traffic=settings_data['dummy_traffic'],
                dummy_traffic_pattern=TrafficPattern(settings_data['dummy_traffic_pattern']),
                cover_traffic_rate=settings_data['cover_traffic_rate'],
                max_message_delay=settings_data['max_message_delay'],
                metadata_protection=settings_data['metadata_protection']
            )
            
            self._apply_settings()
            self._update_anonymity_status()
            
            logger.info("Privacy settings imported successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import privacy settings: {e}")
            return False 