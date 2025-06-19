"""
Traffic Analysis Resistance for Privatus-chat
Week 4: Anonymous Messaging and Onion Routing

This module implements various techniques to resist traffic analysis attacks
that could compromise user anonymity by analyzing communication patterns.

Key Features:
- Message padding to obscure message sizes
- Timing obfuscation with random delays
- Dummy traffic generation for cover
- Burst pattern disruption
- Statistical analysis resistance
"""

import asyncio
import secrets
import time
import statistics
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class TrafficPattern(Enum):
    """Types of traffic patterns to generate"""
    CONSTANT_RATE = "constant_rate"
    BURST = "burst" 
    RANDOM = "random"
    MIMICRY = "mimicry"

@dataclass
class TrafficEvent:
    """Represents a traffic event for analysis"""
    timestamp: float
    size: int
    direction: str  # 'send' or 'receive'
    is_dummy: bool = False
    circuit_id: Optional[int] = None

class MessagePadder:
    """Handles message padding to obscure true message sizes"""
    
    def __init__(self):
        # Standard padding sizes (powers of 2 for efficiency)
        self.padding_sizes = [128, 256, 512, 1024, 2048, 4096, 8192]
        self.max_padding_size = 8192
        self.min_message_size = 128
        
    def pad_message(self, message: bytes) -> bytes:
        """Pad message to next standard size"""
        current_size = len(message)
        
        # Find the next padding size
        target_size = self.min_message_size
        for size in self.padding_sizes:
            if size >= current_size:
                target_size = size
                break
        
        if target_size > self.max_padding_size:
            target_size = self.max_padding_size
            
        # Add random padding
        padding_needed = target_size - current_size
        if padding_needed > 0:
            padding = secrets.token_bytes(padding_needed)
            return message + padding
        
        return message
    
    def unpad_message(self, padded_message: bytes) -> bytes:
        """Remove padding from message (simplified implementation)"""
        # In a real implementation, we'd have padding markers
        # For now, assume the original message length is encoded
        # This is a placeholder for the actual unpadding logic
        return padded_message

class TimingObfuscator:
    """Handles timing obfuscation to break correlation patterns"""
    
    def __init__(self):
        self.min_delay = 0.1  # 100ms minimum delay
        self.max_delay = 2.0  # 2 second maximum delay
        self.delay_distribution = "exponential"  # or "uniform", "normal"
        
        # Adaptive timing based on network conditions
        self.base_latency = 0.1
        self.recent_delays: List[float] = []
        self.max_recent_samples = 100
        
    def get_send_delay(self, message_size: int, urgency: str = "normal") -> float:
        """Calculate delay before sending a message"""
        if urgency == "immediate":
            return 0.0
        elif urgency == "low":
            base_delay = self.max_delay * 0.8
        else:  # normal
            base_delay = (self.min_delay + self.max_delay) / 2
        
        # Add size-based variance
        size_factor = min(1.0, message_size / 1024)  # Normalize to 1KB
        base_delay *= (0.5 + size_factor * 0.5)
        
        # Add randomness based on distribution
        if self.delay_distribution == "exponential":
            # Exponential distribution for realistic network delays
            random_factor = -self.base_latency * (secrets.randbelow(1000) / 1000.0)
            delay = base_delay + abs(random_factor)
        else:  # uniform
            random_factor = (secrets.randbelow(1000) / 1000.0) * self.max_delay * 0.5
            delay = base_delay + random_factor
        
        return max(self.min_delay, min(delay, self.max_delay))
    
    def add_receive_delay(self, received_time: float):
        """Record a received message delay for adaptive timing"""
        self.recent_delays.append(received_time)
        if len(self.recent_delays) > self.max_recent_samples:
            self.recent_delays.pop(0)
        
        # Update base latency estimate
        if len(self.recent_delays) >= 10:
            self.base_latency = statistics.median(self.recent_delays[-10:])

class DummyTrafficGenerator:
    """Generates cover traffic to mask real communication patterns"""
    
    def __init__(self, traffic_callback: Callable[[bytes, str], None]):
        self.traffic_callback = traffic_callback
        self.running = False
        
        # Traffic patterns
        self.patterns = {
            TrafficPattern.CONSTANT_RATE: self._constant_rate_pattern,
            TrafficPattern.BURST: self._burst_pattern,
            TrafficPattern.RANDOM: self._random_pattern,
            TrafficPattern.MIMICRY: self._mimicry_pattern
        }
        
        # Configuration
        self.base_rate = 0.1  # Messages per second
        self.burst_probability = 0.05  # 5% chance of burst
        self.burst_size = (3, 10)  # 3-10 messages per burst
        
        # Statistics
        self.dummy_messages_sent = 0
        self.total_dummy_bytes = 0
        
    async def start_cover_traffic(self, pattern: TrafficPattern = TrafficPattern.RANDOM):
        """Start generating cover traffic"""
        if self.running:
            return
            
        self.running = True
        logger.info(f"Starting cover traffic generation with pattern: {pattern.value}")
        
        # Start the selected pattern
        pattern_func = self.patterns.get(pattern, self._random_pattern)
        asyncio.create_task(pattern_func())
        
    async def stop_cover_traffic(self):
        """Stop generating cover traffic"""
        self.running = False
        logger.info("Stopped cover traffic generation")
    
    async def _constant_rate_pattern(self):
        """Generate constant rate dummy traffic"""
        interval = 1.0 / self.base_rate
        
        while self.running:
            await asyncio.sleep(interval)
            if self.running:
                await self._send_dummy_message()
    
    async def _burst_pattern(self):
        """Generate bursty dummy traffic"""
        while self.running:
            # Normal interval
            base_interval = 1.0 / self.base_rate
            await asyncio.sleep(base_interval)
            
            if not self.running:
                break
            
            # Check for burst
            if secrets.randbelow(1000) / 1000.0 < self.burst_probability:
                # Generate burst
                burst_size = secrets.randbelow(
                    self.burst_size[1] - self.burst_size[0]
                ) + self.burst_size[0]
                
                logger.debug(f"Generating traffic burst of {burst_size} messages")
                
                for _ in range(burst_size):
                    if self.running:
                        await self._send_dummy_message()
                        await asyncio.sleep(0.1)  # Short delay between burst messages
            else:
                await self._send_dummy_message()
    
    async def _random_pattern(self):
        """Generate random pattern dummy traffic"""
        while self.running:
            # Random interval between 1-10 times the base rate
            multiplier = 1 + secrets.randbelow(9)
            interval = multiplier / self.base_rate
            
            await asyncio.sleep(interval)
            if self.running:
                await self._send_dummy_message()
    
    async def _mimicry_pattern(self):
        """Generate traffic that mimics real usage patterns"""
        # This would analyze real usage patterns and generate similar dummy traffic
        # For now, implement a simplified version
        
        while self.running:
            # Simulate realistic patterns (more active during "day" hours)
            current_hour = time.localtime().tm_hour
            
            if 8 <= current_hour <= 22:  # Active hours
                activity_factor = 1.5
            else:  # Quiet hours
                activity_factor = 0.3
            
            interval = (1.0 / self.base_rate) / activity_factor
            await asyncio.sleep(interval)
            
            if self.running:
                await self._send_dummy_message()
    
    async def _send_dummy_message(self):
        """Send a dummy message for cover traffic"""
        # Generate realistic dummy message size
        size_options = [128, 256, 512, 1024]
        weights = [40, 30, 20, 10]  # Favor smaller messages
        
        # Weighted random selection
        total_weight = sum(weights)
        random_value = secrets.randbelow(total_weight)
        cumulative_weight = 0
        
        message_size = size_options[-1]  # Default fallback
        for i, weight in enumerate(weights):
            cumulative_weight += weight
            if random_value < cumulative_weight:
                message_size = size_options[i]
                break
        
        # Generate dummy message
        dummy_message = secrets.token_bytes(message_size)
        
        # Send through callback
        self.traffic_callback(dummy_message, "dummy")
        
        # Update statistics
        self.dummy_messages_sent += 1
        self.total_dummy_bytes += message_size
        
        logger.debug(f"Sent dummy message of {message_size} bytes")

class TrafficAnalysisResistance:
    """Main class coordinating all traffic analysis resistance measures"""
    
    def __init__(self, send_callback: Callable[[bytes, str], None]):
        self.send_callback = send_callback
        
        # Components
        self.padder = MessagePadder()
        self.timing_obfuscator = TimingObfuscator()
        self.dummy_generator = DummyTrafficGenerator(self._handle_dummy_traffic)
        
        # Traffic analysis
        self.traffic_events: List[TrafficEvent] = []
        self.max_events = 10000  # Limit memory usage
        
        # Configuration
        self.padding_enabled = True
        self.timing_obfuscation_enabled = True
        self.cover_traffic_enabled = False
        self.cover_traffic_pattern = TrafficPattern.RANDOM
        
        self.running = False
        
    async def start(self):
        """Start traffic analysis resistance"""
        logger.info("Starting traffic analysis resistance")
        self.running = True
        
        if self.cover_traffic_enabled:
            await self.dummy_generator.start_cover_traffic(self.cover_traffic_pattern)
            
    async def stop(self):
        """Stop traffic analysis resistance"""
        logger.info("Stopping traffic analysis resistance")
        self.running = False
        
        await self.dummy_generator.stop_cover_traffic()
    
    async def send_message_with_protection(self, message: bytes, 
                                         urgency: str = "normal") -> bool:
        """Send a message with full traffic analysis protection"""
        try:
            # Step 1: Pad message
            if self.padding_enabled:
                padded_message = self.padder.pad_message(message)
            else:
                padded_message = message
            
            # Step 2: Apply timing obfuscation
            if self.timing_obfuscation_enabled:
                delay = self.timing_obfuscator.get_send_delay(
                    len(padded_message), urgency
                )
                if delay > 0:
                    await asyncio.sleep(delay)
            
            # Step 3: Record traffic event
            event = TrafficEvent(
                timestamp=time.time(),
                size=len(padded_message),
                direction="send",
                is_dummy=False
            )
            self._record_traffic_event(event)
            
            # Step 4: Send message
            self.send_callback(padded_message, "real")
            
            logger.debug(f"Sent protected message: {len(message)} -> {len(padded_message)} bytes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send protected message: {e}")
            return False
    
    def _handle_dummy_traffic(self, dummy_message: bytes, message_type: str):
        """Handle dummy traffic generation"""
        # Apply same protections to dummy messages
        if self.padding_enabled:
            padded_dummy = self.padder.pad_message(dummy_message)
        else:
            padded_dummy = dummy_message
        
        # Record dummy traffic event
        event = TrafficEvent(
            timestamp=time.time(),
            size=len(padded_dummy),
            direction="send",
            is_dummy=True
        )
        self._record_traffic_event(event)
        
        # Send dummy message
        self.send_callback(padded_dummy, "dummy")
    
    def _record_traffic_event(self, event: TrafficEvent):
        """Record a traffic event for analysis"""
        self.traffic_events.append(event)
        
        # Limit memory usage
        if len(self.traffic_events) > self.max_events:
            # Remove oldest 10% of events
            remove_count = self.max_events // 10
            self.traffic_events = self.traffic_events[remove_count:]
    
    def configure_protection(self, padding: bool = True, timing: bool = True, 
                           cover_traffic: bool = False,
                           cover_pattern: TrafficPattern = TrafficPattern.RANDOM):
        """Configure traffic analysis protection settings"""
        self.padding_enabled = padding
        self.timing_obfuscation_enabled = timing
        
        if cover_traffic != self.cover_traffic_enabled:
            self.cover_traffic_enabled = cover_traffic
            self.cover_traffic_pattern = cover_pattern
            
            if self.running:
                if cover_traffic:
                    asyncio.create_task(
                        self.dummy_generator.start_cover_traffic(cover_pattern)
                    )
                else:
                    asyncio.create_task(
                        self.dummy_generator.stop_cover_traffic()
                    )
        
        logger.info(f"Updated protection: padding={padding}, timing={timing}, "
                   f"cover={cover_traffic}, pattern={cover_pattern.value}")
    
    def get_traffic_statistics(self) -> Dict[str, Any]:
        """Get traffic analysis statistics"""
        if not self.traffic_events:
            return {
                'total_events': 0,
                'real_messages': 0,
                'dummy_messages': 0,
                'total_bytes': 0,
                'dummy_bytes': 0,
                'protection_efficiency': 0.0
            }
        
        real_events = [e for e in self.traffic_events if not e.is_dummy]
        dummy_events = [e for e in self.traffic_events if e.is_dummy]
        
        total_bytes = sum(e.size for e in self.traffic_events)
        dummy_bytes = sum(e.size for e in dummy_events)
        
        # Calculate protection efficiency (higher is better)
        if len(real_events) > 0:
            protection_efficiency = len(dummy_events) / len(real_events)
        else:
            protection_efficiency = 0.0
        
        return {
            'total_events': len(self.traffic_events),
            'real_messages': len(real_events),
            'dummy_messages': len(dummy_events),
            'total_bytes': total_bytes,
            'dummy_bytes': dummy_bytes,
            'protection_efficiency': protection_efficiency,
            'padding_enabled': self.padding_enabled,
            'timing_enabled': self.timing_obfuscation_enabled,
            'cover_traffic_enabled': self.cover_traffic_enabled
        }
    
    def analyze_traffic_patterns(self) -> Dict[str, Any]:
        """Analyze traffic patterns for potential vulnerabilities"""
        if len(self.traffic_events) < 10:
            return {'analysis': 'insufficient_data'}
        
        real_events = [e for e in self.traffic_events if not e.is_dummy]
        
        if not real_events:
            return {'analysis': 'no_real_traffic'}
        
        # Analyze timing patterns
        intervals = []
        for i in range(1, len(real_events)):
            interval = real_events[i].timestamp - real_events[i-1].timestamp
            intervals.append(interval)
        
        if intervals:
            avg_interval = statistics.mean(intervals)
            interval_std = statistics.stdev(intervals) if len(intervals) > 1 else 0
            
            # Detect regular patterns (potential vulnerability)
            regularity_score = interval_std / avg_interval if avg_interval > 0 else 0
            
            # Analyze size patterns
            sizes = [e.size for e in real_events]
            size_std = statistics.stdev(sizes) if len(sizes) > 1 else 0
            avg_size = statistics.mean(sizes)
            
            size_variability = size_std / avg_size if avg_size > 0 else 0
        else:
            regularity_score = 0
            size_variability = 0
            avg_interval = 0
            avg_size = 0
        
        # Generate recommendations
        recommendations = []
        if regularity_score < 0.5:
            recommendations.append("Consider increasing timing randomization")
        if size_variability < 0.3:
            recommendations.append("Message sizes show low variability")
        if len(real_events) > len([e for e in self.traffic_events if e.is_dummy]):
            recommendations.append("Consider increasing cover traffic rate")
        
        return {
            'analysis': 'complete',
            'avg_interval': avg_interval,
            'timing_regularity': regularity_score,
            'size_variability': size_variability,
            'avg_message_size': avg_size,
            'recommendations': recommendations,
            'vulnerability_score': max(0, 1 - regularity_score - size_variability)
        } 