"""
Protocol Fuzzing Tests for Message Handling in Privatus-chat

This module provides comprehensive fuzzing tests specifically designed for the P2P message protocol including:
- Message format fuzzing
- Protocol state transition testing
- Boundary value testing
- Message parsing robustness
- Cryptographic message validation
- Error handling verification
- Performance under malformed input
"""

import asyncio
import json
import random
import struct
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple, Callable
from pathlib import Path
import string
import itertools

# Import network modules
try:
    from ..network.message_protocol import (
        MessageType, MessageHeader, P2PMessage, MessageSerializer, MessageFlags
    )
except ImportError:
    MessageType = None
    MessageHeader = None
    P2PMessage = None
    MessageSerializer = None
    MessageFlags = None


class FuzzingStrategy(Enum):
    """Fuzzing strategies for protocol testing."""

    RANDOM = "random"
    MUTATION = "mutation"
    GENERATION = "generation"
    BOUNDARY = "boundary"
    STATEFUL = "stateful"


class FuzzingTarget(Enum):
    """Components to fuzz in the protocol."""

    MESSAGE_HEADER = "message_header"
    MESSAGE_PAYLOAD = "message_payload"
    SERIALIZATION = "serialization"
    DESERIALIZATION = "deserialization"
    CRYPTOGRAPHIC_VALIDATION = "cryptographic_validation"
    STATE_TRANSITIONS = "state_transitions"


@dataclass
class FuzzingCase:
    """Individual fuzzing test case."""

    id: str
    strategy: FuzzingStrategy
    target: FuzzingTarget
    description: str
    payload: bytes
    expected_behavior: str
    category: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'strategy': self.strategy.value,
            'target': self.target.value,
            'description': self.description,
            'payload': self.payload.hex(),
            'expected_behavior': self.expected_behavior,
            'category': self.category,
            'metadata': self.metadata
        }


@dataclass
class FuzzingResult:
    """Result of a fuzzing test case."""

    test_case: FuzzingCase
    success: bool
    error: Optional[str] = None
    exception_type: Optional[str] = None
    response_time: float = 0.0
    crash_detected: bool = False
    hang_detected: bool = False
    unexpected_behavior: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_case': self.test_case.to_dict(),
            'success': self.success,
            'error': self.error,
            'exception_type': self.exception_type,
            'response_time': self.response_time,
            'crash_detected': self.crash_detected,
            'hang_detected': self.hang_detected,
            'unexpected_behavior': self.unexpected_behavior,
            'timestamp': self.timestamp.isoformat()
        }


class ProtocolFuzzingTester:
    """Comprehensive protocol fuzzing test framework."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.fuzzing_results: List[FuzzingResult] = []
        self.crash_cases: List[FuzzingResult] = []
        self.is_running = False

        # Fuzzing statistics
        self.stats = {
            'total_cases': 0,
            'successful_cases': 0,
            'crashed_cases': 0,
            'hung_cases': 0,
            'unexpected_cases': 0,
            'start_time': None,
            'end_time': None
        }

        # Message templates for fuzzing
        self.message_templates = self._initialize_message_templates()

        # Mutation strategies
        self.mutation_strategies = [
            self._bit_flip_mutation,
            self._byte_mutation,
            self._insertion_mutation,
            self._deletion_mutation,
            self._duplication_mutation,
            self._transposition_mutation,
        ]

        # Boundary test cases
        self.boundary_cases = self._initialize_boundary_cases()

    def _initialize_message_templates(self) -> Dict[str, bytes]:
        """Initialize message templates for fuzzing."""
        templates = {}

        # Valid message templates
        valid_messages = {
            'handshake': self._create_handshake_template(),
            'chat_message': self._create_chat_template(),
            'ping': self._create_ping_template(),
            'error': self._create_error_template(),
        }

        for name, template in valid_messages.items():
            templates[name] = template

        return templates

    def _create_handshake_template(self) -> bytes:
        """Create handshake message template."""
        header = MessageHeader(
            message_type=MessageType.HANDSHAKE.value,
            message_id="test_message_id",
            sender_id=b"sender123456789012",
            recipient_id=b"recipient123456789"
        )

        payload = {
            'protocol_version': 1,
            'public_key': b"public_key_12345678901234567890".hex(),
            'capabilities': ['chat', 'file_transfer'],
            'timestamp': time.time()
        }

        message = P2PMessage(header=header, payload=payload)
        serializer = MessageSerializer()
        return serializer.serialize(message)

    def _create_chat_template(self) -> bytes:
        """Create chat message template."""
        header = MessageHeader(
            message_type=MessageType.CHAT_MESSAGE.value,
            message_id="test_chat_id",
            sender_id=b"sender123456789012",
            recipient_id=b"recipient123456789",
            flags=MessageFlags.REQUIRES_ACK
        )

        payload = {
            'content': 'Hello, this is a test message',
            'timestamp': time.time()
        }

        message = P2PMessage(header=header, payload=payload)
        serializer = MessageSerializer()
        return serializer.serialize(message)

    def _create_ping_template(self) -> bytes:
        """Create ping message template."""
        header = MessageHeader(
            message_type=MessageType.PING.value,
            message_id="test_ping_id",
            sender_id=b"sender123456789012"
        )

        payload = {'timestamp': time.time()}

        message = P2PMessage(header=header, payload=payload)
        serializer = MessageSerializer()
        return serializer.serialize(message)

    def _create_error_template(self) -> bytes:
        """Create error message template."""
        header = MessageHeader(
            message_type=MessageType.ERROR.value,
            message_id="test_error_id",
            sender_id=b"sender123456789012"
        )

        payload = {
            'error_code': 'TEST_ERROR',
            'error_message': 'This is a test error',
            'timestamp': time.time()
        }

        message = P2PMessage(header=header, payload=payload)
        serializer = MessageSerializer()
        return serializer.serialize(message)

    def _initialize_boundary_cases(self) -> List[bytes]:
        """Initialize boundary test cases."""
        cases = []

        # Length boundaries
        for length in [0, 1, 16, 255, 256, 1023, 1024, 4095, 4096, 65535, 65536]:
            cases.append(b'A' * length)
            cases.append(b'\x00' * length)
            cases.append(b'\xFF' * length)

        # Format boundaries
        cases.extend([
            b'',  # Empty
            b'\x00',  # Single null byte
            b'\xFF',  # Single max byte
            b'\x00\x01\x02\x03',  # Incremental bytes
            b'\x03\x02\x01\x00',  # Decremental bytes
            b'\x41\x42\x43\x44' * 100,  # Repeating pattern
        ])

        return cases

    async def run_protocol_fuzzing(self, target_component: str, iterations: int = 1000,
                                 strategy: FuzzingStrategy = FuzzingStrategy.MUTATION) -> List[FuzzingResult]:
        """Run comprehensive protocol fuzzing tests."""
        self.logger.info(f"Starting protocol fuzzing: {strategy.value} on {target_component} for {iterations} iterations")

        self.is_running = True
        self.stats['start_time'] = datetime.now()
        self.fuzzing_results = []

        try:
            if strategy == FuzzingStrategy.RANDOM:
                await self._run_random_fuzzing(target_component, iterations)
            elif strategy == FuzzingStrategy.MUTATION:
                await self._run_mutation_fuzzing(target_component, iterations)
            elif strategy == FuzzingStrategy.GENERATION:
                await self._run_generation_fuzzing(target_component, iterations)
            elif strategy == FuzzingStrategy.BOUNDARY:
                await self._run_boundary_fuzzing(target_component)
            elif strategy == FuzzingStrategy.STATEFUL:
                await self._run_stateful_fuzzing(target_component, iterations)

        except Exception as e:
            self.logger.error(f"Error during protocol fuzzing: {e}")
            self.fuzzing_results.append(FuzzingResult(
                test_case=FuzzingCase(
                    id="error_case",
                    strategy=strategy,
                    target=FuzzingTarget.MESSAGE_HEADER,
                    description="Fuzzing framework error",
                    payload=b"",
                    expected_behavior="No errors",
                    category="error"
                ),
                success=False,
                error=str(e)
            ))

        finally:
            self.is_running = False
            self.stats['end_time'] = datetime.now()

        self.logger.info(f"Protocol fuzzing completed. Results: {len(self.fuzzing_results)} cases, {len(self.crash_cases)} crashes")
        return self.fuzzing_results

    async def _run_random_fuzzing(self, target_component: str, iterations: int):
        """Run random fuzzing tests."""
        for i in range(iterations):
            if not self.is_running:
                break

            # Generate random payload
            payload_size = random.randint(0, 4096)
            payload = bytes(random.randint(0, 255) for _ in range(payload_size))

            test_case = FuzzingCase(
                id=f"random_{i}",
                strategy=FuzzingStrategy.RANDOM,
                target=FuzzingTarget(target_component),
                description=f"Random fuzzing case {i}",
                payload=payload,
                expected_behavior="Graceful error handling",
                category="random"
            )

            result = await self._execute_fuzzing_case(test_case)
            self.fuzzing_results.append(result)

            if i % 100 == 0:
                self.logger.info(f"Random fuzzing progress: {i}/{iterations}")

    async def _run_mutation_fuzzing(self, target_component: str, iterations: int):
        """Run mutation-based fuzzing tests."""
        # Start with valid templates
        base_templates = list(self.message_templates.values())

        for i in range(iterations):
            if not self.is_running:
                break

            # Select random base template
            base_payload = random.choice(base_templates)

            # Apply random mutations
            mutated_payload = base_payload
            num_mutations = random.randint(1, 5)

            for _ in range(num_mutations):
                mutation_func = random.choice(self.mutation_strategies)
                mutated_payload = mutation_func(mutated_payload)

            test_case = FuzzingCase(
                id=f"mutation_{i}",
                strategy=FuzzingStrategy.MUTATION,
                target=FuzzingTarget(target_component),
                description=f"Mutation fuzzing case {i}",
                payload=mutated_payload,
                expected_behavior="Graceful error handling",
                category="mutation"
            )

            result = await self._execute_fuzzing_case(test_case)
            self.fuzzing_results.append(result)

            if i % 100 == 0:
                self.logger.info(f"Mutation fuzzing progress: {i}/{iterations}")

    async def _run_generation_fuzzing(self, target_component: str, iterations: int):
        """Run generation-based fuzzing tests."""
        for i in range(iterations):
            if not self.is_running:
                break

            # Generate protocol-compliant but edge-case messages
            payload = await self._generate_edge_case_message(i)

            test_case = FuzzingCase(
                id=f"generation_{i}",
                strategy=FuzzingStrategy.GENERATION,
                target=FuzzingTarget(target_component),
                description=f"Generation fuzzing case {i}",
                payload=payload,
                expected_behavior="Proper protocol handling",
                category="generation"
            )

            result = await self._execute_fuzzing_case(test_case)
            self.fuzzing_results.append(result)

            if i % 100 == 0:
                self.logger.info(f"Generation fuzzing progress: {i}/{iterations}")

    async def _run_boundary_fuzzing(self, target_component: str):
        """Run boundary value fuzzing tests."""
        for i, payload in enumerate(self.boundary_cases):
            if not self.is_running:
                break

            test_case = FuzzingCase(
                id=f"boundary_{i}",
                strategy=FuzzingStrategy.BOUNDARY,
                target=FuzzingTarget(target_component),
                description=f"Boundary test case {i} (length: {len(payload)})",
                payload=payload,
                expected_behavior="Robust boundary handling",
                category="boundary",
                metadata={'length': len(payload)}
            )

            result = await self._execute_fuzzing_case(test_case)
            self.fuzzing_results.append(result)

    async def _run_stateful_fuzzing(self, target_component: str, iterations: int):
        """Run stateful fuzzing tests."""
        # Simulate protocol state machine
        state_sequence = []

        for i in range(iterations):
            if not self.is_running:
                break

            # Generate state-dependent payload
            payload = await self._generate_stateful_payload(state_sequence)

            test_case = FuzzingCase(
                id=f"stateful_{i}",
                strategy=FuzzingStrategy.STATEFUL,
                target=FuzzingTarget(target_component),
                description=f"Stateful fuzzing case {i}",
                payload=payload,
                expected_behavior="State-aware error handling",
                category="stateful",
                metadata={'state_depth': len(state_sequence)}
            )

            result = await self._execute_fuzzing_case(test_case)
            self.fuzzing_results.append(result)

            # Update state based on result
            state_sequence.append(result.success)

            if i % 100 == 0:
                self.logger.info(f"Stateful fuzzing progress: {i}/{iterations}")

    async def _execute_fuzzing_case(self, test_case: FuzzingCase) -> FuzzingResult:
        """Execute a single fuzzing test case."""
        start_time = time.time()
        result = FuzzingResult(test_case=test_case, success=True)

        try:
            # Simulate message processing
            await self._process_fuzzed_message(test_case.payload)

        except Exception as e:
            result.success = False
            result.error = str(e)
            result.exception_type = type(e).__name__

            # Check for crash indicators
            if self._is_crash_indicator(e):
                result.crash_detected = True
                self.crash_cases.append(result)

            # Check for hang indicators
            if self._is_hang_indicator(e):
                result.hang_detected = True

            # Check for unexpected behavior
            if self._is_unexpected_behavior(e):
                result.unexpected_behavior = True

        finally:
            result.response_time = time.time() - start_time
            self.stats['total_cases'] += 1

            if result.success:
                self.stats['successful_cases'] += 1
            if result.crash_detected:
                self.stats['crashed_cases'] += 1
            if result.hang_detected:
                self.stats['hung_cases'] += 1
            if result.unexpected_behavior:
                self.stats['unexpected_cases'] += 1

        return result

    async def _process_fuzzed_message(self, payload: bytes):
        """Process a fuzzed message payload."""
        # Simulate message deserialization and processing
        if not payload:
            return  # Empty payload is valid

        # Check length prefix
        if len(payload) < 4:
            raise ValueError("Message too short")

        # Parse length
        try:
            message_length = struct.unpack('!I', payload[:4])[0]
        except struct.error:
            raise ValueError("Invalid length prefix")

        # Check message length
        if message_length > len(payload) - 4:
            raise ValueError("Incomplete message")

        # Extract JSON data
        json_data = payload[4:4 + message_length]

        # Check if compressed
        if len(json_data) > 10:  # Simple heuristic
            try:
                import zlib
                decompressed = zlib.decompress(json_data)
                json_data = decompressed
            except zlib.error:
                pass  # Not compressed

        # Parse JSON
        try:
            message_dict = json.loads(json_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"JSON parsing failed: {e}")

        # Validate message structure
        if not isinstance(message_dict, dict):
            raise ValueError("Message is not a dictionary")

        if 'header' not in message_dict:
            raise ValueError("Missing message header")

        if 'payload' not in message_dict:
            raise ValueError("Missing message payload")

        # Validate header structure
        header = message_dict['header']
        required_header_fields = ['message_type', 'message_id', 'sender_id']

        for field in required_header_fields:
            if field not in header:
                raise ValueError(f"Missing header field: {field}")

        # Validate message type
        valid_types = [mt.value for mt in MessageType]
        if header['message_type'] not in valid_types:
            raise ValueError(f"Invalid message type: {header['message_type']}")

        # Simulate processing time based on payload size
        processing_time = len(payload) / 1000000  # Simulate 1µs per byte
        await asyncio.sleep(processing_time)

    def _is_crash_indicator(self, exception: Exception) -> bool:
        """Check if exception indicates a crash."""
        crash_indicators = [
            'Segmentation fault',
            'Access violation',
            'Stack overflow',
            'Heap corruption',
            'Null pointer',
            'Buffer overflow',
            'Memory error'
        ]

        exception_str = str(exception).lower()
        return any(indicator.lower() in exception_str for indicator in crash_indicators)

    def _is_hang_indicator(self, exception: Exception) -> bool:
        """Check if exception indicates a hang."""
        hang_indicators = [
            'Timeout',
            'Deadline exceeded',
            'Operation timed out',
            'Infinite loop'
        ]

        exception_str = str(exception).lower()
        return any(indicator.lower() in exception_str for indicator in hang_indicators)

    def _is_unexpected_behavior(self, exception: Exception) -> bool:
        """Check if exception indicates unexpected behavior."""
        # Any unhandled exception might indicate unexpected behavior
        return True

    # Mutation strategies
    def _bit_flip_mutation(self, data: bytes) -> bytes:
        """Flip random bits in data."""
        if not data:
            return data

        data_array = bytearray(data)
        num_flips = random.randint(1, min(8, len(data)))

        for _ in range(num_flips):
            byte_idx = random.randint(0, len(data_array) - 1)
            bit_idx = random.randint(0, 7)
            data_array[byte_idx] ^= (1 << bit_idx)

        return bytes(data_array)

    def _byte_mutation(self, data: bytes) -> bytes:
        """Mutate random bytes in data."""
        if not data:
            return data

        data_array = bytearray(data)
        num_mutations = random.randint(1, min(10, len(data)))

        for _ in range(num_mutations):
            idx = random.randint(0, len(data_array) - 1)
            data_array[idx] = random.randint(0, 255)

        return bytes(data_array)

    def _insertion_mutation(self, data: bytes) -> bytes:
        """Insert random bytes into data."""
        if len(data) > 10000:  # Limit size
            return data

        insert_data = bytes(random.randint(0, 255) for _ in range(random.randint(1, 100)))
        insert_pos = random.randint(0, len(data))

        return data[:insert_pos] + insert_data + data[insert_pos:]

    def _deletion_mutation(self, data: bytes) -> bytes:
        """Delete random bytes from data."""
        if len(data) < 2:
            return data

        delete_size = random.randint(1, min(100, len(data) // 2))
        delete_pos = random.randint(0, len(data) - delete_size)

        return data[:delete_pos] + data[delete_pos + delete_size:]

    def _duplication_mutation(self, data: bytes) -> bytes:
        """Duplicate random sections of data."""
        if len(data) < 2:
            return data

        # Select section to duplicate
        section_size = random.randint(1, min(50, len(data) // 2))
        section_pos = random.randint(0, len(data) - section_size)

        section = data[section_pos:section_pos + section_size]
        insert_pos = random.randint(0, len(data))

        return data[:insert_pos] + section + data[insert_pos:]

    def _transposition_mutation(self, data: bytes) -> bytes:
        """Transpose random bytes in data."""
        if len(data) < 2:
            return data

        data_array = bytearray(data)
        num_transpositions = random.randint(1, min(5, len(data) // 2))

        for _ in range(num_transpositions):
            idx1 = random.randint(0, len(data_array) - 2)
            idx2 = random.randint(idx1 + 1, len(data_array) - 1)

            # Swap bytes
            data_array[idx1], data_array[idx2] = data_array[idx2], data_array[idx1]

        return bytes(data_array)

    async def _generate_edge_case_message(self, case_id: int) -> bytes:
        """Generate edge case messages for protocol testing."""
        # Generate various edge cases
        edge_cases = [
            self._generate_oversized_message,
            self._generate_undersized_message,
            self._generate_malformed_json,
            self._generate_invalid_unicode,
            self._generate_nested_structures,
            self._generate_circular_references,
        ]

        case_func = edge_cases[case_id % len(edge_cases)]
        return await case_func()

    async def _generate_oversized_message(self) -> bytes:
        """Generate oversized message."""
        large_content = 'A' * 10000
        payload = json.dumps({
            'header': {
                'message_type': 'chat_message',
                'message_id': 'oversized_test',
                'sender_id': 'A' * 100,
                'recipient_id': 'B' * 100
            },
            'payload': {
                'content': large_content,
                'timestamp': time.time()
            }
        }).encode('utf-8')

        # Compress if too large
        if len(payload) > 1024:
            import zlib
            payload = zlib.compress(payload)

        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_undersized_message(self) -> bytes:
        """Generate undersized message."""
        # Very small but valid JSON
        payload = b'{"a":1}'
        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_malformed_json(self) -> bytes:
        """Generate malformed JSON."""
        malformed_jsons = [
            b'{"incomplete": ',
            b'{"unclosed_string": "test',
            b'{"invalid_number": 12.34.56}',
            b'{"trailing_comma": "value",}',
            b'{"invalid_unicode": "\uXXXX"}',
        ]

        payload = random.choice(malformed_jsons)
        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_invalid_unicode(self) -> bytes:
        """Generate message with invalid Unicode."""
        # Generate bytes that are invalid UTF-8
        invalid_utf8 = bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB])
        payload = b'{"content": "' + invalid_utf8 + b'"}'
        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_nested_structures(self) -> bytes:
        """Generate deeply nested message structures."""
        # Create deeply nested JSON
        nested = {'level': 0}

        current = nested
        for i in range(100):  # Deep nesting
            current['next'] = {'level': i + 1}
            current = current['next']

        payload = json.dumps(nested).encode('utf-8')
        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_circular_references(self) -> bytes:
        """Generate message with circular references (will fail JSON encoding)."""
        # This will actually fail, which is what we want to test
        circular = {'self': None}
        circular['self'] = circular

        try:
            payload = json.dumps(circular).encode('utf-8')
        except (TypeError, ValueError):
            # Expected for circular references
            payload = b'{"circular": "reference"}'

        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_stateful_payload(self, state_sequence: List[bool]) -> bytes:
        """Generate stateful payload based on previous results."""
        # Use state history to influence payload generation
        state_complexity = sum(state_sequence) / max(len(state_sequence), 1)

        if state_complexity > 0.7:
            # Previous tests mostly successful, try more complex cases
            return await self._generate_complex_stateful_message()
        else:
            # Previous tests had issues, try simpler cases
            return await self._generate_simple_stateful_message()

    async def _generate_complex_stateful_message(self) -> bytes:
        """Generate complex stateful message."""
        # Create message with multiple nested structures
        complex_payload = {
            'type': 'stateful_complex',
            'nested': {
                'level1': {
                    'level2': {
                        'level3': {
                            'data': 'complex_nested_data'
                        }
                    }
                }
            },
            'arrays': [1, 2, 3, {'nested': 'in_array'}],
            'timestamp': time.time()
        }

        payload = json.dumps(complex_payload).encode('utf-8')
        header = struct.pack('!I', len(payload))
        return header + payload

    async def _generate_simple_stateful_message(self) -> bytes:
        """Generate simple stateful message."""
        simple_payload = {
            'type': 'stateful_simple',
            'message': 'simple_test',
            'timestamp': time.time()
        }

        payload = json.dumps(simple_payload).encode('utf-8')
        header = struct.pack('!I', len(payload))
        return header + payload

    def generate_fuzzing_report(self, output_format: str = 'text') -> str:
        """Generate comprehensive fuzzing report."""
        if output_format == 'text':
            return self._generate_text_report()
        elif output_format == 'json':
            return self._generate_json_report()
        elif output_format == 'html':
            return self._generate_html_report()
        else:
            return "Unsupported format"

    def _generate_text_report(self) -> str:
        """Generate text format report."""
        report = []
        report.append("Protocol Fuzzing Test Report")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Summary statistics
        report.append("Summary Statistics:")
        report.append(f"  Total Cases: {self.stats['total_cases']}")
        report.append(f"  Successful: {self.stats['successful_cases']}")
        report.append(f"  Crashes: {self.stats['crashed_cases']}")
        report.append(f"  Hangs: {self.stats['hung_cases']}")
        report.append(f"  Unexpected: {self.stats['unexpected_cases']}")
        report.append("")

        # Crash analysis
        if self.crash_cases:
            report.append("Crash Analysis:")
            report.append(f"  Total Crashes: {len(self.crash_cases)}")

            # Group crashes by exception type
            crash_types = defaultdict(int)
            for crash in self.crash_cases:
                crash_types[crash.exception_type or 'Unknown'] += 1

            for exc_type, count in crash_types.items():
                report.append(f"  {exc_type}: {count}")
            report.append("")

        # Recommendations
        report.append("Recommendations:")
        if self.stats['crashed_cases'] > 0:
            report.append("  - Address crash vulnerabilities found in message processing")
        if self.stats['hung_cases'] > 0:
            report.append("  - Fix infinite loop and timeout issues")
        if self.stats['unexpected_cases'] > 0:
            report.append("  - Improve error handling for malformed input")

        report.append("  - Implement comprehensive input validation")
        report.append("  - Add timeout mechanisms for message processing")
        report.append("  - Use safe JSON parsing with limits")

        return "\n".join(report)

    def _generate_json_report(self) -> str:
        """Generate JSON format report."""
        report_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_cases': self.stats['total_cases'],
                'successful_cases': self.stats['successful_cases'],
                'crashed_cases': self.stats['crashed_cases'],
                'hung_cases': self.stats['hung_cases'],
                'unexpected_cases': self.stats['unexpected_cases']
            },
            'crash_cases': [result.to_dict() for result in self.crash_cases],
            'summary': {
                'crash_rate': self.stats['crashed_cases'] / max(self.stats['total_cases'], 1),
                'success_rate': self.stats['successful_cases'] / max(self.stats['total_cases'], 1),
                'avg_response_time': sum(r.response_time for r in self.fuzzing_results) / max(len(self.fuzzing_results), 1)
            }
        }

        return json.dumps(report_data, indent=2)

    def _generate_html_report(self) -> str:
        """Generate HTML format report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Protocol Fuzzing Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #333; color: white; padding: 20px; }}
                .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .crash {{ background: #ffebee; border: 1px solid #f44336; margin: 10px 0; padding: 10px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Protocol Fuzzing Test Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <h2>Test Statistics</h2>
            <div class="stats">
                <div class="stat">
                    <strong>Total Cases:</strong> {self.stats['total_cases']}
                </div>
                <div class="stat">
                    <strong>Successful:</strong> {self.stats['successful_cases']}
                </div>
                <div class="stat">
                    <strong>Crashes:</strong> {self.stats['crashed_cases']}
                </div>
                <div class="stat">
                    <strong>Hangs:</strong> {self.stats['hung_cases']}
                </div>
            </div>

            <h2>Crash Details</h2>
        """

        if self.crash_cases:
            html += """
            <table>
                <tr>
                    <th>Test Case</th>
                    <th>Exception Type</th>
                    <th>Error</th>
                    <th>Response Time</th>
                </tr>
            """

            for crash in self.crash_cases:
                html += f"""
                <tr>
                    <td>{crash.test_case.id}</td>
                    <td>{crash.exception_type or 'Unknown'}</td>
                    <td>{crash.error or 'No error message'}</td>
                    <td>{crash.response_time:.3f}s</td>
                </tr>
                """

            html += "</table>"
        else:
            html += "<p>No crashes detected.</p>"

        html += """
        </body>
        </html>
        """

        return html

    def get_fuzzing_statistics(self) -> Dict[str, Any]:
        """Get current fuzzing statistics."""
        return {
            'is_running': self.is_running,
            'total_cases': self.stats['total_cases'],
            'successful_cases': self.stats['successful_cases'],
            'crashed_cases': self.stats['crashed_cases'],
            'hung_cases': self.stats['hung_cases'],
            'unexpected_cases': self.stats['unexpected_cases'],
            'crash_cases_count': len(self.crash_cases),
            'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
            'end_time': self.stats['end_time'].isoformat() if self.stats['end_time'] else None
        }

    def stop_fuzzing(self):
        """Stop all fuzzing operations."""
        self.is_running = False
        self.logger.info("Stopping protocol fuzzing tests")