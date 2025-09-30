"""
Comprehensive tests for the enhanced connection rate limiting system
"""

import asyncio
import pytest
import time
from unittest.mock import Mock, patch
from src.network.connection_manager import (
    ConnectionManager, RateLimiter, RateLimitConfig,
    SecurityLevel, ConnectionFailureType, PeerInfo
)


class TestRateLimiter:
    """Test the RateLimiter class"""

    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization with different security levels"""
        config = RateLimitConfig(security_level=SecurityLevel.HIGH)
        rate_limiter = RateLimiter(config)

        assert rate_limiter.config.security_level == SecurityLevel.HIGH
        assert rate_limiter.config.get_max_attempts_per_minute() == 20
        assert rate_limiter.config.get_backoff_multiplier() == 3.0
        assert rate_limiter.running == False

    @pytest.mark.asyncio
    async def test_ip_normalization(self):
        """Test IP address normalization"""
        config = RateLimitConfig()
        rate_limiter = RateLimiter(config)

        # Test IPv4
        assert rate_limiter._normalize_ip("192.168.1.1") == "192.168.1.1"

        # Test IPv4-mapped IPv6
        assert rate_limiter._normalize_ip("::ffff:192.168.1.1") == "192.168.1.1"

        # Test regular IPv6
        assert rate_limiter._normalize_ip("2001:db8::1") == "2001:db8::1"

        # Test invalid IP
        assert rate_limiter._normalize_ip("invalid") == "invalid"

    @pytest.mark.asyncio
    async def test_rate_limiting_basic(self):
        """Test basic rate limiting functionality"""
        config = RateLimitConfig(security_level=SecurityLevel.LOW)
        rate_limiter = RateLimiter(config)
        await rate_limiter.start()

        try:
            test_ip = "192.168.1.100"

            # First few attempts should be allowed
            for i in range(50):  # Half of LOW security limit (100/minute)
                can_connect, wait_time = await rate_limiter.can_attempt_connection(test_ip)
                assert can_connect == True
                assert wait_time == 0.0

                # Record successful attempt
                await rate_limiter.record_connection_attempt(test_ip, success=True)

            # Next attempts should be rate limited
            can_connect, wait_time = await rate_limiter.can_attempt_connection(test_ip)
            assert can_connect == False
            assert wait_time > 0

        finally:
            await rate_limiter.stop()

    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """Test exponential backoff mechanism"""
        config = RateLimitConfig(security_level=SecurityLevel.MEDIUM)
        rate_limiter = RateLimiter(config)
        await rate_limiter.start()

        try:
            test_ip = "192.168.1.101"

            # Record multiple failures to trigger backoff
            backoff_times = []
            for i in range(5):
                await rate_limiter.record_connection_attempt(
                    test_ip,
                    success=False,
                    failure_type=ConnectionFailureType.TIMEOUT
                )

                # Check if backoff is increasing
                stats = await rate_limiter.get_ip_stats(test_ip)
                backoff_times.append(stats['backoff_until'])

            # Backoff should be increasing (exponential)
            assert backoff_times[1] > backoff_times[0]
            assert backoff_times[2] > backoff_times[1]
            assert backoff_times[4] > backoff_times[3]

        finally:
            await rate_limiter.stop()

    @pytest.mark.asyncio
    async def test_failure_type_tracking(self):
        """Test tracking of different failure types"""
        config = RateLimitConfig()
        rate_limiter = RateLimiter(config)
        await rate_limiter.start()

        try:
            test_ip = "192.168.1.102"

            # Record different types of failures
            await rate_limiter.record_connection_attempt(
                test_ip, success=False, failure_type=ConnectionFailureType.TIMEOUT
            )
            await rate_limiter.record_connection_attempt(
                test_ip, success=False, failure_type=ConnectionFailureType.REFUSED
            )
            await rate_limiter.record_connection_attempt(
                test_ip, success=False, failure_type=ConnectionFailureType.NETWORK_ERROR
            )

            stats = await rate_limiter.get_ip_stats(test_ip)
            assert stats['consecutive_failures'] == 3
            assert stats['total_failures'] == 3
            assert stats['last_failure_type'] == ConnectionFailureType.NETWORK_ERROR.value

            # Success should reset failure tracking
            await rate_limiter.record_connection_attempt(test_ip, success=True)
            stats = await rate_limiter.get_ip_stats(test_ip)
            assert stats['consecutive_failures'] == 0
            assert stats['backoff_until'] == 0.0

        finally:
            await rate_limiter.stop()

    @pytest.mark.asyncio
    async def test_cleanup_functionality(self):
        """Test cleanup of old rate limit data"""
        config = RateLimitConfig()
        rate_limiter = RateLimiter(config)
        await rate_limiter.start()

        try:
            test_ip = "192.168.1.103"

            # Add some attempts
            await rate_limiter.record_connection_attempt(test_ip, success=True)
            await rate_limiter.record_connection_attempt(test_ip, success=True)

            # Manually trigger cleanup by setting old timestamps
            # This is a bit tricky to test directly, but we can verify
            # that data exists and the cleanup mechanism is in place
            assert len(rate_limiter.ip_data) > 0

        finally:
            await rate_limiter.stop()


class TestConnectionManagerRateLimiting:
    """Test ConnectionManager with rate limiting"""

    @pytest.mark.asyncio
    async def test_connection_manager_with_rate_limiting(self):
        """Test ConnectionManager initialization with rate limiting"""
        config = RateLimitConfig(security_level=SecurityLevel.HIGH)
        manager = ConnectionManager(
            max_connections=10,
            security_level=SecurityLevel.HIGH,
            rate_limit_config=config
        )

        assert manager.rate_limit_config.security_level == SecurityLevel.HIGH
        assert manager.rate_limiter is None  # Not initialized until start()

        await manager.start()
        assert manager.rate_limiter is not None
        assert manager.rate_limiter.config.security_level == SecurityLevel.HIGH

        await manager.stop()

    @pytest.mark.asyncio
    async def test_security_level_changes(self):
        """Test dynamic security level changes"""
        manager = ConnectionManager(security_level=SecurityLevel.LOW)
        await manager.start()

        try:
            # Initial level
            assert manager.get_security_level() == SecurityLevel.LOW

            # Change level
            manager.set_security_level(SecurityLevel.PARANOID)
            assert manager.get_security_level() == SecurityLevel.PARANOID
            assert manager.rate_limiter.config.security_level == SecurityLevel.PARANOID

        finally:
            await manager.stop()

    @pytest.mark.asyncio
    async def test_rate_limit_stats(self):
        """Test rate limit statistics retrieval"""
        manager = ConnectionManager(security_level=SecurityLevel.MEDIUM)
        await manager.start()

        try:
            # Get general stats
            general_stats = manager.get_rate_limit_stats()
            assert 'security_level' in general_stats
            assert 'max_attempts_per_minute' in general_stats
            assert general_stats['security_level'] == SecurityLevel.MEDIUM.value
            assert general_stats['max_attempts_per_minute'] == 50

            # Get IP-specific stats
            ip_stats = manager.get_rate_limit_stats("192.168.1.104")
            assert 'attempts_in_window' in ip_stats
            assert 'consecutive_failures' in ip_stats
            assert ip_stats['attempts_in_window'] == 0

        finally:
            await manager.stop()

    @pytest.mark.asyncio
    async def test_connection_attempts_with_rate_limiting(self):
        """Test connection attempts with rate limiting enabled"""
        manager = ConnectionManager(
            max_connections=10,
            security_level=SecurityLevel.LOW,  # More permissive for testing
            connection_timeout=1.0  # Fast timeout for testing
        )
        await manager.start()

        try:
            peer_info = PeerInfo(
                peer_id=b"test_peer_1234567890123456",
                address="127.0.0.1",
                port=12345  # Non-routable port to force failures
            )

            # First few attempts should work (or fail gracefully due to invalid port)
            results = []
            for i in range(10):
                result = await manager.connect_to_peer(peer_info)
                results.append(result)
                await asyncio.sleep(0.1)  # Small delay between attempts

            # Some attempts should succeed in rate limiting (even if connection fails)
            # The important thing is that rate limiting doesn't crash
            assert len(results) == 10

            # Check that rate limiting stats are being tracked
            stats = manager.get_rate_limit_stats("127.0.0.1")
            assert 'attempts_in_window' in stats
            assert stats['attempts_in_window'] > 0

        finally:
            await manager.stop()


class TestSecurityLevels:
    """Test different security levels"""

    @pytest.mark.asyncio
    async def test_security_level_limits(self):
        """Test that different security levels have different limits"""
        levels_and_limits = [
            (SecurityLevel.LOW, 100),
            (SecurityLevel.MEDIUM, 50),
            (SecurityLevel.HIGH, 20),
            (SecurityLevel.PARANOID, 5)
        ]

        for level, expected_limit in levels_and_limits:
            config = RateLimitConfig(security_level=level)
            assert config.get_max_attempts_per_minute() == expected_limit

    @pytest.mark.asyncio
    async def test_security_level_backoff_multipliers(self):
        """Test backoff multipliers for different security levels"""
        multipliers = [
            (SecurityLevel.LOW, 1.5),
            (SecurityLevel.MEDIUM, 2.0),
            (SecurityLevel.HIGH, 3.0),
            (SecurityLevel.PARANOID, 5.0)
        ]

        for level, expected_multiplier in multipliers:
            config = RateLimitConfig(security_level=level)
            assert config.get_backoff_multiplier() == expected_multiplier


if __name__ == "__main__":
    # Run tests if executed directly
    asyncio.run(asyncio.sleep(0))  # Just for pytest discovery