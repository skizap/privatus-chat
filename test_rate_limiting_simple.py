#!/usr/bin/env python3
"""
Simple test script to verify rate limiting functionality
"""

import asyncio
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from network.connection_manager import (
    RateLimiter, RateLimitConfig, SecurityLevel,
    ConnectionFailureType
)


async def test_basic_rate_limiting():
    """Test basic rate limiting functionality"""
    print("Testing basic rate limiting...")

    config = RateLimitConfig(security_level=SecurityLevel.LOW)
    rate_limiter = RateLimiter(config)
    await rate_limiter.start()

    try:
        test_ip = "192.168.1.100"

        # Test multiple successful connections
        for i in range(30):
            can_connect, wait_time = await rate_limiter.can_attempt_connection(test_ip)
            if can_connect:
                await rate_limiter.record_connection_attempt(test_ip, success=True)
                print(f"Connection {i+1}: Allowed")
            else:
                print(f"Connection {i+1}: Rate limited after {wait_time:.1f}s")
                break

        # Test failure tracking
        print("\nTesting failure tracking...")
        for i in range(3):
            await rate_limiter.record_connection_attempt(
                test_ip, success=False, failure_type=ConnectionFailureType.TIMEOUT
            )
            stats = await rate_limiter.get_ip_stats(test_ip)
            print(f"After failure {i+1}: {stats['consecutive_failures']} consecutive failures")

        print("Basic rate limiting test completed successfully!")

    finally:
        await rate_limiter.stop()


async def test_security_levels():
    """Test different security levels"""
    print("\nTesting security levels...")

    for level in SecurityLevel:
        config = RateLimitConfig(security_level=level)
        print(f"{level.value}: {config.get_max_attempts_per_minute()} attempts/min, "
              f"backoff multiplier: {config.get_backoff_multiplier()}")

    print("Security levels test completed!")


async def main():
    """Run all tests"""
    print("Starting rate limiting tests...")

    await test_security_levels()
    await test_basic_rate_limiting()

    print("All tests completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())