"""
Retry Manager for Privatus-chat

Provides intelligent retry mechanisms for transient failures with
exponential backoff, jitter, and circuit breaker patterns.
"""

import asyncio
import random
import time
import logging
from dataclasses import dataclass, field
from typing import Callable, Any, Dict, Optional, Union, List
from enum import Enum

from .exceptions import TransientError, ErrorSeverity


class RetryStrategy(Enum):
    """Retry strategies for different types of operations."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_DELAY = "fixed_delay"
    IMMEDIATE = "immediate"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    jitter: bool = True
    backoff_multiplier: float = 2.0

    # Circuit breaker settings
    circuit_breaker_enabled: bool = True
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: float = 300.0  # 5 minutes

    # Retryable error types
    retryable_errors: List[type] = field(default_factory=list)

    def __post_init__(self):
        """Set default retryable errors if none specified."""
        if not self.retryable_errors:
            self.retryable_errors = [
                ConnectionError,
                TimeoutError,
                OSError,  # Covers network-related OS errors
                TransientError
            ]


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"     # Failing, requests rejected
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker implementation to prevent cascade failures."""

    def __init__(self, config: RetryConfig):
        self.config = config
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt a reset."""
        if self.last_failure_time is None:
            return True

        elapsed = time.time() - self.last_failure_time
        return elapsed >= self.config.circuit_breaker_recovery_timeout

    def record_success(self):
        """Record a successful operation."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            self.failure_count = 0

    def record_failure(self):
        """Record a failed operation."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if (self.state == CircuitBreakerState.CLOSED and
            self.failure_count >= self.config.circuit_breaker_failure_threshold):
            self.state = CircuitBreakerState.OPEN
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN

    def can_attempt(self) -> bool:
        """Check if a request can be attempted."""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
                return True
            return False
        else:  # HALF_OPEN
            return True


class RetryManager:
    """
    Manages retry logic for operations that may fail transiently.

    Provides intelligent retry mechanisms with exponential backoff,
    circuit breaker patterns, and proper error classification.
    """

    def __init__(self, config: Optional[RetryConfig] = None):
        """Initialize retry manager with configuration."""
        self.config = config or RetryConfig()
        self.circuit_breaker = CircuitBreaker(self.config) if self.config.circuit_breaker_enabled else None
        self.logger = logging.getLogger(__name__)

    def _is_retryable_error(self, error: Exception) -> bool:
        """Check if an error should be retried."""
        # Check if error is in retryable types
        for retryable_type in self.config.retryable_errors:
            if isinstance(error, retryable_type):
                return True

        # Check for specific error message patterns
        retryable_patterns = [
            'timeout',
            'connection reset',
            'temporary failure',
            'service unavailable',
            'rate limit',
            'too many requests'
        ]

        error_msg = str(error).lower()
        return any(pattern in error_msg for pattern in retryable_patterns)

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for current attempt."""
        if self.config.strategy == RetryStrategy.IMMEDIATE:
            return 0.0
        elif self.config.strategy == RetryStrategy.FIXED_DELAY:
            delay = self.config.base_delay
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay * attempt
        else:  # EXPONENTIAL_BACKOFF
            delay = self.config.base_delay * (self.config.backoff_multiplier ** (attempt - 1))

        # Apply maximum delay limit
        delay = min(delay, self.config.max_delay)

        # Add jitter to prevent thundering herd
        if self.config.jitter:
            jitter_amount = delay * 0.1  # 10% jitter
            jitter = random.uniform(-jitter_amount, jitter_amount)
            delay += jitter

        return max(0.0, delay)

    def _execute_with_retry_sync(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic (synchronous)."""
        last_error = None

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Check circuit breaker
                if self.circuit_breaker and not self.circuit_breaker.can_attempt():
                    raise TransientError(
                        f"Circuit breaker is OPEN. Too many failures. "
                        f"Try again in {self.config.circuit_breaker_recovery_timeout} seconds."
                    )

                # Execute the function
                result = func(*args, **kwargs)

                # Record success
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                return result

            except Exception as e:
                last_error = e

                # Check if error is retryable
                if not self._is_retryable_error(e):
                    self.logger.debug(f"Error not retryable: {e}")
                    raise

                # Record failure for circuit breaker
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()

                # If this is the last attempt, raise the error
                if attempt == self.config.max_attempts:
                    self.logger.warning(f"Operation failed after {self.config.max_attempts} attempts: {e}")
                    raise

                # Calculate delay and wait
                delay = self._calculate_delay(attempt)
                self.logger.info(f"Attempt {attempt} failed: {e}. Retrying in {delay:.2f}s...")
                time.sleep(delay)

        # Should never reach here, but just in case
        if last_error:
            raise last_error

    async def _execute_with_retry_async(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic (asynchronous)."""
        last_error = None

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Check circuit breaker
                if self.circuit_breaker and not self.circuit_breaker.can_attempt():
                    raise TransientError(
                        f"Circuit breaker is OPEN. Too many failures. "
                        f"Try again in {self.config.circuit_breaker_recovery_timeout} seconds."
                    )

                # Execute the function
                result = await func(*args, **kwargs)

                # Record success
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()

                return result

            except Exception as e:
                last_error = e

                # Check if error is retryable
                if not self._is_retryable_error(e):
                    self.logger.debug(f"Error not retryable: {e}")
                    raise

                # Record failure for circuit breaker
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()

                # If this is the last attempt, raise the error
                if attempt == self.config.max_attempts:
                    self.logger.warning(f"Operation failed after {self.config.max_attempts} attempts: {e}")
                    raise

                # Calculate delay and wait
                delay = self._calculate_delay(attempt)
                self.logger.info(f"Attempt {attempt} failed: {e}. Retrying in {delay:.2f}s...")
                await asyncio.sleep(delay)

        # Should never reach here, but just in case
        if last_error:
            raise last_error

    def execute_with_retry(
        self,
        func: Callable,
        *args,
        is_async: bool = False,
        **kwargs
    ) -> Any:
        """
        Execute a function with retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments for the function
            is_async: Whether the function is asynchronous
            **kwargs: Keyword arguments for the function

        Returns:
            Function result on success

        Raises:
            Last exception encountered if all retries fail
        """
        if is_async:
            return self._execute_with_retry_async(func, *args, **kwargs)
        else:
            return self._execute_with_retry_sync(func, *args, **kwargs)

    def create_retry_config(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
        **kwargs
    ) -> RetryConfig:
        """Create a retry configuration with custom settings."""
        return RetryConfig(
            max_attempts=max_attempts,
            base_delay=base_delay,
            strategy=strategy,
            **kwargs
        )

    def get_circuit_breaker_status(self) -> Dict:
        """Get circuit breaker status information."""
        if not self.circuit_breaker:
            return {'enabled': False}

        return {
            'enabled': True,
            'state': self.circuit_breaker.state.value,
            'failure_count': self.circuit_breaker.failure_count,
            'last_failure_time': self.circuit_breaker.last_failure_time,
            'can_attempt': self.circuit_breaker.can_attempt()
        }


# Global retry manager instances for different operation types
network_retry_manager = RetryManager(RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=30.0,
    strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
    circuit_breaker_enabled=True,
    circuit_breaker_failure_threshold=3,
    circuit_breaker_recovery_timeout=60.0
))

storage_retry_manager = RetryManager(RetryConfig(
    max_attempts=2,
    base_delay=0.5,
    max_delay=10.0,
    strategy=RetryStrategy.LINEAR_BACKOFF,
    circuit_breaker_enabled=True,
    circuit_breaker_failure_threshold=2,
    circuit_breaker_recovery_timeout=30.0
))

crypto_retry_manager = RetryManager(RetryConfig(
    max_attempts=1,  # Crypto operations should not be retried for security
    base_delay=0.0,
    strategy=RetryStrategy.IMMEDIATE,
    circuit_breaker_enabled=False  # Disable circuit breaker for crypto
))