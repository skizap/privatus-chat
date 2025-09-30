"""
Central Error Handler for Privatus-chat

Coordinates error handling, logging, user feedback, and recovery
mechanisms across the entire application.
"""

import asyncio
import functools
import inspect
import threading
from typing import Callable, Any, Dict, Optional, Union, TypeVar, List
from contextlib import contextmanager

from .exceptions import (
    PrivatusChatError, ErrorSeverity, ErrorCategory,
    NetworkError, CryptoError, StorageError, GUIError
)
from .retry_manager import RetryManager, RetryConfig, network_retry_manager, storage_retry_manager
from .secure_logger import secure_logger
from .user_feedback import get_feedback_manager

T = TypeVar('T')


class ErrorHandler:
    """
    Central error handling system for Privatus-chat.

    Provides unified error handling, logging, user feedback, and recovery
    mechanisms with security considerations.
    """

    def __init__(self):
        """Initialize error handler."""
        self.retry_managers = {
            'network': network_retry_manager,
            'storage': storage_retry_manager,
            'crypto': RetryManager(RetryConfig(max_attempts=1))  # No retries for crypto
        }

        # Error statistics for monitoring
        self.error_stats = {
            'total_errors': 0,
            'errors_by_category': {},
            'errors_by_severity': {},
            'recent_errors': []
        }

        # Recovery handlers for different error types
        self.recovery_handlers = {}
        self._setup_default_recovery_handlers()

    def _setup_default_recovery_handlers(self):
        """Setup default recovery handlers for common error types."""
        self.recovery_handlers = {
            ErrorCategory.NETWORK: self._handle_network_error,
            ErrorCategory.STORAGE: self._handle_storage_error,
            ErrorCategory.CRYPTOGRAPHY: self._handle_crypto_error,
            ErrorCategory.GUI: self._handle_gui_error,
            ErrorCategory.AUTHENTICATION: self._handle_authentication_error,
            ErrorCategory.VALIDATION: self._handle_validation_error,
            ErrorCategory.CONFIGURATION: self._handle_configuration_error,
        }

    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        operation_name: str = "unknown_operation",
        show_user_feedback: bool = True,
        retryable: Optional[bool] = None
    ) -> bool:
        """
        Handle an error with full error handling pipeline.

        Args:
            error: Exception that occurred
            context: Additional context information
            operation_name: Name of the operation that failed
            show_user_feedback: Whether to show user feedback dialog
            retryable: Whether error should be retried (auto-detected if None)

        Returns:
            True if error was handled successfully, False otherwise
        """
        # Update error statistics
        self._update_error_stats(error)

        # Log the error
        secure_logger.log_error(error, {
            'operation': operation_name,
            'context': context,
            'thread': threading.current_thread().name,
            'handled': True
        })

        # Determine if error is retryable
        if retryable is None:
            retryable = self._is_retryable_error(error)

        # Get appropriate retry manager
        retry_manager = self._get_retry_manager(error)

        # Attempt recovery if applicable
        recovery_success = False
        if retryable and retry_manager:
            recovery_success = self._attempt_recovery(error, retry_manager, operation_name, context)

        # Show user feedback if requested
        if show_user_feedback:
            self._show_user_feedback(error, context, operation_name, recovery_success)

        # Return whether error was handled (either recovered or user acknowledged)
        return recovery_success or not show_user_feedback

    def _update_error_stats(self, error: Exception):
        """Update error statistics for monitoring."""
        self.error_stats['total_errors'] += 1

        # Update by category
        if isinstance(error, PrivatusChatError):
            category = error.category.value
            self.error_stats['errors_by_category'][category] = (
                self.error_stats['errors_by_category'].get(category, 0) + 1
            )

            severity = error.severity.value
            self.error_stats['errors_by_severity'][severity] = (
                self.error_stats['errors_by_severity'].get(severity, 0) + 1
            )

        # Track recent errors (keep last 100)
        error_entry = {
            'timestamp': asyncio.get_event_loop().time(),
            'error_type': type(error).__name__,
            'error_message': str(error),
            'category': getattr(error, 'category', ErrorCategory.SYSTEM).value if hasattr(error, 'category') else 'system'
        }
        self.error_stats['recent_errors'].append(error_entry)
        if len(self.error_stats['recent_errors']) > 100:
            self.error_stats['recent_errors'] = self.error_stats['recent_errors'][-100:]

    def _is_retryable_error(self, error: Exception) -> bool:
        """Determine if an error should be retried."""
        # PrivatusChatError with TransientError base is always retryable
        if isinstance(error, PrivatusChatError):
            return error.recoverable

        # Network-related errors are usually retryable
        if isinstance(error, (ConnectionError, TimeoutError, OSError)):
            return True

        # Check error message for retryable patterns
        retryable_patterns = [
            'timeout', 'connection reset', 'temporary failure',
            'service unavailable', 'rate limit', 'too many requests'
        ]

        return any(pattern in str(error).lower() for pattern in retryable_patterns)

    def _get_retry_manager(self, error: Exception) -> Optional[RetryManager]:
        """Get appropriate retry manager for error type."""
        if isinstance(error, NetworkError):
            return self.retry_managers['network']
        elif isinstance(error, StorageError):
            return self.retry_managers['storage']
        elif isinstance(error, CryptoError):
            return self.retry_managers['crypto']
        else:
            # Use network retry manager as default for unknown types
            return self.retry_managers['network']

    def _attempt_recovery(
        self,
        error: Exception,
        retry_manager: RetryManager,
        operation_name: str,
        context: Optional[Dict]
    ) -> bool:
        """Attempt to recover from error using retry mechanism."""
        try:
            # This would need to be implemented with actual operation context
            # For now, just log the attempt
            secure_logger.info(f"Attempting recovery for {operation_name} error: {type(error).__name__}")
            return False
        except Exception as e:
            secure_logger.error(f"Recovery attempt failed: {e}")
            return False

    def _show_user_feedback(
        self,
        error: Exception,
        context: Optional[Dict],
        operation_name: str,
        recovery_success: bool
    ):
        """Show appropriate user feedback for the error."""
        try:
            # Use the feedback manager to show error dialog
            feedback_mgr = get_feedback_manager()
            user_choice = feedback_mgr.show_error(error, {
                'operation': operation_name,
                'context': context,
                'recovery_success': recovery_success
            })

            # Handle user response
            if user_choice == 'retry':
                # User requested retry - this would need to be handled by caller
                pass
            elif user_choice == 'help':
                # User requested help - emit signal
                feedback_mgr.help_requested.emit(
                    feedback_mgr._get_help_topic(
                        error.category if hasattr(error, 'category') else ErrorCategory.SYSTEM
                    )
                )

        except Exception as e:
            # Fallback if feedback manager fails
            secure_logger.error(f"Failed to show user feedback: {e}")

    def _handle_network_error(self, error: NetworkError, context: Optional[Dict]) -> bool:
        """Handle network-specific errors."""
        secure_logger.log_security_event("Network error occurred", {
            'error_type': type(error).__name__,
            'context': context
        })
        return True

    def _handle_storage_error(self, error: StorageError, context: Optional[Dict]) -> bool:
        """Handle storage-specific errors."""
        secure_logger.warning(f"Storage error: {error}")
        return True

    def _handle_crypto_error(self, error: CryptoError, context: Optional[Dict]) -> bool:
        """Handle cryptography-specific errors."""
        secure_logger.log_security_event("Cryptographic error occurred", {
            'error_type': type(error).__name__,
            'context': context
        })
        return True

    def _handle_gui_error(self, error: GUIError, context: Optional[Dict]) -> bool:
        """Handle GUI-specific errors."""
        secure_logger.info(f"GUI error: {error}")
        return True

    def _handle_authentication_error(self, error: Exception, context: Optional[Dict]) -> bool:
        """Handle authentication-specific errors."""
        secure_logger.log_security_event("Authentication error occurred", {
            'error_type': type(error).__name__,
            'context': context
        })
        return True

    def _handle_validation_error(self, error: Exception, context: Optional[Dict]) -> bool:
        """Handle validation-specific errors."""
        secure_logger.info(f"Validation error: {error}")
        return True

    def _handle_configuration_error(self, error: Exception, context: Optional[Dict]) -> bool:
        """Handle configuration-specific errors."""
        secure_logger.warning(f"Configuration error: {error}")
        return True

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring."""
        return self.error_stats.copy()

    def clear_error_statistics(self):
        """Clear error statistics."""
        self.error_stats = {
            'total_errors': 0,
            'errors_by_category': {},
            'errors_by_severity': {},
            'recent_errors': []
        }


# Decorator for automatic error handling
def handle_errors(
    operation_name: str = "operation",
    show_user_feedback: bool = True,
    retryable: Optional[bool] = None,
    context: Optional[Dict] = None
):
    """
    Decorator for automatic error handling.

    Args:
        operation_name: Name of the operation for logging
        show_user_feedback: Whether to show user feedback on error
        retryable: Whether operation should be retried on failure
        context: Additional context for error handling
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_handler.handle_error(
                    e,
                    context=context,
                    operation_name=operation_name,
                    show_user_feedback=show_user_feedback,
                    retryable=retryable
                )
                raise  # Re-raise after handling

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                error_handler.handle_error(
                    e,
                    context=context,
                    operation_name=operation_name,
                    show_user_feedback=show_user_feedback,
                    retryable=retryable
                )
                raise  # Re-raise after handling

        # Return appropriate wrapper based on whether function is async
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper

    return decorator


# Context manager for error handling
@contextmanager
def error_handling_context(
    operation_name: str = "operation",
    show_user_feedback: bool = True,
    context: Optional[Dict] = None
):
    """
    Context manager for error handling.

    Usage:
        with error_handling_context("database_operation"):
            # Your code here
            pass
    """
    try:
        yield
    except Exception as e:
        error_handler.handle_error(
            e,
            context=context,
            operation_name=operation_name,
            show_user_feedback=show_user_feedback
        )
        raise


# Global error handler instance
error_handler = ErrorHandler()


# Convenience functions for common error types
def handle_gui_error(error: Exception, context: Optional[Dict] = None) -> None:
    """Handle GUI-specific errors."""
    gui_error = GUIError(str(error), context=context)
    error_handler.handle_error(gui_error, context, "gui_operation")


def handle_network_error(error: Exception, context: Optional[Dict] = None) -> None:
    """Handle network-specific errors."""
    network_error = NetworkError(str(error), context=context)
    error_handler.handle_error(network_error, context, "network_operation")


def handle_crypto_error(error: Exception, context: Optional[Dict] = None) -> None:
    """Handle cryptography-specific errors."""
    crypto_error = CryptoError(str(error), context=context)
    error_handler.handle_error(crypto_error, context, "crypto_operation")


def handle_storage_error(error: Exception, context: Optional[Dict] = None) -> None:
    """Handle storage-specific errors."""
    storage_error = StorageError(str(error), context=context)
    error_handler.handle_error(storage_error, context, "storage_operation")