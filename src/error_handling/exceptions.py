"""
Custom Exceptions for Privatus-chat

Defines all custom exception classes used throughout the application
with proper inheritance hierarchy and security considerations.
"""

from enum import Enum
from typing import Optional, Dict, Any


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification."""
    GUI = "gui"
    NETWORK = "network"
    CRYPTOGRAPHY = "cryptography"
    STORAGE = "storage"
    AUTHENTICATION = "authentication"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    USER_INPUT = "user_input"


class PrivatusChatError(Exception):
    """
    Base exception class for all Privatus-chat errors.

    Provides common functionality for error classification, logging,
    and user feedback while avoiding sensitive data exposure.
    """

    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        user_message: Optional[str] = None,
        recoverable: bool = True,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        Initialize Privatus-chat error.

        Args:
            message: Internal error message (not shown to user)
            severity: Error severity level
            category: Error category for classification
            user_message: User-friendly message (if None, auto-generated)
            recoverable: Whether the error can be recovered from
            context: Additional context data (sanitized for logging)
            cause: Original exception that caused this error
        """
        super().__init__(message)
        self.severity = severity
        self.category = category
        self.user_message = user_message or self._generate_user_message(message)
        self.recoverable = recoverable
        self.context = context or {}
        self.cause = cause
        self.error_id = id(self)

    def _generate_user_message(self, internal_message: str) -> str:
        """Generate user-friendly message from internal message."""
        # Remove sensitive information and provide generic but helpful messages
        if "key" in internal_message.lower() or "password" in internal_message.lower():
            return "A security-related operation failed. Please try again."
        elif "network" in internal_message.lower() or "connection" in internal_message.lower():
            return "Network operation failed. Please check your connection and try again."
        elif "storage" in internal_message.lower() or "database" in internal_message.lower():
            return "Data storage operation failed. Please try again."
        elif "encryption" in internal_message.lower() or "decryption" in internal_message.lower():
            return "Message encryption/decryption failed. Please try again."
        else:
            return "An operation failed. Please try again or contact support if the problem persists."

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging (without sensitive data)."""
        return {
            'error_id': self.error_id,
            'severity': self.severity.value,
            'category': self.category.value,
            'recoverable': self.recoverable,
            'context': self._sanitize_context(self.context),
            'cause_type': type(self.cause).__name__ if self.cause else None
        }

    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from context before logging."""
        sanitized = {}
        sensitive_keys = {'password', 'key', 'token', 'secret', 'private', 'credential'}

        for key, value in context.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value

        return sanitized


class GUIError(PrivatusChatError):
    """Errors related to GUI operations."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.GUI,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )


class NetworkError(PrivatusChatError):
    """Errors related to network operations."""

    def __init__(self, message: str, **kwargs):
        # Set default severity if not provided
        if 'severity' not in kwargs:
            kwargs['severity'] = ErrorSeverity.HIGH
        kwargs['category'] = ErrorCategory.NETWORK

        super().__init__(message, **kwargs)


class CryptoError(PrivatusChatError):
    """Errors related to cryptographic operations."""

    def __init__(self, message: str, **kwargs):
        # Set default severity if not provided
        if 'severity' not in kwargs:
            kwargs['severity'] = ErrorSeverity.HIGH
        kwargs['category'] = ErrorCategory.CRYPTOGRAPHY

        super().__init__(message, **kwargs)


class StorageError(PrivatusChatError):
    """Errors related to data storage operations."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.STORAGE,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )


class AuthenticationError(PrivatusChatError):
    """Errors related to authentication and authorization."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )


class ValidationError(PrivatusChatError):
    """Errors related to input validation."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.LOW,
            **kwargs
        )


class ConfigurationError(PrivatusChatError):
    """Errors related to application configuration."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )


class TransientError(PrivatusChatError):
    """Errors that are likely temporary and may succeed on retry."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            severity=ErrorSeverity.MEDIUM,
            recoverable=True,
            **kwargs
        )


class FatalError(PrivatusChatError):
    """Errors that prevent the application from continuing."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            severity=ErrorSeverity.CRITICAL,
            recoverable=False,
            **kwargs
        )


# Specific exception types for common scenarios

class ConnectionTimeoutError(NetworkError, TransientError):
    """Network connection timeout."""

    def __init__(self, message: str = "Connection timeout", **kwargs):
        super().__init__(message, **kwargs)


class ConnectionRefusedError(NetworkError, TransientError):
    """Network connection refused."""

    def __init__(self, message: str = "Connection refused", **kwargs):
        super().__init__(message, **kwargs)


class EncryptionError(CryptoError):
    """Base class for encryption-related errors."""

    def __init__(self, message: str = "Encryption error", **kwargs):
        super().__init__(message, **kwargs)


class EncryptionFailedError(CryptoError):
    """Encryption operation failed."""

    def __init__(self, message: str = "Encryption failed", **kwargs):
        super().__init__(message, **kwargs)


class DecryptionFailedError(CryptoError):
    """Decryption operation failed."""

    def __init__(self, message: str = "Decryption failed", **kwargs):
        super().__init__(message, **kwargs)


class KeyNotFoundError(CryptoError):
    """Required cryptographic key not found."""

    def __init__(self, message: str = "Required key not found", **kwargs):
        super().__init__(message, **kwargs)


class StorageInitializationError(StorageError, FatalError):
    """Storage system failed to initialize."""

    def __init__(self, message: str = "Storage initialization failed", **kwargs):
        super().__init__(message, **kwargs)


class DatabaseConnectionError(StorageError, TransientError):
    """Database connection failed."""

    def __init__(self, message: str = "Database connection failed", **kwargs):
        super().__init__(message, **kwargs)


class InvalidPasswordError(AuthenticationError, ValidationError):
    """Invalid password provided."""

    def __init__(self, message: str = "Invalid password", **kwargs):
        super().__init__(message, **kwargs)


class WeakPasswordError(ValidationError):
    """Password does not meet security requirements."""

    def __init__(self, message: str = "Password does not meet security requirements", **kwargs):
        super().__init__(message, **kwargs)


class InvalidInputError(ValidationError):
    """User input validation failed."""

    def __init__(self, message: str = "Invalid input provided", **kwargs):
        super().__init__(message, **kwargs)


class FileTransferError(NetworkError, StorageError):
    """File transfer operation failed."""

    def __init__(self, message: str = "File transfer failed", **kwargs):
        super().__init__(message, **kwargs)


class VoiceCallError(NetworkError):
    """Voice call operation failed."""

    def __init__(self, message: str = "Voice call failed", **kwargs):
        super().__init__(message, **kwargs)


class GroupChatError(PrivatusChatError):
    """Group chat operation failed."""

    def __init__(self, message: str = "Group chat operation failed", **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )