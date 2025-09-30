"""
Error Handling Module for Privatus-chat

This module provides comprehensive error handling, logging, and user feedback
throughout the application with security considerations.
"""

from .error_handler import ErrorHandler, ErrorSeverity, ErrorCategory, handle_errors
from .exceptions import (
    PrivatusChatError,
    GUIError,
    NetworkError,
    CryptoError,
    StorageError,
    AuthenticationError,
    ValidationError,
    ConfigurationError,
    TransientError,
    FatalError,
    EncryptionError,
    EncryptionFailedError,
    DecryptionFailedError,
    KeyNotFoundError,
    ConnectionTimeoutError,
    ConnectionRefusedError,
    StorageInitializationError,
    DatabaseConnectionError,
    InvalidPasswordError,
    WeakPasswordError,
    InvalidInputError,
    FileTransferError,
    VoiceCallError,
    GroupChatError
)
from .retry_manager import RetryManager, RetryConfig, storage_retry_manager
from .secure_logger import SecureLogger, secure_logger
from .user_feedback import UserFeedbackManager, get_feedback_manager

__all__ = [
    'ErrorHandler',
    'ErrorSeverity',
    'ErrorCategory',
    'handle_errors',
    'PrivatusChatError',
    'GUIError',
    'NetworkError',
    'CryptoError',
    'StorageError',
    'AuthenticationError',
    'ValidationError',
    'ConfigurationError',
    'TransientError',
    'FatalError',
    'EncryptionError',
    'EncryptionFailedError',
    'DecryptionFailedError',
    'KeyNotFoundError',
    'ConnectionTimeoutError',
    'ConnectionRefusedError',
    'StorageInitializationError',
    'DatabaseConnectionError',
    'InvalidPasswordError',
    'WeakPasswordError',
    'InvalidInputError',
    'FileTransferError',
    'VoiceCallError',
    'GroupChatError',
    'RetryManager',
    'RetryConfig',
    'storage_retry_manager',
    'SecureLogger',
    'secure_logger',
    'UserFeedbackManager',
    'get_feedback_manager'
]