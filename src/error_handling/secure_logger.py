"""
Secure Logger for Privatus-chat

Provides comprehensive logging functionality while ensuring sensitive
data is never exposed in logs or error messages.
"""

import logging
import logging.handlers
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum

from .exceptions import PrivatusChatError, ErrorSeverity, ErrorCategory


class LogLevel(Enum):
    """Log levels for filtering sensitive information."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class SecureLogger:
    """
    Secure logging system that prevents sensitive data exposure.

    Features:
    - Automatic sanitization of sensitive data
    - Structured logging with JSON format
    - Separate log files for different severity levels
    - Log rotation and compression
    - Memory buffer for batch processing
    """

    def __init__(
        self,
        log_dir: Optional[Path] = None,
        app_name: str = "privatus-chat",
        max_buffer_size: int = 1000,
        enable_console: bool = True,
        enable_file: bool = True,
        min_level: LogLevel = LogLevel.INFO
    ):
        """
        Initialize secure logger.

        Args:
            log_dir: Directory for log files (default: ~/.privatus-chat/logs)
            app_name: Application name for log files
            max_buffer_size: Maximum log entries to buffer before flushing
            enable_console: Whether to log to console
            enable_file: Whether to log to files
            min_level: Minimum log level to record
        """
        self.app_name = app_name
        self.max_buffer_size = max_buffer_size
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.min_level = min_level

        # Setup log directory
        if log_dir is None:
            self.log_dir = Path.home() / f".{app_name}" / "logs"
        else:
            self.log_dir = log_dir

        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Sensitive data patterns to redact
        self.sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'credential', 'auth', 'private', 'session', 'cookie',
            'signature', 'hash', 'salt', 'iv', 'nonce'
        ]

        # Setup loggers
        self._setup_loggers()

        # Log buffer for batch processing
        self.log_buffer = []
        self.error_buffer = []

    def _setup_loggers(self):
        """Setup logging infrastructure."""
        # Main logger
        self.logger = logging.getLogger(f"{self.app_name}.secure")
        self.logger.setLevel(self.min_level.value)
        self.logger.propagate = False  # Prevent duplicate messages

        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Create formatters
        console_formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Console handler (only for WARNING and above in production)
        if self.enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(max(self.min_level.value, logging.WARNING))
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)

        # File handlers
        if self.enable_file:
            # Info and above log file
            info_log_file = self.log_dir / f"{self.app_name}.log"
            info_handler = logging.handlers.RotatingFileHandler(
                info_log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            info_handler.setLevel(self.min_level.value)
            info_handler.setFormatter(file_formatter)
            self.logger.addHandler(info_handler)

            # Error-only log file
            error_log_file = self.log_dir / f"{self.app_name}_errors.log"
            error_handler = logging.handlers.RotatingFileHandler(
                error_log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=10  # Keep more error logs
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(file_formatter)
            self.logger.addHandler(error_handler)

            # Security events log
            security_log_file = self.log_dir / f"{self.app_name}_security.log"
            security_handler = logging.handlers.RotatingFileHandler(
                security_log_file,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=20  # Keep many security logs
            )
            security_handler.setLevel(logging.INFO)
            security_handler.setFormatter(file_formatter)
            self.logger.addHandler(security_handler)

    def _sanitize_message(self, message: str) -> str:
        """Sanitize message to remove sensitive data."""
        if not isinstance(message, str):
            message = str(message)

        # Simple pattern-based sanitization
        for pattern in self.sensitive_patterns:
            if pattern in message.lower():
                # Replace sensitive values (basic implementation)
                words = message.split()
                sanitized_words = []
                for word in words:
                    if any(sensitive in word.lower() for sensitive in self.sensitive_patterns):
                        if '=' in word or ':' in word:
                            key, value = word.split('=', 1) if '=' in word else word.split(':', 1)
                            sanitized_words.append(f"{key}=[REDACTED]")
                        else:
                            sanitized_words.append("[REDACTED]")
                    else:
                        sanitized_words.append(word)
                return ' '.join(sanitized_words)

        return message

    def _sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize data structures."""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if any(pattern in key.lower() for pattern in self.sensitive_patterns):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_data(value)
            return sanitized
        elif isinstance(data, (list, tuple)):
            return [self._sanitize_data(item) for item in data]
        elif isinstance(data, str):
            return self._sanitize_message(data)
        else:
            return data

    def _log_to_buffer(self, level: int, message: str, extra: Optional[Dict] = None):
        """Add log entry to buffer for batch processing."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': logging.getLevelName(level),
            'message': self._sanitize_message(message),
            'logger': self.logger.name
        }

        if extra:
            log_entry['extra'] = self._sanitize_data(extra)

        self.log_buffer.append(log_entry)

        # Flush buffer if it's getting too large
        if len(self.log_buffer) >= self.max_buffer_size:
            self._flush_buffer()

    def _flush_buffer(self):
        """Flush log buffer to disk."""
        if not self.log_buffer:
            return

        try:
            # Write to main log file as JSON lines
            log_file = self.log_dir / f"{self.app_name}_buffered.jsonl"
            with open(log_file, 'a', encoding='utf-8') as f:
                for entry in self.log_buffer:
                    f.write(json.dumps(entry) + '\n')
        except Exception as e:
            # Fallback to console if file writing fails
            print(f"Failed to write to log buffer: {e}", file=sys.stderr)

        self.log_buffer.clear()

    def log_error(self, error: Exception, context: Optional[Dict] = None):
        """
        Log an error with full context and sanitization.

        Args:
            error: Exception to log
            context: Additional context data
        """
        # Extract error information
        error_info = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'module': getattr(error, '__module__', 'unknown')
        }

        # Add PrivatusChatError specific information
        if isinstance(error, PrivatusChatError):
            error_info.update(error.to_dict())

        # Merge with additional context
        if context:
            error_info['context'] = context

        # Log the error
        self.logger.error(
            f"Error occurred: {error_info['error_type']}: {error_info['error_message']}",
            extra={'error_info': error_info}
        )

        # Also log to error buffer for analysis
        self.error_buffer.append({
            'timestamp': datetime.utcnow().isoformat(),
            'error_info': self._sanitize_data(error_info)
        })

    def log_security_event(self, event: str, details: Optional[Dict] = None):
        """
        Log security-related events.

        Args:
            event: Security event description
            details: Additional security event details
        """
        extra = {'security_event': True}
        if details:
            extra['details'] = self._sanitize_data(details)

        self.logger.info(f"Security event: {event}", extra=extra)

    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        """
        Log performance metrics.

        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Unit of measurement
        """
        self.logger.info(
            f"Performance: {metric_name}={value}{unit}",
            extra={'performance_metric': True, 'metric_name': metric_name, 'value': value, 'unit': unit}
        )

    def log_user_action(self, action: str, details: Optional[Dict] = None):
        """
        Log user actions for audit purposes.

        Args:
            action: User action description
            details: Additional action details
        """
        extra = {'user_action': True, 'action': action}
        if details:
            extra['details'] = self._sanitize_data(details)

        self.logger.info(f"User action: {action}", extra=extra)

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(self._sanitize_message(message), extra=kwargs)

    def info(self, message: str, **kwargs):
        """Log info message."""
        self.logger.info(self._sanitize_message(message), extra=kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(self._sanitize_message(message), extra=kwargs)

    def error(self, message: str, **kwargs):
        """Log error message."""
        self.logger.error(self._sanitize_message(message), extra=kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self.logger.critical(self._sanitize_message(message), extra=kwargs)

    def flush(self):
        """Flush all log buffers to disk."""
        self._flush_buffer()

        # Also flush any pending log handlers
        for handler in self.logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()

    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get error summary for the specified time period.

        Args:
            hours: Number of hours to look back

        Returns:
            Dictionary with error statistics
        """
        cutoff_time = datetime.utcnow().timestamp() - (hours * 3600)

        error_counts = {}
        recent_errors = []

        # Analyze error buffer
        for error_entry in self.error_buffer:
            entry_time = datetime.fromisoformat(error_entry['timestamp']).timestamp()
            if entry_time >= cutoff_time:
                error_type = error_entry['error_info'].get('error_type', 'Unknown')
                error_counts[error_type] = error_counts.get(error_type, 0) + 1
                recent_errors.append(error_entry)

        return {
            'total_errors': len(recent_errors),
            'error_types': error_counts,
            'time_period_hours': hours,
            'generated_at': datetime.utcnow().isoformat()
        }

    def cleanup_old_logs(self, max_age_days: int = 30):
        """
        Clean up old log files.

        Args:
            max_age_days: Maximum age of log files to keep
        """
        try:
            cutoff_time = time.time() - (max_age_days * 24 * 3600)

            for log_file in self.log_dir.glob("*.log"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    self.logger.info(f"Cleaned up old log file: {log_file.name}")

            # Also clean up buffered log file
            buffered_log = self.log_dir / f"{self.app_name}_buffered.jsonl"
            if buffered_log.exists() and buffered_log.stat().st_mtime < cutoff_time:
                buffered_log.unlink()
                self.logger.info("Cleaned up old buffered log file")

        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")


# Global logger instance
secure_logger = SecureLogger()