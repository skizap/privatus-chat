"""
User Feedback Manager for Privatus-chat

Provides user-friendly error dialogs, notifications, and feedback
mechanisms for GUI operations with graceful error handling.
"""

import asyncio
from typing import Optional, Dict, Any, Callable, List
from PyQt6.QtWidgets import (
    QMessageBox, QWidget, QApplication, QProgressDialog,
    QErrorMessage, QSystemTrayIcon, QMenu, QDialog, QVBoxLayout,
    QLabel, QPushButton, QHBoxLayout, QTextEdit, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QIcon, QAction

from .exceptions import PrivatusChatError, ErrorSeverity, ErrorCategory
from .secure_logger import secure_logger


class NotificationType:
    """Types of user notifications."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"
    QUESTION = "question"


class UserFeedbackManager(QObject):
    """
    Manages user feedback, error dialogs, and notifications.

    Provides consistent, user-friendly error handling across the GUI
    with proper error classification and recovery suggestions.
    """

    # Signals for integration with other components
    error_resolved = pyqtSignal(str)  # error_id
    retry_requested = pyqtSignal(str, dict)  # operation_name, context
    help_requested = pyqtSignal(str)  # help_topic

    def __init__(self, parent: Optional[QWidget] = None):
        """Initialize user feedback manager."""
        super().__init__(parent)
        self.parent = parent or QApplication.activeWindow()
        self.error_dialogs = {}  # Track active error dialogs
        self.notification_queue = []
        self.notification_timer = QTimer()
        self.notification_timer.timeout.connect(self._process_notification_queue)
        self.notification_timer.start(1000)  # Process every second

        # Error message dialog for repetitive errors (lazy-loaded)
        self.error_message_dialog = None
        self._ensure_error_dialog()

        # System tray for background notifications (if available)
        self.system_tray = None
        self._setup_system_tray()

    def _ensure_error_dialog(self):
        """Ensure error message dialog is created (lazy loading)."""
        if self.error_message_dialog is None and QApplication.instance():
            try:
                parent = self.parent or QApplication.activeWindow()
                self.error_message_dialog = QErrorMessage(parent)
                self.error_message_dialog.setWindowTitle("Privatus-chat Error")
            except Exception as e:
                secure_logger.warning(f"Failed to create error dialog: {e}")
                self.error_message_dialog = None

    def _setup_system_tray(self):
        """Setup system tray icon for notifications."""
        try:
            if QApplication.instance():
                self.system_tray = QSystemTrayIcon(self.parent)
                if self.system_tray.isSystemTrayAvailable():
                    self.system_tray.setIcon(QIcon())  # Would need actual icon
                    self.system_tray.setVisible(True)

                    # Create tray menu
                    tray_menu = QMenu()
                    show_action = QAction("Show", self.parent)
                    show_action.triggered.connect(self._show_main_window)
                    tray_menu.addAction(show_action)

                    quit_action = QAction("Quit", self.parent)
                    quit_action.triggered.connect(QApplication.quit)
                    tray_menu.addAction(quit_action)

                    self.system_tray.setContextMenu(tray_menu)
        except Exception as e:
            secure_logger.warning(f"Failed to setup system tray: {e}")

    def _show_main_window(self):
        """Show the main application window."""
        if self.parent and hasattr(self.parent, 'show'):
            self.parent.show()
            self.parent.raise_()
            self.parent.activateWindow()

    def show_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        show_retry: bool = True,
        show_help: bool = True
    ) -> Optional[str]:
        """
        Show user-friendly error dialog.

        Args:
            error: Exception that occurred
            context: Additional context information
            show_retry: Whether to show retry button
            show_help: Whether to show help button

        Returns:
            User's choice: 'retry', 'help', 'ignore', or None
        """
        # Log the error first
        secure_logger.log_error(error, context)

        # Handle PrivatusChatError specially
        if isinstance(error, PrivatusChatError):
            return self._show_privatus_error(error, show_retry, show_help)
        else:
            return self._show_generic_error(error, show_retry, show_help)

    def _show_privatus_error(
        self,
        error: PrivatusChatError,
        show_retry: bool,
        show_help: bool
    ) -> Optional[str]:
        """Show dialog for PrivatusChatError."""
        # Determine dialog type based on severity
        if error.severity == ErrorSeverity.CRITICAL:
            dialog_type = QMessageBox.Icon.Critical
            default_button = QMessageBox.StandardButton.Ok
        elif error.severity == ErrorSeverity.HIGH:
            dialog_type = QMessageBox.Icon.Warning
            default_button = QMessageBox.StandardButton.Ok
        else:
            dialog_type = QMessageBox.Icon.Information
            default_button = QMessageBox.StandardButton.Ok

        # Create buttons based on options
        buttons = [QMessageBox.StandardButton.Ok]

        if show_retry and error.recoverable:
            buttons.append(QMessageBox.StandardButton.Retry)

        if show_help:
            buttons.append(QMessageBox.StandardButton.Help)

        # Create message box
        msg_box = QMessageBox(self.parent)
        msg_box.setIcon(dialog_type)
        msg_box.setWindowTitle(self._get_error_title(error.category))
        msg_box.setText(error.user_message)
        msg_box.setDetailedText(self._get_detailed_error_text(error, context=None))

        # Add buttons
        for button in buttons:
            msg_box.addButton(button)

        # Set default button
        msg_box.setDefaultButton(default_button)

        # Show dialog and get result
        result = msg_box.exec()

        # Handle user response
        if result == QMessageBox.StandardButton.Retry:
            return 'retry'
        elif result == QMessageBox.StandardButton.Help:
            self.help_requested.emit(self._get_help_topic(error.category))
            return 'help'
        else:
            return 'ignore'

    def _show_generic_error(
        self,
        error: Exception,
        show_retry: bool,
        show_help: bool
    ) -> Optional[str]:
        """Show dialog for generic exceptions."""
        # Ensure error dialog is created before using it
        self._ensure_error_dialog()

        if self.error_message_dialog:
            # Use the error message dialog for repetitive errors
            self.error_message_dialog.showMessage(
                f"An unexpected error occurred:\n\n{str(error)}\n\n"
                "Please check the logs for more details."
            )
        else:
            # Fallback to logging if dialog creation failed
            secure_logger.error(f"Generic error (dialog unavailable): {error}")

        return 'ignore'

    def _get_error_title(self, category: ErrorCategory) -> str:
        """Get appropriate title for error category."""
        titles = {
            ErrorCategory.GUI: "Interface Error",
            ErrorCategory.NETWORK: "Connection Error",
            ErrorCategory.CRYPTOGRAPHY: "Security Error",
            ErrorCategory.STORAGE: "Storage Error",
            ErrorCategory.AUTHENTICATION: "Authentication Error",
            ErrorCategory.VALIDATION: "Input Error",
            ErrorCategory.CONFIGURATION: "Configuration Error",
            ErrorCategory.SYSTEM: "System Error",
            ErrorCategory.USER_INPUT: "Input Error"
        }
        return titles.get(category, "Error")

    def _get_detailed_error_text(self, error: PrivatusChatError, context: Optional[Dict]) -> str:
        """Get detailed error text for expandable section."""
        details = []

        if isinstance(error, PrivatusChatError):
            details.append(f"Error ID: {error.error_id}")
            details.append(f"Category: {error.category.value}")
            details.append(f"Severity: {error.severity.value}")
            details.append(f"Recoverable: {'Yes' if error.recoverable else 'No'}")

        if error.cause:
            details.append(f"Caused by: {type(error.cause).__name__}: {str(error.cause)}")

        if context:
            details.append(f"Context: {context}")

        return "\n".join(details) if details else "No additional details available."

    def _get_help_topic(self, category: ErrorCategory) -> str:
        """Get help topic for error category."""
        help_topics = {
            ErrorCategory.GUI: "gui_troubleshooting",
            ErrorCategory.NETWORK: "network_issues",
            ErrorCategory.CRYPTOGRAPHY: "security_help",
            ErrorCategory.STORAGE: "storage_problems",
            ErrorCategory.AUTHENTICATION: "authentication_help",
            ErrorCategory.VALIDATION: "input_validation",
            ErrorCategory.CONFIGURATION: "configuration_issues",
            ErrorCategory.SYSTEM: "system_requirements",
            ErrorCategory.USER_INPUT: "user_input_help"
        }
        return help_topics.get(category, "general_help")

    def show_notification(
        self,
        message: str,
        notification_type: str = NotificationType.INFO,
        duration: int = 5000,
        actions: Optional[List[Dict[str, str]]] = None
    ):
        """
        Show user notification.

        Args:
            message: Notification message
            notification_type: Type of notification
            duration: How long to show notification (ms)
            actions: Optional list of action buttons
        """
        notification = {
            'message': message,
            'type': notification_type,
            'duration': duration,
            'actions': actions or [],
            'timestamp': asyncio.get_event_loop().time()
        }

        self.notification_queue.append(notification)

    def show_success(self, message: str, duration: int = 3000):
        """Show success notification."""
        self.show_notification(message, NotificationType.SUCCESS, duration)

    def show_warning(self, message: str, duration: int = 4000):
        """Show warning notification."""
        self.show_notification(message, NotificationType.WARNING, duration)

    def show_info(self, message: str, duration: int = 4000):
        """Show info notification."""
        self.show_notification(message, NotificationType.INFO, duration)

    def _process_notification_queue(self):
        """Process queued notifications."""
        current_time = asyncio.get_event_loop().time()

        # Remove expired notifications
        self.notification_queue = [
            n for n in self.notification_queue
            if current_time - n['timestamp'] < n['duration'] / 1000
        ]

        # Show next notification if any
        if self.notification_queue:
            notification = self.notification_queue[0]

            if notification['type'] == NotificationType.SUCCESS:
                self._show_system_notification(notification['message'], 'success')
            elif notification['type'] == NotificationType.WARNING:
                self._show_system_notification(notification['message'], 'warning')
            elif notification['type'] == NotificationType.ERROR:
                self._show_system_notification(notification['message'], 'error')
            else:
                self._show_system_notification(notification['message'], 'info')

    def _show_system_notification(self, message: str, notification_type: str):
        """Show system notification."""
        if self.system_tray and self.system_tray.isVisible():
            # Use system tray for notifications
            if notification_type == 'error':
                self.system_tray.showMessage(
                    "Privatus-chat Error",
                    message,
                    QSystemTrayIcon.MessageIcon.Critical
                )
            elif notification_type == 'warning':
                self.system_tray.showMessage(
                    "Privatus-chat Warning",
                    message,
                    QSystemTrayIcon.MessageIcon.Warning
                )
            else:
                self.system_tray.showMessage(
                    "Privatus-chat",
                    message,
                    QSystemTrayIcon.MessageIcon.Information
                )
        else:
            # Fallback to status bar or dialog
            if self.parent and hasattr(self.parent, 'statusBar'):
                self.parent.statusBar().showMessage(message, 3000)

    def show_progress_dialog(
        self,
        title: str,
        message: str,
        maximum: int = 0,
        cancel_text: str = "Cancel"
    ) -> QProgressDialog:
        """
        Show progress dialog for long-running operations.

        Args:
            title: Dialog title
            message: Progress message
            maximum: Maximum progress value
            cancel_text: Text for cancel button

        Returns:
            Progress dialog instance
        """
        progress = QProgressDialog(message, cancel_text, 0, maximum, self.parent)
        progress.setWindowTitle(title)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setAutoReset(False)
        progress.setAutoClose(False)

        return progress

    def show_confirmation_dialog(
        self,
        title: str,
        message: str,
        default_yes: bool = True,
        yes_text: str = "Yes",
        no_text: str = "No"
    ) -> bool:
        """
        Show confirmation dialog.

        Args:
            title: Dialog title
            message: Confirmation message
            default_yes: Whether Yes is the default button
            yes_text: Text for Yes button
            no_text: Text for No button

        Returns:
            True if user clicked Yes, False otherwise
        """
        reply = QMessageBox.question(
            self.parent,
            title,
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes if default_yes else QMessageBox.StandardButton.No
        )

        return reply == QMessageBox.StandardButton.Yes

    def show_input_dialog(
        self,
        title: str,
        message: str,
        default_value: str = "",
        validation_func: Optional[Callable[[str], bool]] = None
    ) -> Optional[str]:
        """
        Show input dialog for user input.

        Args:
            title: Dialog title
            message: Input prompt message
            default_value: Default input value
            validation_func: Optional validation function

        Returns:
            User input or None if cancelled
        """
        from PyQt6.QtWidgets import QInputDialog

        while True:
            value, ok = QInputDialog.getText(
                self.parent,
                title,
                message,
                text=default_value
            )

            if not ok:
                return None

            if validation_func and not validation_func(value):
                QMessageBox.warning(
                    self.parent,
                    "Invalid Input",
                    "The input provided is not valid. Please try again."
                )
                continue

            return value

    def show_critical_error(self, message: str, details: str = "") -> None:
        """
        Show critical error that requires application attention.

        Args:
            message: Error message
            details: Detailed error information
        """
        msg_box = QMessageBox(self.parent)
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setWindowTitle("Critical Error")
        msg_box.setText(message)

        if details:
            msg_box.setDetailedText(details)

        # Add quit button for critical errors
        quit_button = msg_box.addButton("Quit Application", QMessageBox.ButtonRole.RejectRole)
        msg_box.setDefaultButton(quit_button)

        msg_box.exec()

        # Log critical error
        secure_logger.critical(f"Critical error shown to user: {message}")

    def show_recovery_suggestions(self, error: PrivatusChatError) -> Optional[str]:
        """
        Show recovery suggestions for an error.

        Args:
            error: Error that occurred

        Returns:
            User's recovery choice or None
        """
        suggestions = self._get_recovery_suggestions(error)

        if not suggestions:
            return None

        # Create custom dialog with recovery options
        dialog = QDialog(self.parent)
        dialog.setWindowTitle("Recovery Options")
        dialog.setModal(True)
        dialog.resize(400, 300)

        layout = QVBoxLayout()

        # Error message
        error_label = QLabel(f"An error occurred:\n{error.user_message}")
        error_label.setWordWrap(True)
        layout.addWidget(error_label)

        # Recovery options
        if len(suggestions) > 1:
            layout.addWidget(QLabel("Choose a recovery option:"))

            for i, suggestion in enumerate(suggestions):
                btn = QPushButton(suggestion['text'])
                btn.clicked.connect(lambda checked, opt=suggestion['action']: self._execute_recovery(dialog, opt))
                layout.addWidget(btn)
        else:
            # Single suggestion
            suggestion = suggestions[0]
            btn = QPushButton(suggestion['text'])
            btn.clicked.connect(lambda checked, opt=suggestion['action']: self._execute_recovery(dialog, opt))
            layout.addWidget(btn)

        # Cancel button
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        layout.addWidget(cancel_btn)

        dialog.setLayout(layout)
        result = dialog.exec()

        return result

    def _get_recovery_suggestions(self, error: PrivatusChatError) -> List[Dict[str, str]]:
        """Get recovery suggestions for an error."""
        suggestions = []

        if error.category == ErrorCategory.NETWORK:
            suggestions.append({
                'text': 'Retry Connection',
                'action': 'retry_network'
            })
            suggestions.append({
                'text': 'Check Network Settings',
                'action': 'check_network_settings'
            })

        elif error.category == ErrorCategory.STORAGE:
            suggestions.append({
                'text': 'Retry Operation',
                'action': 'retry_storage'
            })
            suggestions.append({
                'text': 'Check Storage Settings',
                'action': 'check_storage_settings'
            })

        elif error.category == ErrorCategory.AUTHENTICATION:
            suggestions.append({
                'text': 'Re-enter Credentials',
                'action': 'reauthenticate'
            })

        elif error.category == ErrorCategory.GUI:
            suggestions.append({
                'text': 'Restart Component',
                'action': 'restart_gui_component'
            })

        # Default suggestion
        if error.recoverable:
            suggestions.append({
                'text': 'Try Again',
                'action': 'retry_generic'
            })

        return suggestions

    def _execute_recovery(self, dialog: QDialog, action: str):
        """Execute recovery action."""
        dialog.accept()

        if action == 'retry_network':
            self.retry_requested.emit('network_connection', {})
        elif action == 'retry_storage':
            self.retry_requested.emit('storage_operation', {})
        elif action == 'reauthenticate':
            self.retry_requested.emit('authentication', {})
        elif action == 'restart_gui_component':
            self.retry_requested.emit('gui_component', {})
        else:
            self.retry_requested.emit('generic', {'action': action})

    def handle_operation_with_feedback(
        self,
        operation_name: str,
        operation_func: Callable,
        error_context: Optional[Dict] = None,
        show_progress: bool = False
    ) -> Any:
        """
        Execute operation with user feedback and error handling.

        Args:
            operation_name: Name of the operation for user feedback
            operation_func: Function to execute
            error_context: Additional error context
            show_progress: Whether to show progress dialog

        Returns:
            Operation result on success
        """
        try:
            if show_progress:
                progress = self.show_progress_dialog(
                    f"{operation_name.title()}",
                    f"Performing {operation_name.lower()}...",
                    0
                )
                progress.show()

            result = operation_func()

            if show_progress:
                progress.close()

            return result

        except Exception as e:
            if show_progress:
                progress.close()

            # Show error and offer retry
            user_choice = self.show_error(e, error_context)

            if user_choice == 'retry':
                # Retry the operation
                return self.handle_operation_with_feedback(
                    operation_name, operation_func, error_context, show_progress
                )
            else:
                raise


# Global feedback manager instance (lazy-loaded)
_feedback_manager = None

def get_feedback_manager() -> UserFeedbackManager:
    """Get the global feedback manager instance (lazy-loaded)."""
    global _feedback_manager
    if _feedback_manager is None:
        _feedback_manager = UserFeedbackManager()
    return _feedback_manager

# Backward compatibility alias
feedback_manager = None  # Will be set to actual instance when first accessed