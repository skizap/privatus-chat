"""
GUI Components for Privatus-chat

Individual UI components used throughout the application interface.
"""

from datetime import datetime
from typing import Dict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QLineEdit, QPushButton, QScrollArea, QFrame, QGroupBox, QComboBox, QCheckBox,
    QFileDialog, QProgressBar, QVBoxLayout, QMessageBox, QDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont

from .themes import theme_manager


class SecurityIndicator(QWidget):
    """Widget displaying current security and anonymity status."""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the security indicator UI."""
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)
        
        # Security status indicators
        self.encryption_label = QLabel("🔒 E2EE")
        self.encryption_label.setStyleSheet("color: green; font-weight: bold;")
        self.encryption_label.setToolTip("End-to-End Encryption Active")
        
        self.anonymity_label = QLabel("🎭 Anonymous")
        self.anonymity_label.setStyleSheet("color: blue; font-weight: bold;")
        self.anonymity_label.setToolTip("Anonymous Mode Active")
        
        self.network_label = QLabel("🌐 Connected")
        self.network_label.setStyleSheet("color: green; font-weight: bold;")
        self.network_label.setToolTip("P2P Network Connected")
        
        layout.addWidget(self.encryption_label)
        layout.addWidget(QLabel(" | "))
        layout.addWidget(self.anonymity_label)
        layout.addWidget(QLabel(" | "))
        layout.addWidget(self.network_label)
        layout.addStretch()
        
        self.setLayout(layout)
        
    def update_encryption_status(self, active: bool, details: str = ""):
        """Update encryption status indicator."""
        if active:
            self.encryption_label.setText("🔒 E2EE")
            self.encryption_label.setStyleSheet("color: green; font-weight: bold;")
            self.encryption_label.setToolTip(f"End-to-End Encryption Active\n{details}")
        else:
            self.encryption_label.setText("🔓 No E2EE")
            self.encryption_label.setStyleSheet("color: red; font-weight: bold;")
            self.encryption_label.setToolTip("End-to-End Encryption Inactive")
            
    def update_anonymity_status(self, level: str, details: str = ""):
        """Update anonymity status indicator."""
        level_config = {
            "Maximum": ("🎭 Maximum", "color: darkblue; font-weight: bold;"),
            "High": ("🎭 High", "color: blue; font-weight: bold;"),
            "Standard": ("🎭 Standard", "color: orange; font-weight: bold;"),
            "Minimal": ("🎭 Minimal", "color: red; font-weight: bold;"),
            "Off": ("👤 Identity", "color: gray; font-weight: bold;")
        }
        
        text, style = level_config.get(level, ("🎭 Unknown", "color: gray;"))
        self.anonymity_label.setText(text)
        self.anonymity_label.setStyleSheet(style)
        self.anonymity_label.setToolTip(f"Privacy Level: {level}\n{details}")
        
    def update_network_status(self, connected: bool, peer_count: int = 0):
        """Update network connection status."""
        if connected:
            self.network_label.setText(f"🌐 Connected ({peer_count} peers)")
            self.network_label.setStyleSheet("color: green; font-weight: bold;")
            self.network_label.setToolTip(f"P2P Network Connected\n{peer_count} peers online")
        else:
            self.network_label.setText("📡 Connecting...")
            self.network_label.setStyleSheet("color: orange; font-weight: bold;")
            self.network_label.setToolTip("Connecting to P2P Network")


class ContactListWidget(QListWidget):
    """Enhanced contact list with security indicators and voice call buttons."""

    contact_selected = pyqtSignal(str)  # contact_id
    voice_call_requested = pyqtSignal(str)  # contact_id

    def __init__(self):
        super().__init__()
        self.contacts = {}
        self.setup_ui()

    def setup_ui(self):
        """Setup contact list appearance."""
        self.setMaximumWidth(280)
        self.setMinimumWidth(220)


# Alias for backward compatibility
ContactList = ContactListWidget


class MessageWidget(QFrame):
        
    def add_contact(self, contact_id: str, display_name: str,
                    is_verified: bool = False, is_online: bool = False):
        """Add a contact to the list with voice call button."""
        # Create custom widget for contact with call button
        contact_widget = self._create_contact_widget(contact_id, display_name, is_verified, is_online)

        # Create list item
        item = QListWidgetItem()
        item.setSizeHint(contact_widget.sizeHint())

        # Store contact data
        self.addItem(item)
        self.setItemWidget(item, contact_widget)

        self.contacts[contact_id] = {
            'display_name': display_name,
            'is_verified': is_verified,
            'is_online': is_online,
            'item': item,
            'widget': contact_widget,
            'call_button': contact_widget.call_button
        }
        
    def update_contact_status(self, contact_id: str, is_online: bool):
        """Update contact online status."""
        if contact_id in self.contacts:
            contact = self.contacts[contact_id]
            contact['is_online'] = is_online

            # Update the contact widget
            contact_widget = contact['widget']
            verification_icon = "✅" if contact['is_verified'] else "⚠️"
            online_icon = "🟢" if is_online else "⚫"

            contact_widget.status_label.setText(f"{verification_icon} {online_icon} {contact['display_name']}")
            contact_widget.call_button.setEnabled(is_online)

    def _create_contact_widget(self, contact_id: str, display_name: str, is_verified: bool, is_online: bool):
        """Create a custom widget for a contact with call button."""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)

        # Contact status and name
        verification_icon = "✅" if is_verified else "⚠️"
        online_icon = "🟢" if is_online else "⚫"

        status_label = QLabel(f"{verification_icon} {online_icon} {display_name}")
        status_label.setStyleSheet("font-size: 11px; padding: 2px;")
        layout.addWidget(status_label, stretch=1)

        # Voice call button
        call_button = QPushButton("📞")
        call_button.setToolTip(f"Start voice call with {display_name}")
        call_button.setMaximumWidth(30)
        call_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 3px;
                font-size: 10px;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        call_button.setEnabled(is_online)
        call_button.clicked.connect(lambda: self.voice_call_requested.emit(contact_id))
        layout.addWidget(call_button)

        widget.setLayout(layout)
        widget.status_label = status_label
        widget.call_button = call_button

        return widget

    def mousePressEvent(self, event):
        """Handle contact selection."""
        super().mousePressEvent(event)
        current_item = self.currentItem()
        if current_item:
            contact_id = current_item.data(Qt.ItemDataRole.UserRole)
            self.contact_selected.emit(contact_id)


class MessageWidget(QFrame):
    """Individual message display widget."""
    
    def __init__(self, message: str, timestamp: datetime, is_outgoing: bool, is_encrypted: bool = True):
        super().__init__()
        self.message = message
        self.timestamp = timestamp
        self.is_outgoing = is_outgoing
        self.is_encrypted = is_encrypted
        self.setup_ui()
        
    def setup_ui(self):
        """Setup message display."""
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Message content
        self.message_label = QLabel(self.message)
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        # Message metadata
        time_str = self.timestamp.strftime("%H:%M")
        encryption_icon = "🔒" if self.is_encrypted else "🔓"
        direction_icon = "➡️" if self.is_outgoing else "⬅️"
        
        self.metadata_label = QLabel(f"{direction_icon} {encryption_icon} {time_str}")
        
        layout.addWidget(self.message_label)
        layout.addWidget(self.metadata_label)
        
        # Apply theme-aware styling
        self.apply_theme_styling()
        
        # Connect to theme changes
        theme_manager.theme_changed.connect(self.apply_theme_styling)
            
        self.setLayout(layout)
        
    def apply_theme_styling(self):
        """Apply theme-aware styling to the message widget."""
        # Get theme colors
        if self.is_outgoing:
            bg_color = theme_manager.get_color("chat_outgoing")
            margin_style = "margin-left: 50px; margin-right: 10px;"
        else:
            bg_color = theme_manager.get_color("chat_incoming")
            margin_style = "margin-left: 10px; margin-right: 50px;"
            
        text_color = theme_manager.get_color("text_primary")
        secondary_text_color = theme_manager.get_color("text_secondary")
        
        # Apply styling
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                color: {text_color};
                border-radius: 10px;
                {margin_style}
            }}
            QLabel {{
                color: {text_color};
            }}
        """)
        
        # Update metadata label with secondary text color
        self.metadata_label.setStyleSheet(f"color: {secondary_text_color}; font-size: 10px;")


class ChatAreaWidget(QScrollArea):
    """Scrollable chat message display area."""
    
    def __init__(self):
        super().__init__()
        self.messages = []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup chat area."""
        self.setWidgetResizable(True)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        # Create container widget
        self.container = QWidget()
        self.container_layout = QVBoxLayout()
        self.container_layout.setSpacing(5)
        self.container_layout.addStretch()
        self.container.setLayout(self.container_layout)

        self.setWidget(self.container)

    def add_message(self, message: str, is_outgoing: bool, is_encrypted: bool = True):
        """Add a new message to the chat."""
        timestamp = datetime.now()
        message_widget = MessageWidget(message, timestamp, is_outgoing, is_encrypted)

        # Insert before the stretch
        self.container_layout.insertWidget(self.container_layout.count() - 1, message_widget)
        self.messages.append(message_widget)

        # Scroll to bottom
        QTimer.singleShot(10, self.scroll_to_bottom)

    def scroll_to_bottom(self):
        """Scroll to the bottom of the chat area."""
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_messages(self):
        """Clear all messages from the chat area."""
        for message_widget in self.messages:
            message_widget.deleteLater()
        self.messages.clear()


# Alias for backward compatibility
ChatArea = ChatAreaWidget


class MessageInputWidget(QWidget):
    """Message input area with send button, file transfer, and voice call support."""

    message_sent = pyqtSignal(str)  # message text
    file_selected = pyqtSignal(str)  # file path
    voice_call_requested = pyqtSignal()  # voice call request

    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        """Setup message input UI."""
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)

        # Voice call button
        self.voice_call_button = QPushButton("📞 Call")
        self.voice_call_button.setToolTip("Start voice call")
        self.voice_call_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.voice_call_button.clicked.connect(self.request_voice_call)
        layout.addWidget(self.voice_call_button)

        # Message input field
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your secure message here...")
        self.message_input.returnPressed.connect(self.send_message)

        # File selection button
        self.file_button = QPushButton("📎")
        self.file_button.setToolTip("Select file to send")
        self.file_button.clicked.connect(self.select_file)
        self.file_button.setMaximumWidth(40)

        # Send button
        self.send_button = QPushButton("Send 🔒")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setMinimumWidth(80)

        layout.addWidget(self.message_input)
        layout.addWidget(self.file_button)
        layout.addWidget(self.send_button)

        self.setLayout(layout)
        
    def send_message(self):
        """Send the current message."""
        message_text = self.message_input.text().strip()
        if message_text:
            self.message_sent.emit(message_text)
            self.message_input.clear()
            
    def set_enabled(self, enabled: bool):
        """Enable/disable message input."""
        self.message_input.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        self.file_button.setEnabled(enabled)
        self.voice_call_button.setEnabled(enabled)
        if enabled:
            self.send_button.setText("Send 🔒")
        else:
            self.send_button.setText("Offline")

    def request_voice_call(self):
        """Request to start a voice call."""
        self.voice_call_requested.emit()

    def select_file(self):
        """Open file selection dialog."""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "Select File to Send",
            "",
            "All Files (*);;Images (*.png *.jpg *.jpeg *.gif);;Documents (*.pdf *.doc *.docx *.txt)"
        )

        if file_path:
            self.file_selected.emit(file_path)


class PrivacyControlPanel(QGroupBox):
    """Privacy and anonymity control panel."""
    
    privacy_level_changed = pyqtSignal(str)  # privacy level
    
    def __init__(self):
        super().__init__("Privacy Controls")
        self.setup_ui()
        
    def setup_ui(self):
        """Setup privacy controls."""
        layout = QVBoxLayout()
        
        # Privacy level selector
        level_layout = QHBoxLayout()
        level_layout.addWidget(QLabel("Privacy Level:"))
        
        self.privacy_combo = QComboBox()
        self.privacy_combo.addItems(["Minimal", "Standard", "High", "Maximum"])
        self.privacy_combo.setCurrentText("Standard")
        self.privacy_combo.currentTextChanged.connect(self.privacy_level_changed.emit)
        level_layout.addWidget(self.privacy_combo)
        
        layout.addLayout(level_layout)
        
        # Anonymity options
        self.anonymous_mode = QCheckBox("Anonymous Mode")
        self.anonymous_mode.setChecked(True)
        layout.addWidget(self.anonymous_mode)
        
        self.traffic_obfuscation = QCheckBox("Traffic Obfuscation")
        self.traffic_obfuscation.setChecked(True)
        layout.addWidget(self.traffic_obfuscation)
        
        self.dummy_traffic = QCheckBox("Cover Traffic")
        self.dummy_traffic.setChecked(False)
        layout.addWidget(self.dummy_traffic)
        
        # Connection info
        self.connection_info = QLabel("Tor-like routing through 3 hops")
        self.connection_info.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(self.connection_info)
        
        self.setLayout(layout)
        
    def get_privacy_settings(self) -> Dict:
        """Get current privacy settings."""
        return {
            'privacy_level': self.privacy_combo.currentText(),
            'anonymous_mode': self.anonymous_mode.isChecked(),
            'traffic_obfuscation': self.traffic_obfuscation.isChecked(),
            'dummy_traffic': self.dummy_traffic.isChecked()
        }


class FileTransferProgressWidget(QWidget):
    """Widget for displaying file transfer progress."""

    def __init__(self):
        super().__init__()
        self.transfers = {}
        self.setup_ui()

    def setup_ui(self):
        """Setup file transfer progress UI."""
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Title
        title = QLabel("📁 File Transfers")
        title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        layout.addWidget(title)

        # Scroll area for transfers
        from PyQt6.QtWidgets import QScrollArea
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMaximumHeight(200)

        self.container = QWidget()
        self.container_layout = QVBoxLayout()
        self.container_layout.setSpacing(2)
        self.container.setLayout(self.container_layout)
        scroll_area.setWidget(self.container)

        layout.addWidget(scroll_area)

        self.setLayout(layout)
        self.setMaximumHeight(250)

    def add_transfer(self, transfer_id: str, file_name: str, direction: str, file_size: int):
        """Add a new file transfer to the progress display."""
        # Create transfer progress widget
        transfer_widget = self._create_transfer_widget(transfer_id, file_name, direction, file_size)
        self.transfers[transfer_id] = transfer_widget
        self.container_layout.addWidget(transfer_widget)

    def update_transfer_progress(self, transfer_id: str, progress: float, status: str, rate: float = 0.0, eta: str = ""):
        """Update transfer progress."""
        if transfer_id in self.transfers:
            widget = self.transfers[transfer_id]
            widget['progress_bar'].setValue(int(progress * 100))
            widget['status_label'].setText(f"{status} ({progress*100:.1f}%)")

            if rate > 0:
                rate_text = f"{rate/1024:.1f} KB/s"
                if eta:
                    rate_text += f" - ETA: {eta}"
                widget['rate_label'].setText(rate_text)
            else:
                widget['rate_label'].setText("")

    def remove_transfer(self, transfer_id: str):
        """Remove a transfer from the display."""
        if transfer_id in self.transfers:
            widget = self.transfers[transfer_id]
            widget['widget'].deleteLater()
            del self.transfers[transfer_id]

    def _create_transfer_widget(self, transfer_id: str, file_name: str, direction: str, file_size: int):
        """Create individual transfer progress widget."""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(3)

        # File info header with better styling
        direction_icon = "⬆️" if direction == "outgoing" else "⬇️"
        file_label = QLabel(f"{direction_icon} {file_name}")
        file_label.setFont(QFont("Arial", 9, QFont.Weight.Bold))

        # Add file size info
        size_mb = file_size / (1024 * 1024)
        size_label = QLabel(f"{size_mb:.1f} MB")
        size_label.setStyleSheet("font-size: 8px; color: gray;")

        header_layout = QHBoxLayout()
        header_layout.addWidget(file_label)
        header_layout.addStretch()
        header_layout.addWidget(size_label)
        layout.addLayout(header_layout)

        # Progress bar with better styling
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        progress_bar.setTextVisible(True)
        progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 3px;
                text-align: center;
                font-size: 9px;
            }
            QProgressBar::chunk {
                background-color: #4caf50;
                border-radius: 2px;
            }
        """)
        layout.addWidget(progress_bar)

        # Status and rate info with improved layout
        status_label = QLabel("Starting...")
        status_label.setStyleSheet("font-size: 9px; color: #666; padding: 2px;")

        rate_label = QLabel("")
        rate_label.setStyleSheet("font-size: 9px; color: #2196f3; padding: 2px;")

        info_layout = QHBoxLayout()
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.addWidget(status_label)
        info_layout.addStretch()
        info_layout.addWidget(rate_label)
        layout.addLayout(info_layout)

        # Add cancel button for active transfers
        cancel_button = QPushButton("❌")
        cancel_button.setMaximumWidth(25)
        cancel_button.setToolTip("Cancel transfer")
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 3px;
                font-size: 10px;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        widget.setLayout(layout)
        widget.setStyleSheet("""
            QWidget {
                background-color: #f9f9f9;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
            }
        """)

        # Connect cancel button
        cancel_button.clicked.connect(lambda: self._cancel_transfer(transfer_id))

        return {
            'widget': widget,
            'progress_bar': progress_bar,
            'status_label': status_label,
            'rate_label': rate_label,
            'cancel_button': cancel_button
        }

    def _cancel_transfer(self, transfer_id: str):
        """Cancel a specific transfer."""
        # Emit signal to parent for cancellation
        # This would be connected to the main window's cancel method
        pass


class FileTransferControlsWidget(QWidget):
    """Widget for file transfer control buttons."""

    accept_requested = pyqtSignal(str)  # transfer_id
    reject_requested = pyqtSignal(str)  # transfer_id
    cancel_requested = pyqtSignal(str)  # transfer_id
    pause_requested = pyqtSignal(str)   # transfer_id
    resume_requested = pyqtSignal(str)  # transfer_id

    def __init__(self):
        super().__init__()
        self.current_transfer_id = None
        self.setup_ui()

    def setup_ui(self):
        """Setup file transfer controls UI."""
        layout = QHBoxLayout()
        layout.setContentsMargins(8, 5, 8, 5)
        layout.setSpacing(5)

        # Accept button with improved styling
        self.accept_button = QPushButton("✅ Accept")
        self.accept_button.clicked.connect(self._accept_transfer)
        self.accept_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        layout.addWidget(self.accept_button)

        # Reject button with improved styling
        self.reject_button = QPushButton("❌ Reject")
        self.reject_button.clicked.connect(self._reject_transfer)
        self.reject_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        layout.addWidget(self.reject_button)

        # Pause/Resume button with improved styling
        self.pause_resume_button = QPushButton("⏸️ Pause")
        self.pause_resume_button.clicked.connect(self._pause_resume_transfer)
        self.pause_resume_button.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        layout.addWidget(self.pause_resume_button)

        # Cancel button with improved styling
        self.cancel_button = QPushButton("🚫 Cancel")
        self.cancel_button.clicked.connect(self._cancel_transfer)
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #757575;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        layout.addWidget(self.cancel_button)

        layout.addStretch()
        self.setLayout(layout)

        # Set initial state
        self.setVisible(False)  # Hidden until a transfer is active

    def set_transfer_id(self, transfer_id: str):
        """Set the current transfer ID for controls."""
        self.current_transfer_id = transfer_id
        self._update_button_states()

    def set_transfer_status(self, status: str):
        """Update button states based on transfer status."""
        if status == "paused":
            self.pause_resume_button.setText("▶️ Resume")
        elif status == "transferring":
            self.pause_resume_button.setText("⏸️ Pause")
        else:
            self.pause_resume_button.setText("⏸️ Pause")

        self._update_button_states()

    def _update_button_states(self):
        """Update button enabled states."""
        has_transfer = self.current_transfer_id is not None
        self.accept_button.setEnabled(has_transfer)
        self.reject_button.setEnabled(has_transfer)
        self.pause_resume_button.setEnabled(has_transfer)
        self.cancel_button.setEnabled(has_transfer)

    def _accept_transfer(self):
        if self.current_transfer_id:
            self.accept_requested.emit(self.current_transfer_id)

    def _reject_transfer(self):
        if self.current_transfer_id:
            self.reject_requested.emit(self.current_transfer_id)

    def _pause_resume_transfer(self):
        if self.current_transfer_id:
            if self.pause_resume_button.text() == "⏸️ Pause":
                self.pause_requested.emit(self.current_transfer_id)
            else:
                self.resume_requested.emit(self.current_transfer_id)

    def _cancel_transfer(self):
        if self.current_transfer_id:
            self.cancel_requested.emit(self.current_transfer_id)


class VoiceCallStatusWidget(QWidget):
    """Widget for displaying active voice call status and controls."""

    call_ended = pyqtSignal()
    mute_toggled = pyqtSignal(bool)
    quality_changed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.current_call_id = None
        self.is_muted = False
        self.setup_ui()

    def setup_ui(self):
        """Setup voice call status UI."""
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)

        # Call status info
        self.status_label = QLabel("🔊 Voice Call Active")
        self.status_label.setStyleSheet("font-weight: bold; color: green; font-size: 12px;")
        layout.addWidget(self.status_label)

        # Call duration
        self.duration_label = QLabel("00:00")
        self.duration_label.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(self.duration_label)

        # Quality indicator
        self.quality_label = QLabel("📶 High")
        self.quality_label.setStyleSheet("color: green; font-size: 10px;")
        layout.addWidget(self.quality_label)

        layout.addStretch()

        # Control buttons
        self.mute_button = QPushButton("🔇 Mute")
        self.mute_button.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 8px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        self.mute_button.clicked.connect(self.toggle_mute)
        layout.addWidget(self.mute_button)

        self.end_call_button = QPushButton("📞 End Call")
        self.end_call_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 4px 8px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.end_call_button.clicked.connect(self.end_call)
        layout.addWidget(self.end_call_button)

        self.setLayout(layout)
        self.setVisible(False)  # Hidden by default

    def start_call(self, call_id: str, contact_name: str):
        """Start displaying call status."""
        self.current_call_id = call_id
        self.status_label.setText(f"🔊 Call with {contact_name}")
        self.setVisible(True)
        self.start_duration_timer()

    def end_call(self):
        """End the current call."""
        if self.current_call_id:
            self.call_ended.emit()
            self.current_call_id = None
            self.setVisible(False)
            self.stop_duration_timer()

    def toggle_mute(self):
        """Toggle mute state."""
        self.is_muted = not self.is_muted
        if self.is_muted:
            self.mute_button.setText("🔊 Unmute")
            self.mute_button.setStyleSheet("""
                QPushButton {
                    background-color: #9E9E9E;
                    color: white;
                    border: none;
                    border-radius: 3px;
                    padding: 4px 8px;
                    font-size: 10px;
                }
                QPushButton:hover {
                    background-color: #757575;
                }
            """)
        else:
            self.mute_button.setText("🔇 Mute")
            self.mute_button.setStyleSheet("""
                QPushButton {
                    background-color: #FF9800;
                    color: white;
                    border: none;
                    border-radius: 3px;
                    padding: 4px 8px;
                    font-size: 10px;
                }
                QPushButton:hover {
                    background-color: #F57C00;
                }
            """)
        self.mute_toggled.emit(self.is_muted)

    def update_call_quality(self, quality: str, latency: int = 0, packet_loss: float = 0.0):
        """Update call quality indicators."""
        quality_icons = {
            "low": "📶 Low",
            "medium": "📶 Medium",
            "high": "📶 High",
            "ultra": "📶 Ultra"
        }

        quality_text = quality_icons.get(quality.lower(), "📶 Medium")
        self.quality_label.setText(quality_text)

        # Update color based on quality
        if quality.lower() == "low":
            self.quality_label.setStyleSheet("color: red; font-size: 10px;")
        elif quality.lower() == "medium":
            self.quality_label.setStyleSheet("color: orange; font-size: 10px;")
        else:
            self.quality_label.setStyleSheet("color: green; font-size: 10px;")

        # Update tooltip with detailed info
        tooltip = f"Quality: {quality}"
        if latency > 0:
            tooltip += f"\nLatency: {latency}ms"
        if packet_loss > 0:
            tooltip += f"\nPacket Loss: {packet_loss*100:.1f}%"
        self.quality_label.setToolTip(tooltip)

    def start_duration_timer(self):
        """Start the call duration timer."""
        self.duration_seconds = 0
        self.duration_timer = QTimer()
        self.duration_timer.timeout.connect(self.update_duration)
        self.duration_timer.start(1000)

    def update_duration(self):
        """Update call duration display."""
        self.duration_seconds += 1
        minutes = self.duration_seconds // 60
        seconds = self.duration_seconds % 60
        self.duration_label.setText(f"{minutes:02d}:{seconds:02d}")

    def stop_duration_timer(self):
        """Stop the call duration timer."""
        if hasattr(self, 'duration_timer'):
            self.duration_timer.stop()


class AudioDeviceSelectorWidget(QWidget):
    """Widget for selecting audio input/output devices."""

    device_changed = pyqtSignal(str, str)  # input_device, output_device

    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        """Setup audio device selector UI."""
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)

        # Input device selector
        input_layout = QVBoxLayout()
        input_label = QLabel("🎤 Input:")
        input_label.setStyleSheet("font-size: 9px; color: gray;")

        self.input_combo = QComboBox()
        self.input_combo.setStyleSheet("font-size: 9px; padding: 2px;")
        self.input_combo.addItems(["Default Microphone", "External Microphone", "Built-in Microphone"])
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_combo)

        # Output device selector
        output_layout = QVBoxLayout()
        output_label = QLabel("🔊 Output:")
        output_label.setStyleSheet("font-size: 9px; color: gray;")

        self.output_combo = QComboBox()
        self.output_combo.setStyleSheet("font-size: 9px; padding: 2px;")
        self.output_combo.addItems(["Default Speakers", "Headphones", "External Speakers"])
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_combo)

        layout.addLayout(input_layout)
        layout.addLayout(output_layout)

        # Connect signals
        self.input_combo.currentTextChanged.connect(self.on_device_changed)
        self.output_combo.currentTextChanged.connect(self.on_device_changed)

        self.setLayout(layout)

    def on_device_changed(self):
        """Handle device selection changes."""
        input_device = self.input_combo.currentText()
        output_device = self.output_combo.currentText()
        self.device_changed.emit(input_device, output_device)

    def set_devices(self, input_devices: list, output_devices: list):
        """Update available devices."""
        self.input_combo.clear()
        self.input_combo.addItems(input_devices)
        self.output_combo.clear()
        self.output_combo.addItems(output_devices)