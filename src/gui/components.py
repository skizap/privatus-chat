"""
GUI Components for Privatus-chat

Individual UI components used throughout the application interface.
"""

from datetime import datetime
from typing import Dict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QLineEdit, QPushButton, QScrollArea, QFrame, QGroupBox, QComboBox, QCheckBox
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
    """Enhanced contact list with security indicators."""
    
    contact_selected = pyqtSignal(str)  # contact_id
    
    def __init__(self):
        super().__init__()
        self.contacts = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Setup contact list appearance."""
        self.setMaximumWidth(250)
        self.setMinimumWidth(200)
        
    def add_contact(self, contact_id: str, display_name: str, 
                   is_verified: bool = False, is_online: bool = False):
        """Add a contact to the list."""
        item = QListWidgetItem()
        
        # Create contact display with security indicators
        verification_icon = "✅" if is_verified else "⚠️"
        online_icon = "🟢" if is_online else "⚫"
        
        item.setText(f"{verification_icon} {online_icon} {display_name}")
        item.setData(Qt.ItemDataRole.UserRole, contact_id)
        
        if is_verified:
            item.setToolTip(f"{display_name}\nVerified Contact ✅\nKeys authenticated")
        else:
            item.setToolTip(f"{display_name}\nUnverified Contact ⚠️\nKey verification recommended")
            
        self.addItem(item)
        self.contacts[contact_id] = {
            'display_name': display_name,
            'is_verified': is_verified,
            'is_online': is_online,
            'item': item
        }
        
    def update_contact_status(self, contact_id: str, is_online: bool):
        """Update contact online status."""
        if contact_id in self.contacts:
            contact = self.contacts[contact_id]
            contact['is_online'] = is_online
            
            verification_icon = "✅" if contact['is_verified'] else "⚠️"
            online_icon = "🟢" if is_online else "⚫"
            
            contact['item'].setText(f"{verification_icon} {online_icon} {contact['display_name']}")

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


class MessageInputWidget(QWidget):
    """Message input area with send button."""
    
    message_sent = pyqtSignal(str)  # message text
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup message input UI."""
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Message input field
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your secure message here...")
        self.message_input.returnPressed.connect(self.send_message)
        
        # Send button
        self.send_button = QPushButton("Send 🔒")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setMinimumWidth(80)
        
        layout.addWidget(self.message_input)
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
        if enabled:
            self.send_button.setText("Send 🔒")
        else:
            self.send_button.setText("Offline")


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