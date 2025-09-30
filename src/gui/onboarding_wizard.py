"""
Onboarding Wizard for Privatus-chat
Phase 3: Enhanced user experience with better onboarding
"""

from PyQt6.QtWidgets import (
    QWizard, QWizardPage, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QRadioButton, QButtonGroup, QTextEdit, QProgressBar,
    QGroupBox, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QIcon
import os


class WelcomePage(QWizardPage):
    """Welcome page for new users."""

    def __init__(self):
        super().__init__()
        self.setTitle("Welcome to Privatus-chat")
        self.setSubTitle("Secure, anonymous, decentralized messaging")
        self.setup_ui()

    def setup_ui(self):
        """Setup welcome page UI."""
        layout = QVBoxLayout()

        # Welcome message
        welcome_label = QLabel(
            "Welcome to Privatus-chat!\n\n"
            "This application provides secure, anonymous communication "
            "without relying on central servers. Your privacy and security "
            "are our top priorities.\n\n"
            "Let's get you set up with the optimal privacy settings."
        )
        welcome_label.setWordWrap(True)
        welcome_label.setFont(QFont("Arial", 11))
        layout.addWidget(welcome_label)

        # Security notice
        security_frame = QFrame()
        security_frame.setFrameStyle(QFrame.Shape.Box)
        security_frame.setStyleSheet("background-color: #e8f5e8; border: 1px solid #4caf50;")

        security_layout = QVBoxLayout()
        security_label = QLabel("🔒 Security First")
        security_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        security_label.setStyleSheet("color: #2e7d32;")
        security_layout.addWidget(security_label)

        security_text = QLabel(
            "All communications are end-to-end encrypted with perfect forward secrecy. "
            "Your messages are routed through multiple anonymous nodes to protect your identity."
        )
        security_text.setWordWrap(True)
        security_layout.addWidget(security_text)

        security_frame.setLayout(security_layout)
        layout.addWidget(security_frame)

        layout.addStretch()
        self.setLayout(layout)


class PrivacyLevelPage(QWizardPage):
    """Privacy level selection page."""

    def __init__(self):
        super().__init__()
        self.setTitle("Choose Your Privacy Level")
        self.setSubTitle("Select the level of anonymity and security for your communications")
        self.setup_ui()

    def setup_ui(self):
        """Setup privacy level selection UI."""
        layout = QVBoxLayout()

        # Privacy level description
        desc_label = QLabel(
            "Privatus-chat offers different privacy levels. Higher privacy levels provide "
            "stronger anonymity but may impact performance and usability."
        )
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        # Privacy level options
        self.privacy_group = QButtonGroup(self)

        # Minimal privacy
        minimal_frame = self._create_privacy_option(
            "Minimal Privacy",
            "Basic encryption with standard routing. Good for casual use.",
            "⚪", "#f44336", 0
        )
        layout.addWidget(minimal_frame)

        # Standard privacy
        standard_frame = self._create_privacy_option(
            "Standard Privacy",
            "End-to-end encryption with onion routing. Balanced security and performance.",
            "🟡", "#ff9800", 1
        )
        layout.addWidget(standard_frame)

        # High privacy
        high_frame = self._create_privacy_option(
            "High Privacy",
            "Advanced anonymity with traffic obfuscation and reputation systems. Recommended.",
            "🟢", "#4caf50", 2
        )
        layout.addWidget(high_frame)

        # Maximum privacy
        max_frame = self._create_privacy_option(
            "Maximum Privacy",
            "Extreme anonymity measures with all countermeasures enabled. May impact speed.",
            "🔵", "#2196f3", 3
        )
        layout.addWidget(max_frame)

        # Default selection
        self.privacy_group.button(2).setChecked(True)  # High privacy

        layout.addStretch()
        self.setLayout(layout)

    def _create_privacy_option(self, title: str, description: str,
                              icon: str, color: str, value: int) -> QFrame:
        """Create a privacy level option frame."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.Box)
        frame.setStyleSheet(f"border: 2px solid {color}; border-radius: 5px;")

        option_layout = QHBoxLayout()

        # Radio button
        radio = QRadioButton()
        radio.setStyleSheet(f"""
            QRadioButton::indicator {{
                width: 15px;
                height: 15px;
                border-radius: 7px;
                border: 2px solid {color};
            }}
            QRadioButton::indicator:checked {{
                background-color: {color};
            }}
        """)
        self.privacy_group.addButton(radio, value)
        option_layout.addWidget(radio)

        # Content
        content_layout = QVBoxLayout()

        title_label = QLabel(f"{icon} {title}")
        title_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title_label.setStyleSheet(f"color: {color};")
        content_layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #666;")
        content_layout.addWidget(desc_label)

        option_layout.addLayout(content_layout)
        option_layout.addStretch()

        frame.setLayout(option_layout)
        return frame

    def get_privacy_level(self) -> str:
        """Get selected privacy level."""
        level_map = {0: "Minimal", 1: "Standard", 2: "High", 3: "Maximum"}
        return level_map.get(self.privacy_group.checkedId(), "High")


class FeatureSetupPage(QWizardPage):
    """Feature setup and preferences page."""

    def __init__(self):
        super().__init__()
        self.setTitle("Setup Features")
        self.setSubTitle("Configure additional features and preferences")
        self.setup_ui()

    def setup_ui(self):
        """Setup feature configuration UI."""
        layout = QVBoxLayout()

        # Feature checkboxes
        features_group = QGroupBox("Enable Features")
        features_layout = QVBoxLayout()

        self.group_chat_cb = QCheckBox("Group Chat (with cryptographic group management)")
        self.group_chat_cb.setChecked(True)
        self.group_chat_cb.setToolTip("Enable secure multi-party group conversations")
        features_layout.addWidget(self.group_chat_cb)

        self.file_transfer_cb = QCheckBox("File Transfer (with resumable downloads)")
        self.file_transfer_cb.setChecked(True)
        self.file_transfer_cb.setToolTip("Enable secure file sharing with resume capability")
        features_layout.addWidget(self.file_transfer_cb)

        self.voice_calls_cb = QCheckBox("Voice Calls (with quality optimization)")
        self.voice_calls_cb.setChecked(True)
        self.voice_calls_cb.setToolTip("Enable encrypted voice communication")
        features_layout.addWidget(self.voice_calls_cb)

        self.anonymous_identity_cb = QCheckBox("Anonymous Identity Management")
        self.anonymous_identity_cb.setChecked(True)
        self.anonymous_identity_cb.setToolTip("Enable reputation-based identity system")
        features_layout.addWidget(self.anonymous_identity_cb)

        features_group.setLayout(features_layout)
        layout.addWidget(features_group)

        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()

        self.auto_updates_cb = QCheckBox("Automatic Security Updates")
        self.auto_updates_cb.setChecked(True)
        self.auto_updates_cb.setToolTip("Automatically update security components")
        advanced_layout.addWidget(self.auto_updates_cb)

        self.performance_monitoring_cb = QCheckBox("Performance Monitoring")
        self.performance_monitoring_cb.setChecked(True)
        self.performance_monitoring_cb.setToolTip("Monitor and optimize application performance")
        advanced_layout.addWidget(self.performance_monitoring_cb)

        self.detailed_logging_cb = QCheckBox("Detailed Security Logging")
        self.detailed_logging_cb.setChecked(False)
        self.detailed_logging_cb.setToolTip("Log detailed security events (may impact performance)")
        advanced_layout.addWidget(self.detailed_logging_cb)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        layout.addStretch()
        self.setLayout(layout)

    def get_feature_settings(self) -> dict:
        """Get feature settings."""
        return {
            "group_chat": self.group_chat_cb.isChecked(),
            "file_transfer": self.file_transfer_cb.isChecked(),
            "voice_calls": self.voice_calls_cb.isChecked(),
            "anonymous_identity": self.anonymous_identity_cb.isChecked(),
            "auto_updates": self.auto_updates_cb.isChecked(),
            "performance_monitoring": self.performance_monitoring_cb.isChecked(),
            "detailed_logging": self.detailed_logging_cb.isChecked()
        }


class SetupCompletePage(QWizardPage):
    """Setup completion page."""

    def __init__(self):
        super().__init__()
        self.setTitle("Setup Complete")
        self.setSubTitle("Your Privatus-chat is ready to use!")
        self.setup_ui()

    def setup_ui(self):
        """Setup completion page UI."""
        layout = QVBoxLayout()

        # Success message
        success_label = QLabel("✅ Setup Complete!")
        success_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        success_label.setStyleSheet("color: #4caf50;")
        success_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_label)

        # Summary
        summary_text = QTextEdit()
        summary_text.setReadOnly(True)
        summary_text.setMaximumHeight(150)
        summary_text.setPlainText(
            "Your Privatus-chat has been configured with:\n\n"
            "• End-to-end encryption with perfect forward secrecy\n"
            "• Onion routing for anonymous communication\n"
            "• Traffic analysis countermeasures\n"
            "• Anonymous identity management with reputation\n"
            "• Secure group chat with key rotation\n"
            "• Resumable file transfers\n"
            "• Optimized voice calls\n"
            "• Advanced privacy dashboard\n\n"
            "Remember: Your privacy depends on your usage patterns. "
            "Stay safe and communicate securely!"
        )
        layout.addWidget(summary_text)

        # Quick tips
        tips_group = QGroupBox("Quick Tips")
        tips_layout = QVBoxLayout()

        tips_text = QLabel(
            "• Use the privacy dashboard to monitor your anonymity\n"
            "• Build trust relationships with verified contacts\n"
            "• Regularly rotate your anonymous identities\n"
            "• Check file integrity after downloads\n"
            "• Monitor voice call quality metrics\n\n"
            "For more information, visit the user guide."
        )
        tips_text.setWordWrap(True)
        tips_layout.addWidget(tips_text)

        tips_group.setLayout(tips_layout)
        layout.addWidget(tips_group)

        layout.addStretch()
        self.setLayout(layout)


class OnboardingWizard(QWizard):
    """Complete onboarding wizard for new users."""

    setup_complete = pyqtSignal(dict)  # setup_settings

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Privatus-chat Setup")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.resize(700, 600)

        # Set window icon if available
        try:
            # This would normally load an icon file
            pass
        except:
            pass

        self.setup_pages()

    def setup_pages(self):
        """Setup wizard pages."""
        self.addPage(WelcomePage())
        self.addPage(PrivacyLevelPage())
        self.addPage(FeatureSetupPage())
        self.addPage(SetupCompletePage())

    def accept(self):
        """Handle wizard completion."""
        # Collect all settings
        settings = {}

        # Privacy level
        privacy_page = self.page(1)  # PrivacyLevelPage
        if hasattr(privacy_page, 'get_privacy_level'):
            settings['privacy_level'] = privacy_page.get_privacy_level()

        # Feature settings
        feature_page = self.page(2)  # FeatureSetupPage
        if hasattr(feature_page, 'get_feature_settings'):
            settings.update(feature_page.get_feature_settings())

        # Emit completion signal
        self.setup_complete.emit(settings)

        super().accept()

    @staticmethod
    def should_show_onboarding() -> bool:
        """Check if onboarding should be shown (first run)."""
        # This would check if the user has completed onboarding before
        # For now, always show for demo purposes
        return not os.path.exists(os.path.expanduser("~/.privatus-chat/onboarding_complete"))


# Integration with main window
def show_onboarding_if_needed(parent=None) -> bool:
    """Show onboarding wizard if needed."""
    if OnboardingWizard.should_show_onboarding():
        wizard = OnboardingWizard(parent)
        result = wizard.exec()

        if result == QWizard.DialogCode.Accepted:
            # Mark onboarding as complete
            os.makedirs(os.path.expanduser("~/.privatus-chat"), exist_ok=True)
            with open(os.path.expanduser("~/.privatus-chat/onboarding_complete"), 'w') as f:
                f.write("completed")

        return True
    return False