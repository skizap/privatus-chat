"""
Graphical User Interface Module

This module implements the PyQt6-based user interface for Privatus-chat,
providing an intuitive and secure chat experience with clear security indicators.

Key Components:
- Main chat interface
- Contact management
- Security status indicators
- Settings and configuration
- Accessibility features
"""

from .main_window import MainChatWindow
from .components import (
    SecurityIndicator,
    ContactListWidget,
    ChatAreaWidget,
    MessageInputWidget,
    PrivacyControlPanel,
    MessageWidget
)
from .gui_app import PrivatusChatGUI, run_gui_application
from .themes import ThemeManager, theme_manager, apply_theme
from .privacy_dashboard import PrivacyDashboard, CircuitVisualization, TrafficMetrics
from .settings_dialog import SettingsDialog

__all__ = [
    'MainChatWindow',
    'PrivatusChatGUI',
    'run_gui_application',
    'SecurityIndicator',
    'ContactListWidget',
    'ChatAreaWidget',
    'MessageInputWidget',
    'PrivacyControlPanel',
    'MessageWidget',
    'ThemeManager',
    'theme_manager',
    'apply_theme',
    'PrivacyDashboard',
    'CircuitVisualization',
    'TrafficMetrics',
    'SettingsDialog'
]