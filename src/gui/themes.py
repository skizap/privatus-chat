"""
Theme Management for Privatus-chat GUI

Provides comprehensive theme support including dark/light modes,
color schemes, and dynamic theme switching.
"""

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtWidgets import QApplication
from typing import Dict, Any
import json
import os


class ThemeManager(QObject):
    """Manages application themes and color schemes."""
    
    theme_changed = pyqtSignal(str)  # theme_name
    
    def __init__(self):
        super().__init__()
        self.current_theme = "dark"
        self.themes = self._load_default_themes()
        
    def _load_default_themes(self) -> Dict[str, Dict[str, Any]]:
        """Load default theme configurations."""
        return {
            "dark": {
                "name": "Dark Mode",
                "description": "Privacy-focused dark theme",
                "colors": {
                    "background": "#2b2b2b",
                    "surface": "#3c3c3c",
                    "surface_variant": "#484848",
                    "primary": "#64b5f6",
                    "primary_variant": "#42a5f5",
                    "secondary": "#81c784",
                    "secondary_variant": "#66bb6a",
                    "text_primary": "#ffffff",
                    "text_secondary": "#b0b0b0",
                    "text_disabled": "#757575",
                    "accent": "#ffa726",
                    "error": "#f44336",
                    "warning": "#ff9800",
                    "success": "#4caf50",
                    "info": "#2196f3",
                    "chat_outgoing": "#1e3a5f",
                    "chat_incoming": "#424242",
                    "chat_bubble_outgoing": "#1976d2",
                    "chat_bubble_incoming": "#424242",
                    "border": "#555555",
                    "hover": "#484848",
                    "focus": "#64b5f6",
                    "selection": "#64b5f640",
                    "scrollbar": "#555555",
                    "scrollbar_hover": "#666666",
                    "button_hover": "#484848",
                    "input_background": "#3c3c3c",
                    "tooltip": "#484848",
                    "overlay": "#00000080"
                }
            },

            "light": {
                "name": "Light Mode",
                "description": "Clean light theme",
                "colors": {
                    "background": "#ffffff",
                    "surface": "#f5f5f5",
                    "surface_variant": "#eeeeee",
                    "primary": "#1976d2",
                    "primary_variant": "#1565c0",
                    "secondary": "#388e3c",
                    "secondary_variant": "#2e7d32",
                    "text_primary": "#212121",
                    "text_secondary": "#757575",
                    "text_disabled": "#bdbdbd",
                    "accent": "#ff5722",
                    "error": "#d32f2f",
                    "warning": "#f57c00",
                    "success": "#388e3c",
                    "info": "#1976d2",
                    "chat_outgoing": "#e3f2fd",
                    "chat_incoming": "#f5f5f5",
                    "chat_bubble_outgoing": "#1976d2",
                    "chat_bubble_incoming": "#424242",
                    "border": "#e0e0e0",
                    "hover": "#eeeeee",
                    "focus": "#1976d2",
                    "selection": "#1976d240",
                    "scrollbar": "#cccccc",
                    "scrollbar_hover": "#aaaaaa",
                    "button_hover": "#eeeeee",
                    "input_background": "#ffffff",
                    "tooltip": "#f5f5f5",
                    "overlay": "#00000040"
                }
            }
        }
    
    def apply_theme(self, theme_name: str):
        """Apply a theme to the application."""
        if theme_name not in self.themes:
            return False
            
        theme = self.themes[theme_name]
        app = QApplication.instance()
        
        if app:
            # Build and apply stylesheet
            style_sheet = self._build_stylesheet(theme)
            app.setStyleSheet(style_sheet)
            
            # Set application palette
            palette = self._build_palette(theme)
            app.setPalette(palette)
            
            self.current_theme = theme_name
            self.theme_changed.emit(theme_name)
            
            return True
            
        return False
    
    def _build_stylesheet(self, theme: Dict[str, Any]) -> str:
        """Build complete stylesheet from theme."""
        colors = theme.get("colors", {})

        # Build comprehensive stylesheet
        styles = f"""
        /* Main Window */
        QMainWindow {{
            background-color: {colors.get("background")};
            color: {colors.get("text_primary")};
        }}

        /* Input Fields */
        QLineEdit {{
            background-color: {colors.get("input_background")};
            border: 2px solid {colors.get("border")};
            border-radius: 20px;
            padding: 8px 15px;
            color: {colors.get("text_primary")};
            font-size: 14px;
        }}
        QLineEdit:focus {{
            border-color: {colors.get("focus")};
        }}
        QLineEdit:disabled {{
            background-color: {colors.get("surface_variant")};
            color: {colors.get("text_disabled")};
        }}

        /* Buttons */
        QPushButton {{
            background-color: {colors.get("primary")};
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background-color: {colors.get("primary_variant")};
        }}
        QPushButton:pressed {{
            background-color: {colors.get("primary_variant")};
        }}
        QPushButton:disabled {{
            background-color: {colors.get("text_disabled")};
            color: {colors.get("text_secondary")};
        }}

        /* Secondary Buttons */
        QPushButton[secondary="true"] {{
            background-color: {colors.get("secondary")};
        }}
        QPushButton[secondary="true"]:hover {{
            background-color: {colors.get("secondary_variant")};
        }}

        /* Contact List */
        QListWidget {{
            background-color: {colors.get("surface")};
            border: 1px solid {colors.get("border")};
            border-radius: 5px;
            color: {colors.get("text_primary")};
            outline: none;
        }}
        QListWidget::item {{
            padding: 8px;
            border-bottom: 1px solid {colors.get("border")};
            border-radius: 3px;
        }}
        QListWidget::item:hover {{
            background-color: {colors.get("hover")};
        }}
        QListWidget::item:selected {{
            background-color: {colors.get("selection")};
            color: {colors.get("primary")};
        }}

        /* Group Box */
        QGroupBox {{
            font-weight: bold;
            border: 2px solid {colors.get("border")};
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 15px;
            color: {colors.get("text_primary")};
            background-color: {colors.get("surface")};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px 0 8px;
            background-color: {colors.get("background")};
            color: {colors.get("primary")};
        }}

        /* Chat Area */
        QScrollArea {{
            background-color: {colors.get("background")};
            border: 1px solid {colors.get("border")};
            border-radius: 8px;
        }}

        /* Scroll Bars */
        QScrollBar:vertical {{
            background-color: {colors.get("surface")};
            width: 12px;
            margin: 2px;
            border-radius: 6px;
        }}
        QScrollBar::handle:vertical {{
            background-color: {colors.get("scrollbar")};
            min-height: 20px;
            border-radius: 6px;
        }}
        QScrollBar::handle:vertical:hover {{
            background-color: {colors.get("scrollbar_hover")};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}

        /* Progress Bars */
        QProgressBar {{
            border: 1px solid {colors.get("border")};
            border-radius: 4px;
            text-align: center;
            font-size: 10px;
            background-color: {colors.get("surface")};
        }}
        QProgressBar::chunk {{
            background-color: {colors.get("success")};
            border-radius: 3px;
        }}

        /* Tabs */
        QTabWidget::pane {{
            border: 1px solid {colors.get("border")};
            border-radius: 5px;
            background-color: {colors.get("surface")};
        }}
        QTabBar::tab {{
            background-color: {colors.get("surface_variant")};
            color: {colors.get("text_primary")};
            border: 1px solid {colors.get("border")};
            border-bottom: none;
            padding: 8px 12px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }}
        QTabBar::tab:selected {{
            background-color: {colors.get("primary")};
            color: white;
        }}
        QTabBar::tab:hover {{
            background-color: {colors.get("hover")};
        }}

        /* Tooltips */
        QToolTip {{
            background-color: {colors.get("tooltip")};
            color: {colors.get("text_primary")};
            border: 1px solid {colors.get("border")};
            border-radius: 4px;
            padding: 5px;
        }}

        /* Status Indicators */
        QLabel[status="success"] {{
            color: {colors.get("success")};
            font-weight: bold;
        }}
        QLabel[status="warning"] {{
            color: {colors.get("warning")};
            font-weight: bold;
        }}
        QLabel[status="error"] {{
            color: {colors.get("error")};
            font-weight: bold;
        }}
        QLabel[status="info"] {{
            color: {colors.get("info")};
            font-weight: bold;
        }}

        /* Chat Messages */
        QLabel[message="outgoing"] {{
            background-color: {colors.get("chat_bubble_outgoing")};
            color: white;
            padding: 8px 12px;
            border-radius: 12px;
            margin: 2px 50px 2px 10px;
        }}
        QLabel[message="incoming"] {{
            background-color: {colors.get("chat_bubble_incoming")};
            color: {colors.get("text_primary")};
            padding: 8px 12px;
            border-radius: 12px;
            margin: 2px 10px 2px 50px;
        }}

        /* File Transfer Widgets */
        QWidget[transfer="active"] {{
            background-color: {colors.get("surface")};
            border: 1px solid {colors.get("primary")};
            border-radius: 5px;
        }}
        QWidget[transfer="completed"] {{
            background-color: {colors.get("success")};
            border: 1px solid {colors.get("success")};
            border-radius: 5px;
        }}
        QWidget[transfer="failed"] {{
            background-color: {colors.get("error")};
            border: 1px solid {colors.get("error")};
            border-radius: 5px;
        }}

        /* Privacy Dashboard */
        QWidget[privacy="high"] {{
            border: 2px solid {colors.get("success")};
        }}
        QWidget[privacy="medium"] {{
            border: 2px solid {colors.get("warning")};
        }}
        QWidget[privacy="low"] {{
            border: 2px solid {colors.get("error")};
        }}

        /* Voice Call Status */
        QWidget[call="active"] {{
            background-color: {colors.get("success")};
            color: white;
            border-radius: 5px;
        }}
        QWidget[call="ringing"] {{
            background-color: {colors.get("warning")};
            color: white;
            border-radius: 5px;
        }}
        QWidget[call="ended"] {{
            background-color: {colors.get("surface")};
            color: {colors.get("text_secondary")};
            border-radius: 5px;
        }}
        """

        return styles
    
    def _build_palette(self, theme: Dict[str, Any]) -> QPalette:
        """Build QPalette from theme colors."""
        colors = theme.get("colors", {})
        palette = QPalette()
        
        # Set palette colors
        palette.setColor(QPalette.ColorRole.Window, QColor(colors.get("background")))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(colors.get("text_primary")))
        palette.setColor(QPalette.ColorRole.Base, QColor(colors.get("surface")))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(colors.get("hover")))
        palette.setColor(QPalette.ColorRole.Text, QColor(colors.get("text_primary")))
        palette.setColor(QPalette.ColorRole.Button, QColor(colors.get("surface")))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(colors.get("text_primary")))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(colors.get("primary")))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        
        return palette
    
    def get_color(self, color_name: str) -> str:
        """Get color value from current theme."""
        theme = self.themes.get(self.current_theme, {})
        colors = theme.get("colors", {})
        return colors.get(color_name, "#000000")
    
    def get_available_themes(self) -> Dict[str, str]:
        """Get list of available themes."""
        return {name: theme["name"] for name, theme in self.themes.items()}


# Global theme manager instance
theme_manager = ThemeManager()


def apply_theme(theme_name: str) -> bool:
    """Apply theme globally."""
    return theme_manager.apply_theme(theme_name)


def get_current_theme() -> str:
    """Get current theme name."""
    return theme_manager.current_theme


def get_theme_color(color_name: str) -> str:
    """Get color from current theme."""
    return theme_manager.get_color(color_name)
