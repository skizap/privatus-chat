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
                    "primary": "#64b5f6",
                    "primary_variant": "#42a5f5",
                    "secondary": "#81c784",
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
                    "border": "#555555",
                    "hover": "#484848"
                }
            },
            
            "light": {
                "name": "Light Mode", 
                "description": "Clean light theme",
                "colors": {
                    "background": "#ffffff",
                    "surface": "#f5f5f5",
                    "primary": "#1976d2",
                    "primary_variant": "#1565c0",
                    "secondary": "#388e3c",
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
                    "border": "#e0e0e0",
                    "hover": "#eeeeee"
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
        
        /* Message Input */
        QLineEdit {{
            background-color: {colors.get("surface")};
            border: 2px solid {colors.get("border")};
            border-radius: 20px;
            padding: 8px 15px;
            color: {colors.get("text_primary")};
            font-size: 14px;
        }}
        QLineEdit:focus {{
            border-color: {colors.get("primary")};
        }}
        
        /* Send Button */
        QPushButton {{
            background-color: {colors.get("primary")};
            color: white;
            border: none;
            border-radius: 20px;
            padding: 8px 15px;
            font-weight: bold;
            font-size: 14px;
        }}
        QPushButton:hover {{
            background-color: {colors.get("primary_variant")};
        }}
        QPushButton:disabled {{
            background-color: {colors.get("text_disabled")};
        }}
        
        /* Contact List */
        QListWidget {{
            background-color: {colors.get("surface")};
            border: 1px solid {colors.get("border")};
            border-radius: 5px;
            color: {colors.get("text_primary")};
        }}
        QListWidget::item {{
            padding: 8px;
            border-bottom: 1px solid {colors.get("border")};
        }}
        QListWidget::item:hover {{
            background-color: {colors.get("hover")};
        }}
        QListWidget::item:selected {{
            background-color: {colors.get("primary")};
            color: white;
        }}
        
        /* Group Box */
        QGroupBox {{
            font-weight: bold;
            border: 2px solid {colors.get("border")};
            border-radius: 5px;
            margin-top: 10px;
            color: {colors.get("text_primary")};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }}
        
        /* Chat Area */
        QScrollArea {{
            background-color: {colors.get("background")};
            border: 1px solid {colors.get("border")};
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
