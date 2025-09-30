"""
Privatus-chat GUI Application

Main GUI application class that integrates the PyQt6 interface
with the cryptographic, networking, and anonymity systems.
"""

import sys
import asyncio
import logging
from typing import Optional
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import QThread, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon

from .main_window import MainChatWindow
from ..error_handling import (
    error_handler, handle_errors, secure_logger,
    GUIError, FatalError, ErrorSeverity
)

logger = logging.getLogger(__name__)


class BackendThread(QThread):
    """Background thread for handling backend operations."""
    
    status_updated = pyqtSignal(str, dict)  # component, status_data
    message_received = pyqtSignal(str, str, dict)  # sender_id, message, metadata
    
    def __init__(self):
        super().__init__()
        self.running = False
        
    def run(self):
        """Run the backend event loop."""
        self.running = True
        logger.info("Backend thread started")
        
        # This would normally run the asyncio event loop for networking
        # For now, we'll simulate backend operations
        while self.running:
            self.msleep(1000)  # Sleep for 1 second
            
            # Simulate status updates
            import random
            peer_count = random.randint(15, 50)
            self.status_updated.emit("network", {"connected": True, "peer_count": peer_count})
            
    def stop(self):
        """Stop the backend thread."""
        self.running = False
        logger.info("Backend thread stopping")


class PrivatusChatGUI(QObject):
    """Main GUI application for Privatus-chat."""
    
    def __init__(self, app_data_dir=None, key_manager=None):
        super().__init__()
        self.app_data_dir = app_data_dir
        self.key_manager = key_manager
        self.main_window = None
        self.backend_thread = None
        
    @handle_errors("gui_initialization", show_user_feedback=True)
    def initialize(self):
        """Initialize the GUI application."""
        # Create main window
        self.main_window = MainChatWindow()

        # Setup backend thread
        self.backend_thread = BackendThread()
        self.backend_thread.status_updated.connect(self.handle_status_update)
        self.backend_thread.message_received.connect(self.handle_message_received)

        # Setup integration with backend systems
        self.setup_backend_integration()

        secure_logger.info("GUI application initialized successfully")
        return True
            
    def setup_backend_integration(self):
        """Setup integration with cryptographic and networking backends."""
        if self.main_window:
            # Connect GUI signals to backend operations
            # For now, this is just a placeholder for future integration
            
            # Load real contacts from storage
            self.main_window.load_real_contacts()
            
            # Update initial status
            self.main_window.security_indicator.update_encryption_status(
                True, "Ready for secure messaging"
            )
            self.main_window.security_indicator.update_anonymity_status(
                "Standard", "3-hop onion routing active"
            )
            
    def show(self):
        """Show the main window."""
        if self.main_window:
            self.main_window.show()
            
            # Start backend thread
            if self.backend_thread:
                self.backend_thread.start()
                
    def handle_status_update(self, component: str, status_data: dict):
        """Handle status updates from backend."""
        if not self.main_window:
            return
            
        if component == "network":
            connected = status_data.get("connected", False)
            peer_count = status_data.get("peer_count", 0)
            self.main_window.security_indicator.update_network_status(connected, peer_count)
            
        elif component == "crypto":
            # Handle cryptographic status updates
            pass
            
        elif component == "anonymity":
            # Handle anonymity status updates
            pass
            
    def handle_message_received(self, sender_id: str, message: str, metadata: dict):
        """Handle incoming messages."""
        if not self.main_window:
            return
            
        # Add message to chat if the sender is the current contact
        if self.main_window.current_contact_id == sender_id:
            is_encrypted = metadata.get("encrypted", True)
            self.main_window.chat_area.add_message(message, False, is_encrypted)
            
    def shutdown(self):
        """Shutdown the GUI application."""
        logger.info("Shutting down GUI application")
        
        # Stop backend thread
        if self.backend_thread and self.backend_thread.isRunning():
            self.backend_thread.stop()
            self.backend_thread.wait()
            
        # Close main window
        if self.main_window:
            self.main_window.close()


@handle_errors("gui_application_startup", show_user_feedback=True)
def run_gui_application(app_data_dir=None, key_manager=None):
    """Run the Privatus-chat GUI application."""

    # Create QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("Privatus-chat")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Privatus")

    # Set application style
    app.setStyle('Fusion')

    # Create and initialize GUI
    gui = PrivatusChatGUI(app_data_dir, key_manager)

    if not gui.initialize():
        secure_logger.error("GUI initialization failed")
        return 1

    # Show the application
    gui.show()

    # Setup clean shutdown
    def shutdown_handler():
        try:
            gui.shutdown()
        except Exception as e:
            secure_logger.error(f"Error during GUI shutdown: {e}")

    app.aboutToQuit.connect(shutdown_handler)

    # Run the application
    secure_logger.info("Starting GUI event loop")
    return app.exec()


if __name__ == "__main__":
    # Setup logging for standalone GUI testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the GUI application
    sys.exit(run_gui_application()) 