#!/usr/bin/env python3
"""
Week 5 GUI Demo for Privatus-chat

Demonstrates the complete GUI implementation with all Week 5 features:
- PyQt6-based user interface
- Security status indicators  
- Contact management system
- Privacy control panel
- Real-time chat interface
- Integration with backend systems
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.gui import run_gui_application
from src.crypto import initialize_crypto_system, verify_entropy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_demo_environment():
    """Setup demo environment with temporary data directory."""
    demo_dir = Path.home() / ".privatus-chat-demo"
    demo_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (demo_dir / "keys").mkdir(exist_ok=True)
    (demo_dir / "db").mkdir(exist_ok=True)
    (demo_dir / "logs").mkdir(exist_ok=True)
    (demo_dir / "config").mkdir(exist_ok=True)
    
    logger.info(f"Demo environment created at: {demo_dir}")
    return demo_dir


def initialize_demo_crypto(demo_dir):
    """Initialize cryptographic system for demo."""
    logger.info("Initializing demo cryptographic system...")
    
    # Check entropy
    entropy = verify_entropy()
    logger.info(f"System entropy: {entropy:.1f} bits")
    
    # Initialize key manager
    key_storage_path = demo_dir / "keys"
    key_manager = initialize_crypto_system(key_storage_path)
    
    # Generate demo keys
    if not key_manager.identity_key:
        logger.info("Generating demo identity key...")
        identity_key = key_manager.generate_identity_key()
        logger.info(f"Demo identity key: {identity_key.key_id}")
    
    if not key_manager.signed_prekey:
        logger.info("Generating demo signed prekey...")
        signed_prekey = key_manager.generate_signed_prekey(1)
        logger.info(f"Demo signed prekey: {signed_prekey.key_id}")
    
    # Generate one-time prekeys
    if len(key_manager.one_time_prekeys) < 5:
        logger.info("Generating demo one-time prekeys...")
        new_prekeys = key_manager.generate_one_time_prekeys(5)
        logger.info(f"Generated {len(new_prekeys)} demo prekeys")
    
    return key_manager


def display_demo_info():
    """Display demo information."""
    print("\n" + "="*60)
    print("🎨 PRIVATUS-CHAT GUI DEMO - WEEK 5")
    print("="*60)
    print("This demo showcases the complete GUI implementation:")
    print()
    print("🖼️  User Interface Features:")
    print("   • Modern PyQt6-based chat interface")
    print("   • Real-time security status indicators")
    print("   • Contact list with verification status")
    print("   • Privacy controls panel")
    print("   • Message encryption indicators")
    print("   • Network connection status")
    print()
    print("🔐 Security Features:")
    print("   • Visual encryption status (🔒/🔓)")
    print("   • Privacy level indicators (🎭)")
    print("   • Contact verification status (✅/⚠️)")
    print("   • Network security indicators (🌐)")
    print()
    print("👥 Contact Management:")
    print("   • Add/remove contacts")
    print("   • Key verification status")
    print("   • Online/offline indicators")
    print("   • Security tooltips")
    print()
    print("⚙️  Privacy Controls:")
    print("   • Privacy level selection")
    print("   • Anonymous mode toggle")
    print("   • Traffic obfuscation options")
    print("   • Cover traffic controls")
    print()
    print("📱 Demo Features:")
    print("   • Sample contacts (Alice, Bob, Charlie)")
    print("   • Simulated message conversations")
    print("   • Real-time status updates")
    print("   • All GUI components functional")
    print("="*60)
    print("🚀 Launching GUI Demo...")
    print("="*60)


def main():
    """Main demo function."""
    try:
        print("Starting Privatus-chat GUI Demo...")
        
        # Display demo information
        display_demo_info()
        
        # Setup demo environment
        demo_dir = setup_demo_environment()
        
        # Initialize demo cryptographic system
        key_manager = initialize_demo_crypto(demo_dir)
        
        # Launch GUI application
        logger.info("Launching GUI demo...")
        return run_gui_application(
            app_data_dir=demo_dir,
            key_manager=key_manager
        )
        
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        print(f"\n❌ Demo Error: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure PyQt6 is installed: pip install PyQt6")
        print("2. Check Python version (3.11+ recommended)")
        print("3. Verify all dependencies are installed")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 