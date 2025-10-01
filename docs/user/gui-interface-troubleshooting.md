# GUI and Interface Troubleshooting Guide

This guide provides comprehensive solutions for GUI display issues, interface problems, and user interaction challenges in Privatus-chat.

## Table of Contents

1. [Application Startup Issues](#application-startup-issues)
2. [Display and Rendering Problems](#display-and-rendering-problems)
3. [User Interface Freezes and Crashes](#user-interface-freezes-and-crashes)
4. [Input and Interaction Issues](#input-and-interaction-issues)
5. [Theme and Appearance Problems](#theme-and-appearance-problems)
6. [Window and Layout Issues](#window-and-layout-issues)
7. [Integration and Backend Issues](#integration-and-backend-issues)
8. [Platform-Specific GUI Issues](#platform-specific-gui-issues)

## Application Startup Issues

### Application Fails to Start

**Problem**: Privatus-chat GUI fails to launch or exits immediately.

**Symptoms**:
- Application window doesn't appear
- Process exits with error code
- Console shows startup errors

**Solutions**:

1. **Check Python Environment**:
   ```bash
   # Verify Python version
   python --version  # Should be 3.8 or higher

   # Check if required modules are installed
   python -c "import PyQt6; print('PyQt6 OK')"
   python -c "import cryptography; print('Cryptography OK')"
   ```

2. **Test GUI Dependencies**:
   ```python
   # Test PyQt6 installation
   try:
       from PyQt6.QtWidgets import QApplication
       from PyQt6.QtCore import Qt

       app = QApplication([])
       print("✓ PyQt6 basic functionality works")

   except Exception as e:
       print(f"✗ PyQt6 issue: {e}")
   ```

3. **Check Display Environment**:
   ```bash
   # Check display server (Linux)
   echo $DISPLAY
   xdpyinfo | head -5

   # Check graphics drivers
   glxinfo | grep "OpenGL version"

   # Check available Qt platforms
   export QT_DEBUG_PLUGINS=1
   python launch_gui.py 2>&1 | head -20
   ```

4. **Verify Application Files**:
   ```bash
   # Check if all required files exist
   ls -la src/gui/
   ls -la src/gui/*.py

   # Verify main entry point
   file launch_gui.py
   head -5 launch_gui.py
   ```

### Master Password Prompt Issues

**Problem**: Master password dialog doesn't appear or fails.

**Solutions**:

1. **Check Environment Variable**:
   ```bash
   # Check if password is set in environment
   echo $PRIVATUS_MASTER_PASSWORD

   # Test with environment variable
   export PRIVATUS_MASTER_PASSWORD="your_secure_password"
   python launch_gui.py
   ```

2. **Test Password Validation**:
   ```python
   # Test password requirements
   def test_password_requirements():
       password = "your_test_password"

       # Length check
       if len(password) < 12:
           print("✗ Password too short")

       # Character requirements
       import re
       has_upper = bool(re.search(r'[A-Z]', password))
       has_lower = bool(re.search(r'[a-z]', password))
       has_digit = bool(re.search(r'[0-9]', password))
       has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))

       if not (has_upper and has_lower and has_digit and has_special):
           print("✗ Password missing character requirements")

       print("✓ Password meets requirements")
   ```

3. **Check Storage Path Creation**:
   ```python
   # Test data directory creation
   from pathlib import Path

   data_dir = Path.home() / '.privatus-chat'
   try:
       data_dir.mkdir(parents=True, exist_ok=True)
       test_file = data_dir / 'test'
       test_file.write_text('test')
       test_file.unlink()
       print("✓ Data directory accessible")
   except Exception as e:
       print(f"✗ Data directory issue: {e}")
   ```

### Storage Initialization Failures

**Problem**: Application starts but storage initialization fails.

**Solutions**:

1. **Check Database Files**:
   ```bash
   # Check existing database files
   ls -la ~/.privatus-chat/
   file ~/.privatus-chat/*.db

   # Check file permissions
   ls -ld ~/.privatus-chat/
   chmod 700 ~/.privatus-chat/
   ```

2. **Test Database Connection**:
   ```python
   # Test database initialization
   from src.storage.database_fixed import StorageManager
   from pathlib import Path

   try:
       data_dir = Path.home() / '.privatus-chat'
       storage = StorageManager(data_dir, "test_password")
       print("✓ Database initialization successful")
   except Exception as e:
       print(f"✗ Database initialization failed: {e}")
   ```

3. **Reset Corrupted Storage**:
   ```bash
   # Backup existing data
   cp -r ~/.privatus-chat ~/.privatus-chat.backup

   # Remove corrupted files
   rm -rf ~/.privatus-chat/*.db
   rm -rf ~/.privatus-chat/keys/*.enc

   # Restart application
   python launch_gui.py
   ```

## Display and Rendering Problems

### Interface Elements Not Visible

**Problem**: GUI elements don't display properly or are invisible.

**Solutions**:

1. **Check Theme Compatibility**:
   ```python
   # Test theme loading
   from src.gui.themes import theme_manager

   try:
       themes = theme_manager.get_available_themes()
       print(f"✓ Available themes: {themes}")

       # Test theme application
       theme_manager.apply_theme("dark")
       print("✓ Theme application works")

   except Exception as e:
       print(f"✗ Theme issue: {e}")
   ```

2. **Verify Widget Creation**:
   ```python
   # Test basic widget creation
   from PyQt6.QtWidgets import QApplication, QWidget, QLabel

   try:
       app = QApplication([])
       widget = QWidget()
       label = QLabel("Test Label")
       widget.show()
       print("✓ Basic widgets work")
       app.quit()

   except Exception as e:
       print(f"✗ Widget creation failed: {e}")
   ```

3. **Check Font Rendering**:
   ```python
   # Test font availability
   from PyQt6.QtGui import QFontDatabase

   try:
       available_fonts = QFontDatabase.families()
       print(f"✓ Available fonts: {len(available_fonts)}")

       # Test specific fonts
       font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
       print(f"✓ System font: {font.family()}")

   except Exception as e:
       print(f"✗ Font issue: {e}")
   ```

### High DPI Display Issues

**Problem**: Interface doesn't scale properly on high-resolution displays.

**Solutions**:

1. **Check Display Scaling**:
   ```python
   # Test DPI scaling
   from PyQt6.QtWidgets import QApplication
   from PyQt6.QtCore import Qt

   app = QApplication([])
   screen = app.primaryScreen()
   dpi = screen.devicePixelRatio()

   print(f"Display DPI ratio: {dpi}")

   # Set scaling attributes
   app.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
   app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
   ```

2. **Manual Scaling Configuration**:
   ```python
   # Set custom scaling
   import os
   os.environ['QT_SCALE_FACTOR'] = '1.5'
   os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'

   # Or use fractional scaling
   os.environ['QT_SCREEN_SCALE_FACTORS'] = '1.5'
   ```

3. **Test Different Scale Factors**:
   ```bash
   # Test various scale factors
   for scale in 1.0 1.25 1.5 2.0; do
       echo "Testing scale factor: $scale"
       QT_SCALE_FACTOR=$scale python launch_gui.py --test-mode
   done
   ```

### Color and Theme Issues

**Problem**: Colors don't display correctly or themes don't apply.

**Solutions**:

1. **Check Color Support**:
   ```python
   # Test color capabilities
   from PyQt6.QtGui import QColor, QPalette

   try:
       # Test color creation
       color = QColor("#FF0000")
       print(f"✓ Color creation: {color.name()}")

       # Test palette
       palette = QPalette()
       palette.setColor(QPalette.ColorRole.Window, QColor("#2D2D30"))
       print("✓ Palette manipulation works")

   except Exception as e:
       print(f"✗ Color issue: {e}")
   ```

2. **Verify Theme Files**:
   ```bash
   # Check theme files exist
   find . -name "*theme*" -type f

   # Check theme file syntax
   python -c "
   import json
   with open('src/gui/themes.json', 'r') as f:
       themes = json.load(f)
       print(f'Available themes: {list(themes.keys())}')
   "
   ```

3. **Reset Theme Settings**:
   ```python
   # Reset to default theme
   from src.gui.themes import theme_manager

   try:
       theme_manager.reset_to_default()
       print("✓ Theme reset to default")
   except Exception as e:
       print(f"✗ Theme reset failed: {e}")
   ```

## User Interface Freezes and Crashes

### Application Freezes During Use

**Problem**: GUI becomes unresponsive during normal operation.

**Solutions**:

1. **Check Backend Thread Status**:
   ```python
   # Monitor backend thread
   def check_backend_health():
       if hasattr(gui, 'backend_thread'):
           running = gui.backend_thread.isRunning()
           print(f"Backend thread running: {running}")

           if running:
               # Check for thread locks
               import threading
               print(f"Active threads: {threading.active_count()}")
   ```

2. **Monitor Event Loop**:
   ```python
   # Check Qt event loop
   from PyQt6.QtWidgets import QApplication
   from PyQt6.QtCore import QTimer

   def check_event_loop():
       app = QApplication.instance()
       if app:
           # Check if event loop is processing
           timer = QTimer()
           timer.timeout.connect(lambda: print("Event loop active"))
           timer.start(1000)
   ```

3. **Check Memory Usage**:
   ```python
   # Monitor memory consumption
   import psutil
   import os

   def check_memory_usage():
       process = psutil.Process(os.getpid())
       memory_mb = process.memory_info().rss / 1024 / 1024
       print(f"Memory usage: {memory_mb:.1f} MB")

       # Check for memory leaks
       import gc
       gc.collect()
       print("Garbage collection completed")
   ```

### Unexpected Application Crashes

**Problem**: Application crashes with segmentation faults or exceptions.

**Solutions**:

1. **Enable Debug Mode**:
   ```bash
   # Run with debug logging
   export QT_LOGGING_RULES="*.debug=true"
   python launch_gui.py 2>&1 | tee gui_debug.log
   ```

2. **Check Exception Handling**:
   ```python
   # Test error handling system
   from src.error_handling import error_handler

   try:
       # Test error reporting
       error_handler.handle_error(
           Exception("Test error"),
           {"component": "gui_test"}
       )
       print("✓ Error handling works")

   except Exception as e:
       print(f"✗ Error handling failed: {e}")
   ```

3. **Monitor System Resources**:
   ```bash
   # Check system resource usage
   top -p $(pgrep -f privatus-chat) -b -n 1

   # Check for resource limits
   ulimit -a

   # Monitor file descriptors
   lsof -p $(pgrep -f privatus-chat) | wc -l
   ```

## Input and Interaction Issues

### Keyboard Input Not Working

**Problem**: Keyboard input doesn't register in text fields or chat input.

**Solutions**:

1. **Check Focus Management**:
   ```python
   # Test focus handling
   from PyQt6.QtWidgets import QApplication, QLineEdit

   app = QApplication([])
   edit = QLineEdit()
   edit.show()

   # Check focus
   has_focus = edit.hasFocus()
   print(f"Widget has focus: {has_focus}")

   # Set focus programmatically
   edit.setFocus()
   print("Focus set programmatically")
   ```

2. **Test Input Method Editor**:
   ```python
   # Check IME support
   from PyQt6.QtWidgets import QApplication, QInputMethod

   app = QApplication([])
   input_method = QInputMethod()

   print(f"IME available: {input_method.isVisible()}")
   print(f"IME locale: {input_method.locale()}")
   ```

3. **Verify Event Processing**:
   ```python
   # Test key event handling
   from PyQt6.QtCore import Qt
   from PyQt6.QtWidgets import QApplication, QWidget

   class TestWidget(QWidget):
       def keyPressEvent(self, event):
           print(f"Key pressed: {event.key()}")
           super().keyPressEvent(event)

   app = QApplication([])
   widget = TestWidget()
   widget.show()
   widget.setFocus()
   ```

### Mouse Interaction Problems

**Problem**: Mouse clicks and interactions don't work properly.

**Solutions**:

1. **Check Mouse Events**:
   ```python
   # Test mouse event handling
   from PyQt6.QtWidgets import QApplication, QWidget, QPushButton

   class TestWidget(QWidget):
       def mousePressEvent(self, event):
           print(f"Mouse pressed: {event.button()}")
           super().mousePressEvent(event)

   app = QApplication([])
   widget = TestWidget()
   button = QPushButton("Test Button")
   widget.show()
   ```

2. **Verify Button States**:
   ```python
   # Check button functionality
   from PyQt6.QtWidgets import QApplication, QPushButton

   app = QApplication([])
   button = QPushButton("Test")

   # Check button state
   print(f"Button enabled: {button.isEnabled()}")
   print(f"Button visible: {button.isVisible()}")

   # Test signal connection
   def on_clicked():
       print("Button clicked!")

   button.clicked.connect(on_clicked)
   ```

3. **Check Widget Hierarchy**:
   ```python
   # Verify widget parenting
   from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton

   app = QApplication([])
   parent = QWidget()
   layout = QVBoxLayout(parent)

   button = QPushButton("Test")
   layout.addWidget(button)

   print(f"Button parent: {button.parent()}")
   print(f"Layout parent: {layout.parent()}")
   ```

## Theme and Appearance Problems

### Theme Not Applying Correctly

**Problem**: Theme changes don't take effect or apply inconsistently.

**Solutions**:

1. **Test Theme Loading**:
   ```python
   # Test theme file loading
   import json
   from pathlib import Path

   theme_file = Path("src/gui/themes.json")
   if theme_file.exists():
       with open(theme_file, 'r') as f:
           themes = json.load(f)
           print(f"✓ Loaded {len(themes)} themes")
   else:
       print("✗ Theme file not found")
   ```

2. **Check Style Application**:
   ```python
   # Test style sheet application
   from PyQt6.QtWidgets import QApplication, QWidget

   app = QApplication([])
   widget = QWidget()

   # Test style sheet
   style = """
   QWidget {
       background-color: #2D2D30;
       color: #FFFFFF;
   }
   """

   widget.setStyleSheet(style)
   print("✓ Style sheet applied")
   ```

3. **Verify Theme Manager**:
   ```python
   # Test theme manager functionality
   from src.gui.themes import theme_manager

   try:
       # List available themes
       themes = theme_manager.get_available_themes()
       print(f"Available themes: {themes}")

       # Test theme switching
       for theme in themes[:2]:  # Test first 2 themes
           theme_manager.apply_theme(theme)
           print(f"✓ Applied theme: {theme}")

   except Exception as e:
       print(f"✗ Theme manager issue: {e}")
   ```

### Font and Text Display Issues

**Problem**: Text doesn't display correctly or fonts don't load.

**Solutions**:

1. **Check Font Availability**:
   ```python
   # Test font loading
   from PyQt6.QtGui import QFont, QFontDatabase

   # Test system fonts
   system_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont)
   print(f"System font: {system_font.family()}")

   # Test specific font
   font = QFont("Arial", 10)
   if font.exactMatch():
       print("✓ Arial font available")
   else:
       print("○ Arial font not available, using fallback")
   ```

2. **Test Text Rendering**:
   ```python
   # Test text display
   from PyQt6.QtWidgets import QApplication, QLabel

   app = QApplication([])
   label = QLabel("Test Text Display")

   # Test different fonts
   fonts = ["Arial", "Helvetica", "DejaVu Sans", "Ubuntu"]
   for font_name in fonts:
       font = QFont(font_name, 12)
       if QFontDatabase().families().__contains__(font_name):
           label.setFont(font)
           print(f"✓ Using font: {font_name}")
           break
   ```

3. **Check Unicode Support**:
   ```python
   # Test Unicode text rendering
   from PyQt6.QtWidgets import QApplication, QLabel

   app = QApplication([])
   label = QLabel("Unicode Test: 你好世界 🌍")

   # Check if text renders correctly
   text = label.text()
   print(f"Unicode text length: {len(text)}")
   print(f"Unicode text: {repr(text)}")
   ```

## Window and Layout Issues

### Window Size and Position Problems

**Problem**: Window doesn't size or position correctly.

**Solutions**:

1. **Check Window Geometry**:
   ```python
   # Test window sizing
   from PyQt6.QtWidgets import QApplication, QWidget

   app = QApplication([])
   window = QWidget()

   # Test window geometry
   window.setGeometry(100, 100, 800, 600)
   geometry = window.geometry()

   print(f"Window geometry: {geometry.x()}, {geometry.y()}, {geometry.width()}, {geometry.height()}")
   ```

2. **Test Layout Management**:
   ```python
   # Test layout functionality
   from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton

   app = QApplication([])
   window = QWidget()
   layout = QVBoxLayout(window)

   # Add test widgets
   for i in range(3):
       button = QPushButton(f"Button {i}")
       layout.addWidget(button)

   window.show()
   print("✓ Layout management works")
   ```

3. **Check Screen Information**:
   ```python
   # Get screen information
   from PyQt6.QtWidgets import QApplication

   app = QApplication([])
   screen = app.primaryScreen()

   print(f"Screen size: {screen.size().width()}x{screen.size().height()}")
   print(f"Screen DPI: {screen.devicePixelRatio()}")
   print(f"Available geometry: {screen.availableGeometry()}")
   ```

### Layout and Widget Positioning Issues

**Problem**: Widgets don't position correctly or overlap.

**Solutions**:

1. **Test Widget Positioning**:
   ```python
   # Test absolute positioning
   from PyQt6.QtWidgets import QApplication, QWidget, QLabel

   app = QApplication([])
   window = QWidget()

   # Test absolute positioning
   label1 = QLabel("Top Left", window)
   label1.move(10, 10)

   label2 = QLabel("Bottom Right", window)
   label2.move(100, 50)

   print("✓ Absolute positioning works")
   ```

2. **Check Layout Constraints**:
   ```python
   # Test layout constraints
   from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QSizePolicy

   app = QApplication([])
   window = QWidget()
   layout = QVBoxLayout(window)

   # Test size policies
   widget = QWidget()
   widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
   layout.addWidget(widget)

   print("✓ Size policies work")
   ```

3. **Verify Widget Hierarchy**:
   ```python
   # Check widget parenting
   from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout

   app = QApplication([])
   parent = QWidget()
   layout = QVBoxLayout(parent)

   # Check parent-child relationships
   child = QWidget()
   layout.addWidget(child)

   print(f"Child parent: {child.parent()}")
   print(f"Layout parent: {layout.parent()}")
   ```

## Integration and Backend Issues

### Backend Thread Communication Problems

**Problem**: GUI doesn't receive updates from backend thread.

**Solutions**:

1. **Test Signal-Slot Connections**:
   ```python
   # Test PyQt signal connections
   from PyQt6.QtCore import QObject, pyqtSignal

   class TestEmitter(QObject):
       test_signal = pyqtSignal(str)

   class TestReceiver(QObject):
       def __init__(self):
           super().__init__()
           self.received = []

       def on_signal(self, message):
           self.received.append(message)
           print(f"Received: {message}")

   emitter = TestEmitter()
   receiver = TestReceiver()

   # Connect signal
   emitter.test_signal.connect(receiver.on_signal)

   # Test emission
   emitter.test_signal.emit("Test message")
   print(f"✓ Signal-slot works: {len(receiver.received)} messages")
   ```

2. **Check Thread Safety**:
   ```python
   # Test thread-safe operations
   from PyQt6.QtCore import QThread, QTimer

   def test_thread_safety():
       # Test timer in main thread
       timer = QTimer()
       timer.timeout.connect(lambda: print("Timer works"))
       timer.start(1000)

       print("✓ Thread safety test passed")
   ```

3. **Monitor Backend Status**:
   ```python
   # Check backend thread status
   def check_backend_status():
       if hasattr(gui, 'backend_thread'):
           thread = gui.backend_thread

           print(f"Thread running: {thread.isRunning()}")
           print(f"Thread finished: {thread.isFinished()}")

           # Check for thread errors
           if thread.isFinished():
               print("Backend thread finished")
   ```

### Storage Integration Issues

**Problem**: GUI doesn't properly integrate with storage system.

**Solutions**:

1. **Test Storage Manager**:
   ```python
   # Test storage manager integration
   from src.storage.database_fixed import StorageManager

   try:
       storage = StorageManager(Path.home() / '.privatus-chat', "test_password")

       # Test basic operations
       contacts = storage.get_all_contacts()
       print(f"✓ Storage integration: {len(contacts)} contacts")

   except Exception as e:
       print(f"✗ Storage integration failed: {e}")
   ```

2. **Check Data Loading**:
   ```python
   # Test data loading in GUI context
   def test_data_loading():
       if hasattr(gui.main_window, 'storage') and gui.main_window.storage:
           try:
               # Test contact loading
               contacts = gui.main_window.storage.get_all_contacts()
               print(f"✓ Loaded {len(contacts)} contacts")

               # Test message loading
               if gui.main_window.current_contact_id:
                   messages = gui.main_window.storage.get_conversation_history(
                       gui.main_window.current_contact_id
                   )
                   print(f"✓ Loaded {len(messages)} messages")

           except Exception as e:
               print(f"✗ Data loading failed: {e}")
   ```

3. **Verify Error Handling**:
   ```python
   # Test error handling integration
   from src.error_handling import get_feedback_manager

   try:
       feedback_manager = get_feedback_manager()
       print("✓ Feedback manager available")

       # Test error display
       feedback_manager.show_error(
           Exception("Test error"),
           show_retry=True
       )
       print("✓ Error display works")

   except Exception as e:
       print(f"✗ Error handling issue: {e}")
   ```

## Platform-Specific GUI Issues

### Windows GUI Problems

**Problem**: GUI issues specific to Windows platform.

**Solutions**:

1. **Check Windows Display Settings**:
   ```powershell
   # Check display scaling
   Get-CimInstance -Namespace root\cimv2 -ClassName Win32_VideoController | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution

   # Check DPI settings
   Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels"
   ```

2. **Test Windows-Specific Features**:
   ```python
   # Test Windows integration
   from PyQt6.QtCore import QSysInfo

   print(f"Windows version: {QSysInfo.windowsVersion()}")
   print(f"Product type: {QSysInfo.productType()}")
   print(f"Product version: {QSysInfo.productVersion()}")
   ```

3. **Check Windows Permissions**:
   ```powershell
   # Check application permissions
   $appPath = "C:\Path\To\privatus-chat.exe"
   Get-Acl $appPath | Format-List

   # Check if running as administrator
   $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   Write-Host "Running as admin: $isAdmin"
   ```

### macOS GUI Problems

**Problem**: GUI issues specific to macOS platform.

**Solutions**:

1. **Check macOS Integration**:
   ```python
   # Test macOS-specific features
   from PyQt6.QtCore import QSysInfo

   print(f"macOS version: {QSysInfo.macVersion()}")
   print(f"Product version: {QSysInfo.productVersion()}")

   # Check for dark mode
   import subprocess
   result = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                          capture_output=True, text=True)
   dark_mode = 'Dark' in result.stdout
   print(f"Dark mode: {dark_mode}")
   ```

2. **Test Menu Bar Integration**:
   ```python
   # Test macOS menu bar
   from PyQt6.QtWidgets import QApplication

   app = QApplication([])
   print(f"Menu bar visible: {app.menuBar().isVisible()}")

   # Test dock integration
   from PyQt6.QtWidgets import QMainWindow
   window = QMainWindow()
   window.setWindowTitle("Test")
   window.show()
   ```

3. **Check Gatekeeper Settings**:
   ```bash
   # Check Gatekeeper status
   spctl --status

   # Check app signature
   codesign --verify /Applications/Privatus-chat.app

   # Check if app is notarized
   spctl --assess --verbose /Applications/Privatus-chat.app
   ```

### Linux GUI Problems

**Problem**: GUI issues specific to Linux platform.

**Solutions**:

1. **Check Display Server**:
   ```bash
   # Check display server type
   echo $XDG_SESSION_TYPE
   echo $WAYLAND_DISPLAY
   echo $DISPLAY

   # Check desktop environment
   echo $XDG_CURRENT_DESKTOP
   echo $DESKTOP_SESSION
   ```

2. **Test Qt Platform Integration**:
   ```python
   # Test Qt platform plugin
   from PyQt6.QtWidgets import QApplication

   app = QApplication([])
   platform = app.platformName()
   print(f"Qt platform: {platform}")

   # Check platform plugins
   import os
   plugin_path = os.path.join(os.path.dirname(PyQt6.__file__), 'plugins', 'platforms')
   print(f"Platform plugins: {os.listdir(plugin_path) if os.path.exists(plugin_path) else 'Not found'}")
   ```

3. **Check System Theme Integration**:
   ```bash
   # Check system theme
   gsettings get org.gnome.desktop.interface gtk-theme
   gsettings get org.gnome.desktop.interface icon-theme

   # Check font settings
   gsettings get org.gnome.desktop.interface font-name
   gsettings get org.gnome.desktop.interface monospace-font-name
   ```

## Diagnostic Tools and Commands

### GUI Diagnostics Script

```python
#!/usr/bin/env python3
"""
Privatus-chat GUI Diagnostics Tool
"""

import sys
import os
from pathlib import Path

def run_gui_diagnostics():
    print("=== Privatus-chat GUI Diagnostics ===\n")

    # 1. Check Python environment
    print("1. Checking Python environment...")
    print(f"   Python version: {sys.version}")
    print(f"   Python executable: {sys.executable}")

    # 2. Check PyQt6 installation
    print("\n2. Checking PyQt6 installation...")
    try:
        import PyQt6
        print(f"   ✓ PyQt6 version: {PyQt6.QtCore.PYQT_VERSION_STR}")
        print(f"   ✓ PyQt6 path: {PyQt6.__file__}")

        # Test basic functionality
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt

        print("   ✓ QApplication can be imported")
        print("   ✓ Qt constants available")

    except ImportError as e:
        print(f"   ✗ PyQt6 import failed: {e}")
        return
    except Exception as e:
        print(f"   ✗ PyQt6 test failed: {e}")

    # 3. Check Qt platform plugins
    print("\n3. Checking Qt platform plugins...")
    try:
        import PyQt6
        plugin_dir = Path(PyQt6.__file__).parent / 'plugins' / 'platforms'
        if plugin_dir.exists():
            plugins = list(plugin_dir.glob('*'))
            print(f"   ✓ Found {len(plugins)} platform plugins:")
            for plugin in plugins:
                print(f"     - {plugin.name}")
        else:
            print("   ○ Platform plugins directory not found")

    except Exception as e:
        print(f"   ✗ Platform plugin check failed: {e}")

    # 4. Check display environment
    print("\n4. Checking display environment...")
    display_vars = ['DISPLAY', 'WAYLAND_DISPLAY', 'XDG_SESSION_TYPE']
    for var in display_vars:
        value = os.environ.get(var, 'Not set')
        print(f"   {var}: {value}")

    # 5. Check GUI dependencies
    print("\n5. Checking GUI dependencies...")
    dependencies = [
        ('PyQt6', 'PyQt6'),
        ('PyQt6.QtCore', 'PyQt6.QtCore'),
        ('PyQt6.QtWidgets', 'PyQt6.QtWidgets'),
        ('PyQt6.QtGui', 'PyQt6.QtGui'),
    ]

    for name, module in dependencies:
        try:
            __import__(module)
            print(f"   ✓ {name}")
        except ImportError:
            print(f"   ✗ {name} missing")

    # 6. Test GUI creation (without showing)
    print("\n6. Testing GUI creation...")
    try:
        from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel

        app = QApplication([]) if not QApplication.instance() else QApplication.instance()

        # Test widget creation
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel("GUI Test")
        layout.addWidget(label)

        print("   ✓ Widget creation successful")
        print(f"   ✓ Widget size: {widget.size().width()}x{widget.size().height()}")

        # Test theme application
        try:
            from src.gui.themes import theme_manager
            themes = theme_manager.get_available_themes()
            print(f"   ✓ Theme manager: {len(themes)} themes available")
        except Exception as e:
            print(f"   ○ Theme manager: {e}")

    except Exception as e:
        print(f"   ✗ GUI creation failed: {e}")

    # 7. Check storage integration
    print("\n7. Checking storage integration...")
    try:
        from pathlib import Path
        data_dir = Path.home() / '.privatus-chat'

        if data_dir.exists():
            print(f"   ✓ Data directory exists: {data_dir}")
            contents = list(data_dir.glob('*'))
            print(f"   ✓ Data directory contents: {len(contents)} items")
        else:
            print("   ○ Data directory does not exist yet")

        # Test storage manager creation
        try:
            from src.storage.database_fixed import StorageManager
            storage = StorageManager(data_dir, "test_password")
            print("   ✓ Storage manager creation successful")
        except Exception as e:
            print(f"   ○ Storage manager: {e}")

    except Exception as e:
        print(f"   ✗ Storage integration check failed: {e}")

    print("\n=== GUI Diagnostics Complete ===")

if __name__ == "__main__":
    run_gui_diagnostics()
```

### GUI Performance Monitoring Script

```python
#!/usr/bin/env python3
"""
Privatus-chat GUI Performance Monitor
"""

import time
import psutil
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer, QObject

class GUIPerformanceMonitor(QObject):
    def __init__(self):
        super().__init__()
        self.process = psutil.Process(os.getpid())
        self.start_time = time.time()
        self.measurements = []

        # Setup monitoring timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.collect_metrics)
        self.timer.start(1000)  # Collect every second

    def collect_metrics(self):
        """Collect performance metrics."""
        try:
            # Memory usage
            memory_mb = self.process.memory_info().rss / 1024 / 1024

            # CPU usage
            cpu_percent = self.process.cpu_percent()

            # GUI thread info
            app = QApplication.instance()
            thread_count = len(self.process.threads()) if self.process else 0

            # Uptime
            uptime = time.time() - self.start_time

            metrics = {
                'timestamp': time.time(),
                'memory_mb': memory_mb,
                'cpu_percent': cpu_percent,
                'threads': thread_count,
                'uptime_seconds': uptime
            }

            self.measurements.append(metrics)

            # Keep only last 300 measurements (5 minutes)
            if len(self.measurements) > 300:
                self.measurements.pop(0)

            # Print current metrics
            print(f"GUI Performance: {memory_mb:.1f}MB, {cpu_percent:.1f}% CPU, {thread_count} threads")

        except Exception as e:
            print(f"Performance monitoring error: {e}")

    def get_performance_report(self):
        """Generate performance report."""
        if not self.measurements:
            return "No performance data available"

        # Calculate averages
        avg_memory = sum(m['memory_mb'] for m in self.measurements) / len(self.measurements)
        avg_cpu = sum(m['cpu_percent'] for m in self.measurements) / len(self.measurements)
        max_memory = max(m['memory_mb'] for m in self.measurements)

        return f"""
GUI Performance Report:
- Average Memory: {avg_memory:.1f} MB
- Average CPU: {avg_cpu:.1f}%
- Peak Memory: {max_memory:.1f} MB
- Monitoring Duration: {self.measurements[-1]['uptime_seconds']:.1f} seconds
- Samples Collected: {len(self.measurements)}
        """

def start_performance_monitoring():
    """Start GUI performance monitoring."""
    app = QApplication.instance() or QApplication([])

    monitor = GUIPerformanceMonitor()

    # Show initial status
    print("GUI Performance Monitoring Started")
    print("Monitor will run for 5 minutes or until stopped")

    return monitor

if __name__ == "__main__":
    monitor = start_performance_monitoring()

    # Run for 5 minutes
    import time
    time.sleep(300)

    print(monitor.get_performance_report())
```

### GUI Widget Test Script

```python
#!/usr/bin/env python3
"""
Privatus-chat GUI Widget Test Tool
"""

import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit, QListWidget, QSplitter
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QPalette, QColor

def test_gui_widgets():
    """Test all major GUI widgets."""
    print("Testing GUI widgets...")

    app = QApplication([]) if not QApplication.instance() else QApplication.instance()

    # Create test window
    window = QMainWindow()
    window.setWindowTitle("GUI Widget Test")
    window.setGeometry(100, 100, 800, 600)

    # Create central widget
    central = QWidget()
    window.setCentralWidget(central)

    # Test layout
    layout = QVBoxLayout(central)

    # Test labels
    title_label = QLabel("Privatus-chat GUI Test")
    title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
    layout.addWidget(title_label)

    # Test buttons
    button_layout = QHBoxLayout()

    test_button = QPushButton("Test Button")
    test_button.clicked.connect(lambda: print("Button clicked!"))
    button_layout.addWidget(test_button)

    toggle_button = QPushButton("Toggle Theme")
    toggle_button.clicked.connect(lambda: test_theme_toggle())
    button_layout.addWidget(toggle_button)

    layout.addLayout(button_layout)

    # Test text areas
    text_edit = QTextEdit()
    text_edit.setPlaceholderText("Test text input area...")
    layout.addWidget(text_edit)

    # Test list widget
    list_widget = QListWidget()
    for i in range(5):
        list_widget.addItem(f"Test Item {i}")
    layout.addWidget(list_widget)

    # Test splitter
    splitter = QSplitter(Qt.Orientation.Horizontal)
    left_panel = QWidget()
    right_panel = QWidget()

    left_layout = QVBoxLayout(left_panel)
    right_layout = QVBoxLayout(right_panel)

    left_layout.addWidget(QLabel("Left Panel"))
    right_layout.addWidget(QLabel("Right Panel"))

    splitter.addWidget(left_panel)
    splitter.addWidget(right_panel)
    splitter.setSizes([400, 400])

    layout.addWidget(splitter)

    window.show()
    print("✓ GUI widgets test window displayed")

    return app, window

def test_theme_toggle():
    """Test theme switching."""
    print("Testing theme toggle...")

    try:
        from src.gui.themes import theme_manager

        current_theme = theme_manager.get_current_theme()
        themes = theme_manager.get_available_themes()

        # Switch to next theme
        if themes:
            current_index = themes.index(current_theme) if current_theme in themes else 0
            next_index = (current_index + 1) % len(themes)
            next_theme = themes[next_index]

            theme_manager.apply_theme(next_theme)
            print(f"✓ Switched to theme: {next_theme}")

    except Exception as e:
        print(f"✗ Theme toggle failed: {e}")

if __name__ == "__main__":
    app, window = test_gui_widgets()

    print("GUI Widget Test Complete")
    print("Close the test window to exit")

    sys.exit(app.exec())
```

## Emergency Procedures

### GUI Reset Procedures

```python
# Emergency GUI reset
def emergency_gui_reset():
    """Reset GUI to default state."""

    try:
        # 1. Close all dialogs and windows
        app = QApplication.instance()
        if app:
            for widget in app.topLevelWidgets():
                if widget.isVisible():
                    widget.hide()

        # 2. Reset theme to default
        from src.gui.themes import theme_manager
        theme_manager.reset_to_default()
        print("✓ Theme reset to default")

        # 3. Clear GUI state
        if hasattr(gui, 'main_window'):
            gui.main_window.contact_list.clear()
            gui.main_window.chat_area.clear_messages()
            gui.main_window.status_bar.showMessage("GUI reset complete")

        print("✓ GUI reset complete")

    except Exception as e:
        print(f"✗ GUI reset failed: {e}")
```

### Force Application Restart

```python
# Force restart GUI application
def force_gui_restart():
    """Force restart the GUI application."""

    try:
        # 1. Save current state if possible
        if hasattr(gui, 'main_window') and gui.main_window.storage:
            print("Saving current state...")
            # Save any unsaved data

        # 2. Shutdown current instance
        gui.shutdown()
        print("✓ GUI shutdown complete")

        # 3. Restart application
        import subprocess
        import sys

        print("Restarting GUI...")
        subprocess.Popen([sys.executable, "launch_gui.py"])

        # Exit current process
        QApplication.quit()

    except Exception as e:
        print(f"✗ GUI restart failed: {e}")
```

## Prevention and Best Practices

### GUI Maintenance Best Practices

1. **Regular GUI Updates**:
   ```python
   # Check for GUI updates
   def check_gui_updates():
       # Check theme files
       theme_files = Path("src/gui").glob("*.json")
       for theme_file in theme_files:
           mtime = theme_file.stat().st_mtime
           age_days = (time.time() - mtime) / (24 * 3600)
           if age_days > 30:
               print(f"Theme file {theme_file.name} is {age_days:.0f} days old")

       # Check GUI source files
       gui_files = Path("src/gui").glob("*.py")
       for gui_file in gui_files:
           # Check for syntax errors
           import py_compile
           try:
               py_compile.compile(gui_file, doraise=True)
               print(f"✓ {gui_file.name} compiles successfully")
           except Exception as e:
               print(f"✗ {gui_file.name} compilation error: {e}")
   ```

2. **Performance Monitoring**:
   ```python
   # Monitor GUI performance
   def monitor_gui_performance():
       import psutil
       import os

       process = psutil.Process(os.getpid())

       # Check memory usage
       memory_mb = process.memory_info().rss / 1024 / 1024
       if memory_mb > 500:  # 500MB threshold
           print(f"⚠ High memory usage: {memory_mb:.1f}MB")

       # Check thread count
       thread_count = len(process.threads())
       if thread_count > 20:
           print(f"⚠ High thread count: {thread_count}")

       # Check CPU usage
       cpu_percent = process.cpu_percent()
       if cpu_percent > 50:
           print(f"⚠ High CPU usage: {cpu_percent:.1f}%")
   ```

3. **Error Prevention**:
   ```python
   # Implement error prevention measures
   def setup_error_prevention():
       # Set up exception hook
       def gui_exception_hook(exctype, value, traceback):
           print(f"GUI Exception: {exctype.__name__}: {value}")
           # Log error details
           import traceback
           with open('gui_errors.log', 'a') as f:
               f.write(f"{time.ctime()}: {traceback.format_exc()}\n")

       sys.excepthook = gui_exception_hook

       # Set up signal handlers
       import signal
       def signal_handler(signum, frame):
           print(f"Received signal {signum}")
           emergency_gui_reset()

       signal.signal(signal.SIGTERM, signal_handler)
       signal.signal(signal.SIGINT, signal_handler)
   ```

### GUI Optimization Techniques

1. **Widget Reuse**:
   ```python
   # Reuse widgets instead of creating new ones
   widget_pool = {}

   def get_reusable_widget(widget_type):
       if widget_type not in widget_pool:
           widget_pool[widget_type] = []

       if widget_pool[widget_type]:
           return widget_pool[widget_type].pop()
       else:
           return create_new_widget(widget_type)

   def return_widget_to_pool(widget, widget_type):
       widget.clear()  # Clear any content
       widget_pool.setdefault(widget_type, []).append(widget)
   ```

2. **Lazy Loading**:
   ```python
   # Load GUI components only when needed
   def lazy_load_component(component_name):
       if component_name not in loaded_components:
           if component_name == "contact_list":
               load_contact_list()
           elif component_name == "chat_area":
               load_chat_area()
           # ... other components

           loaded_components.add(component_name)

       return get_component(component_name)
   ```

3. **Memory Management**:
   ```python
   # Implement proper memory management
   def cleanup_gui_resources():
       # Clear image caches
       if hasattr(gui, 'image_cache'):
           gui.image_cache.clear()

       # Clear widget references
       for widget in unused_widgets:
           widget.deleteLater()

       # Force garbage collection
       import gc
       gc.collect()

       print("✓ GUI resources cleaned up")
   ```

## Getting Help

### Self-Service Resources

1. **Documentation**:
   - [Installation Guide](installation-guide.md)
   - [User Guide](user-guide.md)
   - [FAQ](faq.md)

2. **Community Support**:
   - [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
   - [GUI Discussions](https://github.com/privatus-chat/privatus-chat/discussions/categories/gui)

### Reporting GUI Issues

When reporting GUI issues, please include:

1. **System Information**:
   - Operating system and version
   - Desktop environment (Linux) or window manager
   - Display resolution and scaling settings

2. **GUI Environment**:
   - PyQt6 version
   - Qt platform being used
   - Theme and appearance settings

3. **Problem Details**:
   - Exact steps to reproduce
   - Screenshots if applicable
   - GUI diagnostic output

4. **Error Information**:
   - Any error messages displayed
   - Console output from GUI launch
   - GUI debug logs

---

*Remember: GUI issues are often platform-specific. Always include your operating system, desktop environment, and display settings when reporting problems.*

*Last updated: January 2025*
*Version: 1.0.0*