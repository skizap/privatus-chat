# Development and Debugging Troubleshooting Guide

This guide provides comprehensive solutions for development environment issues, debugging problems, and testing challenges in Privatus-chat.

## Table of Contents

1. [Development Environment Setup Issues](#development-environment-setup-issues)
2. [Code Compilation and Import Problems](#code-compilation-and-import-problems)
3. [Testing Framework Issues](#testing-framework-issues)
4. [Debugging and Logging Problems](#debugging-and-logging-problems)
5. [Log Analysis Methods and Patterns](#log-analysis-methods-and-patterns)
6. [Effective Debugging Techniques and Workflows](#effective-debugging-techniques-and-workflows)
7. [Log Analysis Tools and Best Practices](#log-analysis-tools-and-best-practices)
8. [Debugging Scenarios and Case Studies](#debugging-scenarios-and-case-studies)
9. [Version Control and Collaboration Issues](#version-control-and-collaboration-issues)
10. [Build and Deployment Problems](#build-and-deployment-problems)
11. [Performance Profiling Issues](#performance-profiling-issues)
12. [Development Tools and IDE Problems](#development-tools-and-ide-problems)

## Development Environment Setup Issues

### Python Environment Problems

**Problem**: Python development environment not working correctly.

**Symptoms**:
- Import errors for required modules
- Version conflicts between packages
- Virtual environment issues

**Solutions**:

1. **Check Python Installation**:
   ```bash
   # Verify Python version and installation
   python --version
   python -c "import sys; print(sys.path)"

   # Check pip installation
   pip --version

   # Verify package manager
   python -m pip list | head -10
   ```

2. **Test Virtual Environment**:
   ```bash
   # Create and test virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # Install requirements
   pip install -r requirements.txt
   pip install -r requirements-dev.txt

   # Verify installation
   python -c "import PyQt6; print('PyQt6 OK')"
   python -c "import cryptography; print('Cryptography OK')"
   ```

3. **Check Package Dependencies**:
   ```python
   # Verify all dependencies are installed correctly
   import subprocess
   import sys

   def check_dependencies():
       required_packages = [
           'PyQt6',
           'cryptography',
           'pytest',
           'pytest_asyncio',
           'asyncio',
           'sqlite3'
       ]

       missing_packages = []

       for package in required_packages:
           try:
               __import__(package)
               print(f"✓ {package}")
           except ImportError:
               print(f"✗ {package} missing")
               missing_packages.append(package)

       if missing_packages:
           print(f"\nMissing packages: {missing_packages}")
           print("Install with: pip install " + " ".join(missing_packages))
       else:
           print("\n✓ All required packages installed")

   check_dependencies()
   ```

### Development Dependencies Issues

**Problem**: Development tools and testing frameworks not working.

**Solutions**:

1. **Install Development Dependencies**:
   ```bash
   # Install all development dependencies
   pip install -r requirements-dev.txt

   # Verify pytest installation
   python -m pytest --version

   # Check coverage tools
   python -c "import pytest_cov; print('Coverage OK')"
   ```

2. **Test Development Tools**:
   ```python
   # Test development tool functionality
   def test_dev_tools():
       # Test pytest
       try:
           import pytest
           print(f"✓ Pytest version: {pytest.__version__}")
       except ImportError:
           print("✗ Pytest not available")

       # Test coverage
       try:
           import coverage
           print(f"✓ Coverage version: {coverage.__version__}")
       except ImportError:
           print("○ Coverage not available")

       # Test profiling tools
       try:
           import cProfile
           import pstats
           print("✓ Profiling tools available")
       except ImportError:
           print("✗ Profiling tools missing")
   ```

3. **Configure Development Environment**:
   ```python
   # Setup development configuration
   import os
   import sys

   def setup_dev_environment():
       # Add source directories to path
       src_path = os.path.join(os.path.dirname(__file__), 'src')
       if src_path not in sys.path:
           sys.path.insert(0, src_path)

       # Set environment variables for development
       os.environ['PRIVATUS_DEV_MODE'] = '1'
       os.environ['PRIVATUS_LOG_LEVEL'] = 'DEBUG'

       print("✓ Development environment configured")
   ```

## Code Compilation and Import Problems

### Import Errors During Development

**Problem**: Cannot import modules during development.

**Symptoms**:
- "Module not found" errors
- Import path issues
- Circular import problems

**Solutions**:

1. **Check Python Path Configuration**:
   ```python
   # Verify Python path includes source directories
   import sys
   import os

   def check_python_path():
       src_path = os.path.abspath('src')
       print(f"Source path: {src_path}")
       print(f"In sys.path: {src_path in sys.path}")

       if src_path not in sys.path:
           sys.path.insert(0, src_path)
           print("✓ Added src to Python path")

       # Test imports
       try:
           from crypto.key_management import KeyManager
           print("✓ KeyManager import successful")
       except ImportError as e:
           print(f"✗ Import failed: {e}")
   ```

2. **Test Module Structure**:
   ```python
   # Verify module structure and __init__.py files
   import os
   from pathlib import Path

   def check_module_structure():
       src_path = Path('src')

       # Check for __init__.py files
       missing_init = []

       for py_file in src_path.rglob('*.py'):
           init_file = py_file.parent / '__init__.py'
           if not init_file.exists():
               missing_init.append(str(py_file))

       if missing_init:
           print(f"✗ Missing __init__.py files: {missing_init}")
       else:
           print("✓ All __init__.py files present")

       # Check package structure
       packages = [p for p in src_path.iterdir() if p.is_dir()]
       print(f"✓ Found {len(packages)} packages: {[p.name for p in packages]}")
   ```

3. **Debug Import Issues**:
   ```python
   # Debug specific import problems
   def debug_import_issue(module_name):
       try:
           # Try different import methods
           module = __import__(module_name, fromlist=[''])
           print(f"✓ Direct import successful: {module}")

       except ImportError as e:
           print(f"✗ Direct import failed: {e}")

           # Try with explicit path
           try:
               import importlib.util
               spec = importlib.util.spec_from_file_location(module_name, f"src/{module_name.replace('.', '/')}.py")
               module = importlib.util.module_from_spec(spec)
               spec.loader.exec_module(module)
               print(f"✓ Explicit path import successful: {module}")
           except Exception as e2:
               print(f"✗ Explicit path import failed: {e2}")
   ```

### Syntax and Compilation Errors

**Problem**: Code has syntax errors or won't compile.

**Solutions**:

1. **Check Python Syntax**:
   ```bash
   # Check syntax of all Python files
   find src -name "*.py" -exec python -m py_compile {} \;

   # Check for specific syntax issues
   python -c "
   import ast
   import os

   for root, dirs, files in os.walk('src'):
       for file in files:
           if file.endswith('.py'):
               filepath = os.path.join(root, file)
               try:
                   with open(filepath, 'r') as f:
                       ast.parse(f.read())
                   print(f'✓ {filepath}')
               except SyntaxError as e:
                   print(f'✗ {filepath}: {e}')
   "
   ```

2. **Test Code Compilation**:
   ```python
   # Test compilation of specific modules
   import py_compile
   import os

   def test_module_compilation(module_path):
       try:
           # Try to compile the module
           py_compile.compile(module_path, doraise=True)
           print(f"✓ {module_path} compiles successfully")

           # Try to import the compiled module
           module_name = os.path.splitext(os.path.basename(module_path))[0]
           __import__(module_name)
           print(f"✓ {module_name} imports successfully")

       except py_compile.PyCompileError as e:
           print(f"✗ Compilation failed: {e}")
       except ImportError as e:
           print(f"✗ Import failed: {e}")
   ```

3. **Check for Common Syntax Issues**:
   ```python
   # Check for common syntax problems
   def check_common_syntax_issues():
       import ast
       import os

       issues_found = []

       for root, dirs, files in os.walk('src'):
           for file in files:
               if file.endswith('.py'):
                   filepath = os.path.join(root, file)

                   try:
                       with open(filepath, 'r') as f:
                           content = f.read()

                       # Check for common issues
                       lines = content.split('\n')

                       for i, line in enumerate(lines, 1):
                           # Check for mixed tabs and spaces
                           if '\t' in line and '    ' in line:
                               issues_found.append(f"{filepath}:{i}: Mixed tabs and spaces")

                           # Check for long lines
                           if len(line) > 100:
                               issues_found.append(f"{filepath}:{i}: Line too long ({len(line)} chars)")

                           # Check for trailing whitespace
                           if line.rstrip() != line:
                               issues_found.append(f"{filepath}:{i}: Trailing whitespace")

                   except Exception as e:
                       issues_found.append(f"{filepath}: Read error: {e}")

       if issues_found:
           print("Found syntax/style issues:")
           for issue in issues_found[:10]:  # Show first 10 issues
               print(f"  {issue}")
       else:
           print("✓ No common syntax issues found")
   ```

## Testing Framework Issues

### Test Discovery Problems

**Problem**: Tests are not being discovered or run by the test framework.

**Solutions**:

1. **Check Test File Naming**:
   ```bash
   # Verify test file naming conventions
   find tests -name "*.py" | head -10

   # Check for proper test naming
   find tests -name "test_*.py" | wc -l
   find tests -name "*_test.py" | wc -l
   ```

2. **Test Pytest Configuration**:
   ```python
   # Test pytest discovery
   import pytest

   def test_pytest_discovery():
       # Try to discover tests
       import os
       test_dir = 'tests'

       if os.path.exists(test_dir):
           # List test files
           test_files = []
           for file in os.listdir(test_dir):
               if file.startswith('test_') and file.endswith('.py'):
                   test_files.append(os.path.join(test_dir, file))

           print(f"✓ Found {len(test_files)} test files:")
           for test_file in test_files:
               print(f"  - {test_file}")

           # Try to run a simple test discovery
           import subprocess
           result = subprocess.run(['python', '-m', 'pytest', '--collect-only', test_dir],
                                 capture_output=True, text=True)

           if result.returncode == 0:
               print("✓ Test discovery successful")
               print(f"Discovered tests: {result.stdout.count('test_')}")
           else:
               print(f"✗ Test discovery failed: {result.stderr}")

       else:
           print(f"✗ Test directory not found: {test_dir}")
   ```

3. **Check Test Markers and Fixtures**:
   ```python
   # Verify test fixtures and markers
   def check_test_fixtures():
       # Check for async fixtures
       async_fixtures = []
       sync_fixtures = []

       # This would analyze test files for fixture definitions
       # For now, just check basic pytest functionality

       try:
           import pytest_asyncio
           print("✓ pytest-asyncio available")
       except ImportError:
           print("○ pytest-asyncio not available")

       # Check for common test markers
       markers = ['asyncio', 'slow', 'integration', 'unit']
       print(f"✓ Common test markers: {markers}")
   ```

### Test Execution Failures

**Problem**: Tests fail to run or execute properly.

**Solutions**:

1. **Run Tests in Different Modes**:
   ```bash
   # Run tests in verbose mode
   python -m pytest -v tests/

   # Run specific test file
   python -m pytest tests/test_networking.py -v

   # Run with coverage
   python -m pytest --cov=src tests/

   # Run only failing tests
   python -m pytest --lf tests/
   ```

2. **Debug Test Execution**:
   ```python
   # Debug test execution issues
   import pytest
   import sys

   def debug_test_execution():
       # Check pytest configuration
       print(f"Python path: {sys.path[:3]}")

       # Try to run a simple test manually
       try:
           # Import test module
           import tests.test_networking
           print("✓ Test module imports successfully")

           # Check test functions
           import inspect
           test_functions = [name for name, obj in inspect.getmembers(tests.test_networking)
                           if inspect.isfunction(obj) and name.startswith('test_')]

           print(f"✓ Found {len(test_functions)} test functions")

       except Exception as e:
           print(f"✗ Test execution debug failed: {e}")
   ```

3. **Check Async Test Configuration**:
   ```python
   # Verify async test setup
   def check_async_test_setup():
       try:
           import pytest_asyncio

           # Check if event loop is available
           import asyncio
           loop = asyncio.get_event_loop()
           print(f"✓ Event loop: {loop}")

           # Test async fixture
           async def test_async_fixture():
               await asyncio.sleep(0.01)
               return "async_test_passed"

           # Test running async function
           result = asyncio.run(test_async_fixture())
           print(f"✓ Async test: {result}")

       except Exception as e:
           print(f"✗ Async test setup failed: {e}")
   ```

### Test Data and Fixture Issues

**Problem**: Test fixtures or test data not working correctly.

**Solutions**:

1. **Check Test Data Setup**:
   ```python
   # Verify test data and fixtures
   def check_test_data():
       # Check demo data directory
       demo_data_path = Path('demo_data')
       if demo_data_path.exists():
           print(f"✓ Demo data directory: {demo_data_path}")

           # Check for test keys
           keys_dir = demo_data_path / 'keys'
           if keys_dir.exists():
               key_files = list(keys_dir.glob('*.enc'))
               print(f"✓ Test key files: {len(key_files)}")
           else:
               print("○ Test keys directory not found")

       else:
           print("○ Demo data directory not found")

       # Check test configuration
       config_files = list(Path('.').glob('*config*.json'))
       print(f"✓ Config files: {len(config_files)}")
   ```

2. **Test Fixture Dependencies**:
   ```python
   # Check fixture dependency chain
   def check_fixture_dependencies():
       # This would analyze test files for fixture usage
       # For now, check basic fixture functionality

       try:
           # Test basic fixture creation
           def simple_fixture():
               return "fixture_value"

           result = simple_fixture()
           print(f"✓ Simple fixture works: {result}")

           # Test async fixture
           async def async_fixture():
               await asyncio.sleep(0.01)
               return "async_fixture_value"

           # Test running async fixture
           result = asyncio.run(async_fixture())
           print(f"✓ Async fixture works: {result}")

       except Exception as e:
           print(f"✗ Fixture test failed: {e}")
   ```

3. **Verify Test Database Setup**:
   ```python
   # Check test database configuration
   def check_test_database():
       try:
           # Test in-memory database
           import sqlite3

           conn = sqlite3.connect(':memory:')
           cursor = conn.cursor()

           # Create test schema
           cursor.execute('''
               CREATE TABLE test_contacts (
                   contact_id TEXT PRIMARY KEY,
                   display_name TEXT NOT NULL
               )
           ''')

           # Insert test data
           cursor.execute("INSERT INTO test_contacts VALUES (?, ?)",
                        ("test_contact_1", "Test Contact"))

           # Query test data
           cursor.execute("SELECT * FROM test_contacts")
           result = cursor.fetchone()

           if result:
               print(f"✓ Test database works: {result}")
           else:
               print("✗ Test database query failed")

           conn.close()

       except Exception as e:
           print(f"✗ Test database check failed: {e}")
   ```

## Debugging and Logging Problems

### Logging Configuration Issues

**Problem**: Logging not working correctly in development.

**Symptoms**:
- No log output
- Incorrect log levels
- Log files not created

**Solutions**:

1. **Check Logging Configuration**:
   ```python
   # Test logging setup
   import logging
   import logging.config

   def test_logging_setup():
       # Test basic logging
       logging.basicConfig(level=logging.DEBUG)

       logger = logging.getLogger('test_logger')
       logger.info("Test log message")

       print("✓ Basic logging configured")

       # Test file logging
       try:
           file_handler = logging.FileHandler('test.log')
           file_handler.setLevel(logging.DEBUG)

           formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
           file_handler.setFormatter(formatter)

           logger.addHandler(file_handler)
           logger.info("Test file log message")

           print("✓ File logging configured")

       except Exception as e:
           print(f"✗ File logging failed: {e}")
   ```

2. **Verify Log Directory Permissions**:
   ```bash
   # Check log directory setup
   mkdir -p logs/
   chmod 755 logs/

   # Test log file creation
   touch logs/test.log
   ls -la logs/test.log
   ```

3. **Check Application Logging**:
   ```python
   # Test application-specific logging
   def test_application_logging():
       try:
           # Import application modules
           from src.crypto.key_management import security_logger
           from src.error_handling import secure_logger

           # Test security logging
           security_logger.info("Test security log")
           print("✓ Security logging works")

           # Test error logging
           secure_logger.info("Test secure log")
           print("✓ Secure logging works")

       except Exception as e:
           print(f"✗ Application logging failed: {e}")
   ```

### Debug Information Not Available

**Problem**: Cannot get sufficient debug information during development.

**Solutions**:

1. **Enable Debug Mode**:
   ```python
   # Enable comprehensive debug mode
   import os

   def enable_debug_mode():
       # Set debug environment variables
       os.environ['PRIVATUS_DEBUG'] = '1'
       os.environ['PRIVATUS_LOG_LEVEL'] = 'DEBUG'
       os.environ['PYTHONASYNCIODEBUG'] = '1'

       # Configure detailed logging
       logging.getLogger().setLevel(logging.DEBUG)
       logging.getLogger('src').setLevel(logging.DEBUG)

       print("✓ Debug mode enabled")
   ```

2. **Add Debug Logging Points**:
   ```python
   # Add strategic debug logging
   def add_debug_logging():
       # Add debug points in key functions
       def debug_decorator(func):
           def wrapper(*args, **kwargs):
               print(f"DEBUG: Entering {func.__name__}")
               start_time = time.time()

               try:
                   result = func(*args, **kwargs)
                   end_time = time.time()
                   print(f"DEBUG: {func.__name__} completed in {end_time - start_time:.3f}s")
                   return result
               except Exception as e:
                   print(f"DEBUG: {func.__name__} failed: {e}")
                   raise

           return wrapper

       # Apply to key functions
       # KeyManager.__init__ = debug_decorator(KeyManager.__init__)
       print("✓ Debug logging points added")
   ```

3. **Implement Debug Console**:
   ```python
   # Create debug console for interactive debugging
   def create_debug_console():
       try:
           # This would create an interactive debug console
           # For now, just provide debug utilities

           def debug_print_status():
               print("=== Debug Status ===")
               print(f"Python path: {sys.path[:3]}")
               print(f"Current directory: {os.getcwd()}")

               # Check loaded modules
               import sys
               modules = [m for m in sys.modules.keys() if m.startswith('src')]
               print(f"Loaded src modules: {len(modules)}")

               print("==================")

           debug_print_status()

       except Exception as e:
           print(f"✗ Debug console creation failed: {e}")
   ```

## Log Analysis Methods and Patterns

### Log File Structure and Organization

Privatus-chat uses a structured logging system with multiple log files for different purposes:

**Log File Types:**
- `privatus-chat.log` - General application logs (INFO level and above)
- `privatus-chat_errors.log` - Error and critical events only
- `privatus-chat_security.log` - Security-related events and authentication logs
- `privatus-chat_buffered.jsonl` - High-volume logs in JSON Lines format

**Log Entry Structure:**
```json
{
 "timestamp": "2025-01-15T10:30:45.123456",
 "level": "ERROR",
 "message": "Connection timeout occurred",
 "logger": "privatus-chat.network",
 "extra": {
   "operation": "message_send",
   "peer_id": "[REDACTED]",
   "error_type": "ConnectionTimeout",
   "context": {
     "retry_count": 3,
     "last_success": "2025-01-15T10:25:30"
   }
 }
}
```

### Log Analysis Fundamentals

#### 1. Log Level Analysis

**Understanding Log Levels:**
- **DEBUG**: Detailed diagnostic information for development
- **INFO**: General information about application operation
- **WARNING**: Potentially harmful situations that don't stop execution
- **ERROR**: Error events that might still allow the application to continue
- **CRITICAL**: Serious errors that may cause the application to terminate

**Analyzing Log Level Patterns:**
```python
def analyze_log_levels(log_file_path):
   """Analyze log level distribution in log files."""
   import json
   from collections import Counter
   from datetime import datetime

   level_counts = Counter()
   time_distribution = []

   try:
       with open(log_file_path, 'r') as f:
           for line in f:
               if line.strip():
                   try:
                       entry = json.loads(line)
                       level = entry.get('level', 'UNKNOWN')
                       level_counts[level] += 1

                       # Track temporal patterns
                       timestamp = entry.get('timestamp')
                       if timestamp:
                           time_distribution.append({
                               'timestamp': timestamp,
                               'level': level
                           })
                   except json.JSONDecodeError:
                       continue

       # Print analysis results
       print("Log Level Distribution:")
       for level, count in level_counts.most_common():
           percentage = (count / sum(level_counts.values())) * 100
           print(f"  {level}: {count} ({percentage".1f"}%)")

       return level_counts, time_distribution

   except FileNotFoundError:
       print(f"Log file not found: {log_file_path}")
       return None, None
```

#### 2. Error Pattern Recognition

**Common Error Patterns:**
```python
def identify_error_patterns(log_entries, time_window_minutes=5):
   """Identify recurring error patterns within time windows."""
   from collections import defaultdict
   import hashlib

   error_patterns = defaultdict(list)
   pattern_hashes = {}

   for entry in log_entries:
       if entry.get('level') in ['ERROR', 'CRITICAL']:
           # Create pattern signature
           error_type = entry.get('extra', {}).get('error_type', 'Unknown')
           operation = entry.get('extra', {}).get('operation', 'unknown')
           message = entry.get('message', '')

           pattern_key = f"{error_type}:{operation}"
           pattern_hash = hashlib.md5(pattern_key.encode()).hexdigest()

           error_patterns[pattern_hash].append({
               'timestamp': entry.get('timestamp'),
               'message': message,
               'context': entry.get('extra', {})
           })

   # Filter for recurring patterns (3+ occurrences)
   recurring_patterns = {
       pattern_hash: occurrences
       for pattern_hash, occurrences in error_patterns.items()
       if len(occurrences) >= 3
   }

   return recurring_patterns
```

**Error Correlation Analysis:**
```python
def correlate_errors(error_patterns):
   """Correlate errors to identify root causes."""
   correlated_issues = {}

   for pattern_hash, occurrences in error_patterns.items():
       if len(occurrences) >= 3:
           # Analyze temporal clustering
           timestamps = [occ.get('timestamp') for occ in occurrences]

           # Check if errors occur in bursts
           if len(timestamps) >= 5:
               time_diffs = []
               for i in range(1, len(timestamps)):
                   try:
                       from datetime import datetime
                       t1 = datetime.fromisoformat(timestamps[i-1].replace('Z', '+00:00'))
                       t2 = datetime.fromisoformat(timestamps[i].replace('Z', '+00:00'))
                       diff = (t2 - t1).total_seconds()
                       time_diffs.append(diff)
                   except:
                       continue

               # If errors occur within short time windows, likely related
               if time_diffs and max(time_diffs) <= 300:  # 5 minutes
                   correlated_issues[pattern_hash] = {
                       'frequency': len(occurrences),
                       'time_span': max(time_diffs),
                       'pattern': 'burst_pattern',
                       'severity': 'high'
                   }

   return correlated_issues
```

#### 3. Performance Analysis from Logs

**Performance Metric Extraction:**
```python
def extract_performance_metrics(log_file_path):
   """Extract and analyze performance metrics from logs."""
   import re
   from collections import defaultdict

   performance_data = defaultdict(list)
   metric_patterns = {
       'response_time': r'Performance: (\w+)=(\d+\.?\d*)(\w*)',
       'memory_usage': r'Memory: (\w+)=(\d+\.?\d*)(\w*)',
       'cpu_usage': r'CPU: (\w+)=(\d+\.?\d*)(\w*)',
       'network_latency': r'Latency: (\w+)=(\d+\.?\d*)(\w*)'
   }

   try:
       with open(log_file_path, 'r') as f:
           for line_num, line in enumerate(f, 1):
               if line.strip():
                   try:
                       entry = json.loads(line)

                       # Check for performance metrics in extra data
                       extra = entry.get('extra', {})
                       if extra.get('performance_metric'):
                           metric_name = extra.get('metric_name')
                           value = extra.get('value')
                           unit = extra.get('unit', '')

                           if metric_name and value is not None:
                               performance_data[metric_name].append({
                                   'timestamp': entry.get('timestamp'),
                                   'value': float(value),
                                   'unit': unit,
                                   'line_number': line_num
                               })

                   except json.JSONDecodeError:
                       continue

       # Analyze performance trends
       for metric, data_points in performance_data.items():
           if len(data_points) >= 2:
               values = [point['value'] for point in data_points]
               print(f"\n{metric} Analysis:")
               print(f"  Samples: {len(values)}")
               print(f"  Average: {sum(values)/len(values)".2f"}")
               print(f"  Min: {min(values)".2f"}")
               print(f"  Max: {max(values)".2f"}")

               # Detect performance degradation
               if len(values) >= 10:
                   recent_avg = sum(values[-5:]) / 5
                   overall_avg = sum(values) / len(values)

                   if recent_avg > overall_avg * 1.2:  # 20% degradation
                       print(f"  ⚠ Performance degradation detected!")

       return performance_data

   except FileNotFoundError:
       print(f"Log file not found: {log_file_path}")
       return None
```

#### 4. Security Event Analysis

**Security Log Analysis:**
```python
def analyze_security_events(security_log_path, hours_back=24):
   """Analyze security events for suspicious patterns."""
   import json
   from datetime import datetime, timedelta
   from collections import Counter

   cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
   security_events = []
   event_types = Counter()
   suspicious_patterns = []

   try:
       with open(security_log_path, 'r') as f:
           for line in f:
               if line.strip():
                   try:
                       entry = json.loads(line)

                       # Parse timestamp
                       timestamp_str = entry.get('timestamp')
                       if timestamp_str:
                           try:
                               entry_time = datetime.fromisoformat(
                                   timestamp_str.replace('Z', '+00:00')
                               )

                               if entry_time >= cutoff_time:
                                   security_events.append(entry)

                                   # Count event types
                                   if 'Security event:' in entry.get('message', ''):
                                       event_type = entry.get('message').split(':')[1].strip()
                                       event_types[event_type] += 1

                           except ValueError:
                               continue

                   except json.JSONDecodeError:
                       continue

       # Analyze for suspicious patterns
       print(f"Security Events in last {hours_back} hours:")
       print(f"  Total events: {len(security_events)}")
       print("  Event breakdown:"
       for event_type, count in event_types.most_common():
           print(f"    {event_type}: {count}")

       # Detect potential security issues
       if event_types.get('Authentication failure', 0) > 10:
           suspicious_patterns.append({
               'type': 'multiple_auth_failures',
               'severity': 'high',
               'description': 'Multiple authentication failures detected'
           })

       if event_types.get('Connection rejected', 0) > 50:
           suspicious_patterns.append({
               'type': 'connection_flood',
               'severity': 'medium',
               'description': 'High number of rejected connections'
           })

       return security_events, event_types, suspicious_patterns

   except FileNotFoundError:
       print(f"Security log file not found: {security_log_path}")
       return None, None, None
```

### Advanced Log Analysis Techniques

#### 1. Log Correlation and Root Cause Analysis

**Multi-Log Correlation:**
```python
def correlate_multiple_logs(log_files, time_window_seconds=300):
   """Correlate events across multiple log files."""
   import json
   from datetime import datetime, timedelta

   correlated_events = []

   # Parse all log entries with timestamps
   all_entries = []
   for log_file in log_files:
       try:
           with open(log_file, 'r') as f:
               for line in f:
                   if line.strip():
                       try:
                           entry = json.loads(line)
                           timestamp = entry.get('timestamp')

                           if timestamp:
                               try:
                                   entry_time = datetime.fromisoformat(
                                       timestamp.replace('Z', '+00:00')
                                   )
                                   entry['source_file'] = log_file
                                   entry['parsed_time'] = entry_time
                                   all_entries.append(entry)
                               except ValueError:
                                   continue

                       except json.JSONDecodeError:
                           continue
       except FileNotFoundError:
           print(f"Log file not found: {log_file}")
           continue

   # Sort by timestamp
   all_entries.sort(key=lambda x: x['parsed_time'])

   # Find correlated events within time windows
   for i, entry in enumerate(all_entries):
       entry_time = entry['parsed_time']
       window_start = entry_time - timedelta(seconds=time_window_seconds/2)
       window_end = entry_time + timedelta(seconds=time_window_seconds/2)

       # Find related events in the time window
       related_events = []
       for other_entry in all_entries[max(0, i-10):min(len(all_entries), i+10)]:
           if window_start <= other_entry['parsed_time'] <= window_end:
               if other_entry != entry:  # Don't include the same event
                   related_events.append(other_entry)

       if related_events:
           correlated_events.append({
               'primary_event': entry,
               'related_events': related_events,
               'correlation_window': time_window_seconds,
               'correlation_strength': len(related_events)
           })

   return correlated_events
```

#### 2. Anomaly Detection in Logs

**Statistical Anomaly Detection:**
```python
def detect_log_anomalies(log_file_path, baseline_hours=24, analysis_hours=1):
   """Detect anomalous log patterns using statistical analysis."""
   import json
   import numpy as np
   from datetime import datetime, timedelta
   from collections import Counter

   baseline_end = datetime.utcnow()
   baseline_start = baseline_end - timedelta(hours=baseline_hours)
   analysis_end = baseline_end
   analysis_start = analysis_end - timedelta(hours=analysis_hours)

   # Collect baseline data
   baseline_messages = Counter()
   baseline_levels = Counter()

   try:
       with open(log_file_path, 'r') as f:
           for line in f:
               if line.strip():
                   try:
                       entry = json.loads(line)
                       timestamp = entry.get('timestamp')

                       if timestamp:
                           try:
                               entry_time = datetime.fromisoformat(
                                   timestamp.replace('Z', '+00:00')
                               )

                               if baseline_start <= entry_time <= baseline_end:
                                   message = entry.get('message', '')
                                   level = entry.get('level', 'UNKNOWN')

                                   baseline_messages[message] += 1
                                   baseline_levels[level] += 1

                           except ValueError:
                               continue

                   except json.JSONDecodeError:
                       continue

       # Analyze recent period
       analysis_messages = Counter()
       analysis_levels = Counter()

       with open(log_file_path, 'r') as f:
           for line in f:
               if line.strip():
                   try:
                       entry = json.loads(line)
                       timestamp = entry.get('timestamp')

                       if timestamp:
                           try:
                               entry_time = datetime.fromisoformat(
                                   timestamp.replace('Z', '+00:00')
                               )

                               if analysis_start <= entry_time <= analysis_end:
                                   message = entry.get('message', '')
                                   level = entry.get('level', 'UNKNOWN')

                                   analysis_messages[message] += 1
                                   analysis_levels[level] += 1

                           except ValueError:
                               continue

                   except json.JSONDecodeError:
                       continue

       # Detect anomalies
       anomalies = []

       # Check for unusual message frequency
       for message, count in analysis_messages.items():
           baseline_count = baseline_messages.get(message, 0)
           if baseline_count == 0 and count > 2:
               anomalies.append({
                   'type': 'new_message_pattern',
                   'message': message,
                   'frequency': count,
                   'severity': 'medium'
               })

       # Check for unusual log level distribution
       for level, count in analysis_levels.items():
           baseline_count = baseline_levels.get(level, 0)
           if baseline_count > 0:
               ratio = count / baseline_count
               if ratio > 3.0:  # 3x increase in log volume
                   anomalies.append({
                       'type': 'log_level_spike',
                       'level': level,
                       'current_count': count,
                       'baseline_count': baseline_count,
                       'ratio': ratio,
                       'severity': 'high' if level in ['ERROR', 'CRITICAL'] else 'low'
                   })

       return anomalies

   except FileNotFoundError:
       print(f"Log file not found: {log_file_path}")
       return None
```

#### 3. Log-Based Performance Profiling

**Extract Performance Insights:**
```python
def extract_performance_insights(log_file_path):
   """Extract performance insights from application logs."""
   import json
   import re
   from datetime import datetime
   from collections import defaultdict

   performance_insights = {
       'slow_operations': [],
       'memory_issues': [],
       'network_problems': [],
       'resource_contention': []
   }

   try:
       with open(log_file_path, 'r') as f:
           for line_num, line in enumerate(f, 1):
               if line.strip():
                   try:
                       entry = json.loads(line)

                       message = entry.get('message', '')
                       level = entry.get('level', '')
                       timestamp = entry.get('timestamp')
                       extra = entry.get('extra', {})

                       # Detect slow operations
                       if 'timeout' in message.lower() or 'slow' in message.lower():
                           performance_insights['slow_operations'].append({
                               'timestamp': timestamp,
                               'message': message,
                               'level': level,
                               'line': line_num
                           })

                       # Detect memory issues
                       if any(term in message.lower() for term in ['memory', 'out of memory', 'allocation']):
                           performance_insights['memory_issues'].append({
                               'timestamp': timestamp,
                               'message': message,
                               'level': level,
                               'line': line_num
                           })

                       # Detect network problems
                       if any(term in message.lower() for term in ['connection', 'network', 'timeout']):
                           performance_insights['network_problems'].append({
                               'timestamp': timestamp,
                               'message': message,
                               'level': level,
                               'line': line_num
                           })

                       # Check for performance metrics in extra data
                       if extra.get('performance_metric'):
                           metric_name = extra.get('metric_name')
                           value = extra.get('value')

                           if metric_name and value:
                               # Flag concerning performance values
                               if 'response_time' in metric_name and value > 5.0:  # > 5 seconds
                                   performance_insights['slow_operations'].append({
                                       'timestamp': timestamp,
                                       'metric': metric_name,
                                       'value': value,
                                       'threshold': 5.0,
                                       'line': line_num
                                   })

                   except json.JSONDecodeError:
                       continue

       # Print insights summary
       print("Performance Insights Summary:")
       for category, issues in performance_insights.items():
           if issues:
               print(f"  {category.replace('_', ' ').title()}: {len(issues)} issues")

               # Show most recent issues
               for issue in issues[-3:]:
                   print(f"    {issue.get('timestamp', 'Unknown')}: {issue.get('message', issue.get('metric', 'Unknown'))}")

       return performance_insights

   except FileNotFoundError:
       print(f"Log file not found: {log_file_path}")
       return None
```

### Log Analysis Tools and Scripts

#### 1. Automated Log Analyzer

```python
#!/usr/bin/env python3
"""
Automated Log Analysis Tool for Privatus-chat
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, defaultdict

class LogAnalyzer:
   """Comprehensive log analysis tool."""

   def __init__(self, log_directory):
       self.log_dir = Path(log_directory)
       self.analysis_results = {}

   def analyze_all_logs(self, hours_back=24):
       """Perform comprehensive analysis of all log files."""
       print(f"=== Log Analysis Report ===")
       print(f"Analysis Time: {datetime.utcnow().isoformat()}")
       print(f"Time Window: {hours_back} hours")
       print("=" * 50)

       # Analyze each log file type
       log_files = {
           'main': self.log_dir / 'privatus-chat.log',
           'errors': self.log_dir / 'privatus-chat_errors.log',
           'security': self.log_dir / 'privatus-chat_security.log',
           'buffered': self.log_dir / 'privatus-chat_buffered.jsonl'
       }

       for log_type, log_path in log_files.items():
           if log_path.exists():
               print(f"\n--- {log_type.upper()} LOG ANALYSIS ---")
               self.analyze_single_log(log_path, hours_back)
           else:
               print(f"\n--- {log_type.upper()} LOG ---")
               print(f"Log file not found: {log_path}")

   def analyze_single_log(self, log_path, hours_back):
       """Analyze a single log file."""
       cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)

       try:
           # Basic statistics
           total_entries = 0
           level_counts = Counter()
           recent_errors = []

           with open(log_path, 'r') as f:
               for line in f:
                   if line.strip():
                       try:
                           entry = json.loads(line)
                           total_entries += 1

                           # Parse timestamp
                           timestamp_str = entry.get('timestamp')
                           if timestamp_str:
                               try:
                                   entry_time = datetime.fromisoformat(
                                       timestamp_str.replace('Z', '+00:00')
                                   )

                                   if entry_time >= cutoff_time:
                                       level = entry.get('level', 'UNKNOWN')
                                       level_counts[level] += 1

                                       if level in ['ERROR', 'CRITICAL']:
                                           recent_errors.append(entry)

                               except ValueError:
                                   continue

                       except json.JSONDecodeError:
                           continue

           # Print results
           print(f"Total entries: {total_entries}")
           print(f"Recent entries ({hours_back}h): {sum(level_counts.values())}")
           print("Log levels:"            for level, count in level_counts.most_common():
               print(f"  {level}: {count}")

           if recent_errors:
               print(f"Recent errors: {len(recent_errors)}")
               # Show most recent error
               latest_error = max(recent_errors, key=lambda x: x.get('timestamp', ''))
               print(f"  Latest: {latest_error.get('message', 'Unknown')}")

       except Exception as e:
           print(f"Error analyzing {log_path}: {e}")

def main():
   parser = argparse.ArgumentParser(description='Analyze Privatus-chat logs')
   parser.add_argument('--log-dir', default='~/.privatus-chat/logs',
                      help='Log directory path')
   parser.add_argument('--hours', type=int, default=24,
                      help='Hours to look back')

   args = parser.parse_args()

   # Expand user path
   log_dir = Path(args.log_dir).expanduser()

   if not log_dir.exists():
       print(f"Log directory not found: {log_dir}")
       sys.exit(1)

   analyzer = LogAnalyzer(log_dir)
   analyzer.analyze_all_logs(args.hours)

if __name__ == "__main__":
   main()
```

#### 2. Real-time Log Monitor

```python
#!/usr/bin/env python3
"""
Real-time Log Monitor for Privatus-chat
"""

import json
import time
import argparse
from pathlib import Path
from collections import deque, Counter
from datetime import datetime, timedelta

class RealTimeLogMonitor:
   """Monitor logs in real-time for issues."""

   def __init__(self, log_file, alert_thresholds=None):
       self.log_file = Path(log_file)
       self.alert_thresholds = alert_thresholds or {
           'error_rate': 5,  # errors per minute
           'critical_rate': 1,  # critical per 5 minutes
           'memory_spike': 100  # MB increase
       }

       # Track recent activity
       self.recent_errors = deque(maxlen=100)
       self.error_rates = deque(maxlen=60)  # 1 hour of minute-by-minute data

   def monitor_logs(self, duration_minutes=60):
       """Monitor logs for the specified duration."""
       print(f"Monitoring {self.log_file} for {duration_minutes} minutes...")
       print("Press Ctrl+C to stop\n")

       start_time = datetime.utcnow()
       end_time = start_time + timedelta(minutes=duration_minutes)

       try:
           # Get initial file size
           last_size = self.log_file.stat().st_size if self.log_file.exists() else 0

           while datetime.utcnow() < end_time:
               try:
                   current_size = self.log_file.stat().st_size

                   if current_size > last_size:
                       # Read new content
                       with open(self.log_file, 'r') as f:
                           f.seek(last_size)
                           new_content = f.read()
                           last_size = current_size

                       # Process new lines
                       for line in new_content.split('\n'):
                           if line.strip():
                               self.process_log_line(line)

                   # Check alert conditions every minute
                   if int(time.time()) % 60 == 0:
                       self.check_alerts()

                   time.sleep(1)

               except FileNotFoundError:
                   time.sleep(5)  # Wait for file to be created
                   continue

       except KeyboardInterrupt:
           print("\nMonitoring stopped by user")

       self.print_final_summary()

   def process_log_line(self, line):
       """Process a single log line."""
       try:
           entry = json.loads(line)

           level = entry.get('level', 'INFO')
           timestamp = entry.get('timestamp')
           message = entry.get('message', '')

           # Track errors
           if level in ['ERROR', 'CRITICAL']:
               self.recent_errors.append({
                   'timestamp': timestamp,
                   'level': level,
                   'message': message
               })

           # Print significant events
           if level in ['ERROR', 'CRITICAL']:
               print(f"[{timestamp}] {level}: {message}")
           elif level == 'WARNING' and any(term in message.lower()
                                         for term in ['memory', 'cpu', 'disk']):
               print(f"[{timestamp}] {level}: {message}")

       except json.JSONDecodeError:
           pass  # Skip malformed lines

   def check_alerts(self):
       """Check if alert thresholds are exceeded."""
       now = datetime.utcnow()

       # Calculate error rate (errors per minute)
       recent_minute = now - timedelta(minutes=1)
       recent_errors = [
           error for error in self.recent_errors
           if error.get('timestamp') and
           datetime.fromisoformat(error['timestamp'].replace('Z', '+00:00')) > recent_minute
       ]

       error_rate = len(recent_errors)

       if error_rate >= self.alert_thresholds['error_rate']:
           print(f"🚨 ALERT: High error rate detected ({error_rate} errors/minute)")

       # Check for critical errors
       recent_5min = now - timedelta(minutes=5)
       recent_critical = [
           error for error in self.recent_errors
           if error.get('level') == 'CRITICAL' and
           error.get('timestamp') and
           datetime.fromisoformat(error['timestamp'].replace('Z', '+00:00')) > recent_5min
       ]

       if len(recent_critical) >= self.alert_thresholds['critical_rate']:
           print(f"🚨 ALERT: Multiple critical errors in last 5 minutes ({len(recent_critical)})")

   def print_final_summary(self):
       """Print monitoring summary."""
       print("\n=== Monitoring Summary ===")

       if self.recent_errors:
           error_levels = Counter(error['level'] for error in self.recent_errors)
           print("Errors by level:")
           for level, count in error_levels.items():
               print(f"  {level}: {count}")

           # Show most recent errors
           print("\nMost recent errors:")
           for error in list(self.recent_errors)[-5:]:
               print(f"  {error['timestamp']}: {error['message']}")
       else:
           print("No errors detected during monitoring period")

def main():
   parser = argparse.ArgumentParser(description='Monitor Privatus-chat logs in real-time')
   parser.add_argument('--log-file', default='~/.privatus-chat/logs/privatus-chat.log',
                      help='Log file to monitor')
   parser.add_argument('--duration', type=int, default=60,
                      help='Monitoring duration in minutes')

   args = parser.parse_args()

   # Expand user path
   log_file = Path(args.log_file).expanduser()

   monitor = RealTimeLogMonitor(log_file)
   monitor.monitor_logs(args.duration)

if __name__ == "__main__":
   main()
```

#### 3. Log Search and Filtering Tool

```python
#!/usr/bin/env python3
"""
Advanced Log Search and Filtering Tool
"""

import json
import argparse
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

class LogSearchTool:
   """Advanced log search and filtering capabilities."""

   def __init__(self, log_directory):
       self.log_dir = Path(log_directory)

   def search_logs(self, query, log_types=None, hours_back=None,
                  level=None, regex=False):
       """Search logs with advanced filtering."""
       log_types = log_types or ['main', 'errors', 'security']
       results = []

       # Determine time filter
       cutoff_time = None
       if hours_back:
           cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)

       # Compile search pattern
       if regex:
           try:
               pattern = re.compile(query, re.IGNORECASE)
           except re.error as e:
               print(f"Invalid regex pattern: {e}")
               return []
       else:
           pattern = query.lower()

       # Search each log file
       for log_type in log_types:
           log_path = self.log_dir / f'privatus-chat_{log_type}.log'
           if log_type == 'main':
               log_path = self.log_dir / 'privatus-chat.log'

           if not log_path.exists():
               continue

           try:
               with open(log_path, 'r') as f:
                   for line_num, line in enumerate(f, 1):
                       if line.strip():
                           try:
                               entry = json.loads(line)

                               # Apply time filter
                               if cutoff_time and entry.get('timestamp'):
                                   try:
                                       entry_time = datetime.fromisoformat(
                                           entry['timestamp'].replace('Z', '+00:00')
                                       )
                                       if entry_time < cutoff_time:
                                           continue
                                   except ValueError:
                                       continue

                               # Apply level filter
                               if level and entry.get('level') != level:
                                   continue

                               # Search in message and extra data
                               message = entry.get('message', '')
                               extra_data = json.dumps(entry.get('extra', {}))

                               search_text = (message + ' ' + extra_data).lower()

                               if regex:
                                   if pattern.search(search_text):
                                       results.append({
                                           'entry': entry,
                                           'file': log_path.name,
                                           'line': line_num,
                                           'matched_in': 'regex_match'
                                       })
                               else:
                                   if query.lower() in search_text:
                                       results.append({
                                           'entry': entry,
                                           'file': log_path.name,
                                           'line': line_num,
                                           'matched_in': 'text_search'
                                       })

                           except json.JSONDecodeError:
                               continue

           except Exception as e:
               print(f"Error reading {log_path}: {e}")

       return results

   def print_search_results(self, results, max_results=50):
       """Print formatted search results."""
       if not results:
           print("No matching log entries found")
           return

       print(f"Found {len(results)} matching entries (showing first {min(max_results, len(results))}):")
       print("=" * 80)

       for i, result in enumerate(results[:max_results]):
           entry = result['entry']
           print(f"\n{i+1}. [{entry.get('timestamp', 'Unknown')}] {entry.get('level', 'INFO')}")
           print(f"   File: {result['file']}:{result['line']}")
           print(f"   Message: {entry.get('message', 'No message')}")

           # Show relevant extra data
           extra = entry.get('extra', {})
           if extra:
               for key, value in extra.items():
                   if isinstance(value, (str, int, float, bool)):
                       print(f"   {key}: {value}")

       if len(results) > max_results:
           print(f"\n... and {len(results) - max_results} more results")

def main():
   parser = argparse.ArgumentParser(description='Search Privatus-chat logs')
   parser.add_argument('--log-dir', default='~/.privatus-chat/logs',
                      help='Log directory path')
   parser.add_argument('query', help='Search query (text or regex)')
   parser.add_argument('--log-types', nargs='+',
                      choices=['main', 'errors', 'security', 'buffered'],
                      default=['main', 'errors'],
                      help='Log file types to search')
   parser.add_argument('--hours-back', type=int,
                      help='Search only entries from N hours ago')
   parser.add_argument('--level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      help='Filter by log level')
   parser.add_argument('--regex', action='store_true',
                      help='Treat query as regular expression')
   parser.add_argument('--max-results', type=int, default=50,
                      help='Maximum number of results to show')

   args = parser.parse_args()

   # Expand user path
   log_dir = Path(args.log_dir).expanduser()

   if not log_dir.exists():
       print(f"Log directory not found: {log_dir}")
       sys.exit(1)

   searcher = LogSearchTool(log_dir)
   results = searcher.search_logs(
       args.query,
       args.log_types,
       args.hours_back,
       args.level,
       args.regex
   )

   searcher.print_search_results(results, args.max_results)

if __name__ == "__main__":
   main()
```

### Log Analysis Best Practices

#### 1. Systematic Log Investigation

**Step-by-Step Analysis Process:**
1. **Identify the Problem**: Define what you're looking for (error, performance issue, security event)
2. **Gather Context**: Determine time windows and affected components
3. **Filter and Search**: Use appropriate filters to narrow down relevant logs
4. **Pattern Recognition**: Look for recurring patterns and correlations
5. **Root Cause Analysis**: Trace back to identify the source of issues
6. **Verification**: Confirm findings with additional evidence

**Effective Search Strategies:**
```python
def systematic_log_investigation(problem_description, time_window_hours=4):
   """Perform systematic log investigation for a problem."""

   # Step 1: Define search criteria
   search_criteria = {
       'keywords': extract_keywords(problem_description),
       'time_window': time_window_hours,
       'log_levels': ['ERROR', 'CRITICAL', 'WARNING'],
       'components': identify_affected_components(problem_description)
   }

   # Step 2: Multi-stage search
   results = []

   # Stage 1: Broad search for error patterns
   broad_results = search_logs(
       ' OR '.join(search_criteria['keywords']),
       hours_back=search_criteria['time_window'],
       level=search_criteria['log_levels']
   )
   results.extend(broad_results)

   # Stage 3: Component-specific search
   for component in search_criteria['components']:
       component_results = search_logs(
           f"component:{component}",
           hours_back=search_criteria['time_window']
       )
       results.extend(component_results)

   # Step 4: Analyze and correlate results
   analysis = analyze_search_results(results)

   return analysis

def extract_keywords(description):
   """Extract relevant keywords from problem description."""
   # Simple keyword extraction - could be enhanced with NLP
   common_terms = {
       'connection': ['connection', 'connect', 'network', 'timeout'],
       'authentication': ['auth', 'login', 'password', 'token'],
       'performance': ['slow', 'timeout', 'memory', 'cpu'],
       'security': ['unauthorized', 'forbidden', 'breach', 'attack']
   }

   keywords = []
   desc_lower = description.lower()

   for category, terms in common_terms.items():
       if any(term in desc_lower for term in terms):
           keywords.extend(terms)

   return keywords or [description]
```

#### 2. Performance Analysis Workflow

**Log-Based Performance Investigation:**
```python
def investigate_performance_issue(symptoms, time_window_hours=2):
   """Investigate performance issues using log analysis."""

   # 1. Extract performance metrics from logs
   performance_data = extract_performance_metrics_from_logs(time_window_hours)

   # 2. Identify performance degradation patterns
   degradation_points = identify_performance_degradation(performance_data)

   # 3. Correlate with system events
   correlated_events = correlate_with_system_events(degradation_points)

   # 4. Generate performance report
   report = generate_performance_report(
       symptoms,
       performance_data,
       degradation_points,
       correlated_events
   )

   return report
```

#### 3. Security Incident Response

**Security Log Analysis for Incident Response:**
```python
def security_incident_analysis(incident_time, incident_type):
   """Analyze security logs for incident response."""

   # 1. Gather security events around incident time
   security_events = collect_security_events(
       incident_time,
       window_minutes=30
   )

   # 2. Identify attack patterns
   attack_indicators = identify_attack_patterns(security_events)

   # 3. Trace attacker activity
   attack_trace = trace_attacker_activity(security_events, attack_indicators)

   # 4. Assess impact and scope
   impact_assessment = assess_security_impact(attack_trace)

   # 5. Generate incident report
   incident_report = generate_incident_report(
       incident_type,
       security_events,
       attack_indicators,
       attack_trace,
       impact_assessment
   )

   return incident_report
```

### Log Analysis Case Studies

#### Case Study 1: Intermittent Connection Failures

**Problem**: Users experiencing random connection drops during messaging.

**Analysis Steps:**
1. **Search for connection-related errors:**
  ```bash
  python log_search_tool.py "connection.*timeout|Connection reset|Connection refused"
  ```

2. **Identify temporal patterns:**
  ```python
  # Look for error bursts
  error_bursts = identify_error_bursts(connection_errors, window_minutes=5)
  ```

3. **Correlate with network events:**
  ```python
  # Check for related network events
  network_events = correlate_network_events(error_bursts)
  ```

**Findings**: Connection drops occurred every 30 minutes, correlating with network maintenance windows.

#### Case Study 2: Memory Leak Detection

**Problem**: Application memory usage gradually increasing over time.

**Analysis Steps:**
1. **Extract memory-related logs:**
  ```python
  memory_logs = search_logs("memory|allocation|leak", hours_back=48)
  ```

2. **Analyze memory usage patterns:**
  ```python
  memory_trends = analyze_memory_trends(memory_logs)
  ```

3. **Identify memory hotspots:**
  ```python
  hotspots = identify_memory_hotspots(memory_trends)
  ```

**Findings**: Memory leak in message caching system, objects not properly cleaned up.

#### Case Study 3: Security Breach Investigation

**Problem**: Suspicious authentication attempts detected.

**Analysis Steps:**
1. **Gather security events:**
  ```python
  security_events = analyze_security_events(hours_back=24)
  ```

2. **Identify attack patterns:**
  ```python
  attack_patterns = identify_suspicious_patterns(security_events)
  ```

3. **Trace attacker activity:**
  ```python
  attack_trace = trace_attacker_journey(attack_patterns)
  ```

**Findings**: Coordinated brute force attack from multiple IP addresses targeting weak user credentials.

### Log Analysis Tools Integration

#### Integration with External Tools

**ELK Stack Integration:**
```python
def setup_logstash_pipeline():
   """Setup Logstash pipeline for advanced log analysis."""

   logstash_config = """
   input {
       file {
           path => "/home/user/.privatus-chat/logs/privatus-chat_*.log"
           codec => json
           start_position => "beginning"
       }
   }

   filter {
       grok {
           match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} - %{LOGLEVEL:level} - %{GREEDYDATA:message}" }
       }

       mutate {
           add_field => {
               "application" => "privatus-chat"
               "environment" => "development"
           }
       }
   }

   output {
       elasticsearch {
           hosts => ["localhost:9200"]
           index => "privatus-chat-%{+YYYY.MM.dd}"
       }
   }
   """

   return logstash_config
```

**Grafana Dashboard Configuration:**
```python
def create_log_analysis_dashboard():
   """Create Grafana dashboard for log analysis."""

   dashboard_config = {
       "title": "Privatus-chat Log Analysis",
       "panels": [
           {
               "title": "Error Rate",
               "type": "graph",
               "targets": [
                   {
                       "expr": "rate(privatus_chat_errors_total[5m])",
                       "legendFormat": "Error Rate"
                   }
               ]
           },
           {
               "title": "Log Level Distribution",
               "type": "piechart",
               "targets": [
                   {
                       "expr": "privatus_chat_logs_by_level",
                       "legendFormat": "{{ level }}"
                   }
               ]
           },
           {
               "title": "Top Error Messages",
               "type": "table",
               "targets": [
                   {
                       "expr": "topk(10, privatus_chat_error_messages_total)",
                       "legendFormat": "{{ message }}"
                   }
               ]
           }
       ]
   }

   return dashboard_config
```

## Effective Debugging Techniques and Workflows

### Systematic Debugging Methodology

#### 1. Problem Definition and Scoping

**Define the Problem Clearly:**
```python
def define_debugging_problem():
   """Structure your debugging approach systematically."""

   problem_definition = {
       'description': "Clear description of the issue",
       'symptoms': [
           "Observable behaviors that indicate the problem",
           "Error messages or unexpected outputs",
           "Performance degradation or crashes"
       ],
       'scope': {
           'affected_components': ['component1', 'component2'],
           'affected_operations': ['operation1', 'operation2'],
           'frequency': 'intermittent|consistent|under_specific_conditions'
       },
       'environment': {
           'platform': 'linux|windows|macos',
           'configuration': 'development|testing|production',
           'dependencies': 'list of relevant dependencies'
       },
       'expected_behavior': "What should happen instead",
       'actual_behavior': "What is actually happening"
   }

   return problem_definition
```

**Scope Assessment:**
```python
def assess_problem_scope(symptoms):
   """Determine the scope and impact of the problem."""

   scope_indicators = {
       'localized': {
           'indicators': ['single_component', 'isolated_function', 'specific_operation'],
           'debugging_approach': 'component_focused'
       },
       'systemic': {
           'indicators': ['multiple_components', 'cross_system_effects', 'performance_impact'],
           'debugging_approach': 'system_wide_analysis'
       },
       'intermittent': {
           'indicators': ['timing_dependent', 'race_conditions', 'resource_dependent'],
           'debugging_approach': 'reproduction_focused'
       }
   }

   # Analyze symptoms to determine scope
   if any(indicator in str(symptoms).lower() for indicator in
          ['multiple', 'system', 'cross', 'performance']):
       return 'systemic'
   elif any(indicator in str(symptoms).lower() for indicator in
            ['sometimes', 'randomly', 'intermittently', 'timing']):
       return 'intermittent'
   else:
       return 'localized'
```

#### 2. Information Gathering Phase

**Collect Comprehensive Context:**
```python
def gather_debugging_context():
   """Gather all relevant information for debugging."""

   context = {
       'system_state': {
           'configuration': collect_system_configuration(),
           'environment_variables': collect_environment_variables(),
           'running_processes': collect_process_information(),
           'resource_usage': collect_resource_usage()
       },
       'recent_changes': {
           'code_changes': collect_recent_code_changes(),
           'configuration_changes': collect_recent_config_changes(),
           'dependency_updates': collect_dependency_updates()
       },
       'error_context': {
           'error_messages': collect_error_messages(),
           'stack_traces': collect_stack_traces(),
           'log_entries': collect_relevant_logs()
       },
       'reproduction_steps': {
           'steps_to_reproduce': document_reproduction_steps(),
           'test_cases': identify_relevant_test_cases(),
           'minimal_example': create_minimal_reproduction()
       }
   }

   return context
```

**Log-Based Context Collection:**
```python
def collect_relevant_logs(time_window_hours=4, components=None):
   """Collect logs relevant to the current issue."""

   # Define log collection criteria
   collection_criteria = {
       'time_window': time_window_hours,
       'components': components or ['all'],
       'log_levels': ['ERROR', 'CRITICAL', 'WARNING'],
       'keywords': extract_issue_keywords()
   }

   # Collect from different log sources
   logs = {
       'application_logs': search_application_logs(collection_criteria),
       'system_logs': search_system_logs(collection_criteria),
       'security_logs': search_security_logs(collection_criteria),
       'performance_logs': search_performance_logs(collection_criteria)
   }

   # Correlate and filter logs
   correlated_logs = correlate_log_entries(logs)

   return correlated_logs
```

#### 3. Hypothesis Formation

**Develop Debugging Hypotheses:**
```python
def develop_debugging_hypotheses(problem_description, context):
   """Develop testable hypotheses for the problem."""

   hypotheses = []

   # Common hypothesis patterns
   hypothesis_templates = {
       'configuration': "Issue is caused by incorrect {component} configuration",
       'resource': "Issue is caused by insufficient {resource} availability",
       'timing': "Issue is caused by race condition or timing dependency",
       'dependency': "Issue is caused by incompatible or missing dependency",
       'environment': "Issue is specific to certain environment conditions",
       'code_logic': "Issue is caused by logical error in {component} code"
   }

   # Generate hypotheses based on problem characteristics
   if 'connection' in problem_description.lower():
       hypotheses.extend([
           "Network configuration issue preventing proper connection",
           "Firewall or security policy blocking connection",
           "Resource exhaustion causing connection drops",
           "Race condition in connection establishment"
       ])

   if 'performance' in problem_description.lower():
       hypotheses.extend([
           "Memory leak causing gradual performance degradation",
           "Resource contention between components",
           "Inefficient algorithm or data structure",
           "External service bottleneck"
       ])

   if 'authentication' in problem_description.lower():
       hypotheses.extend([
           "Incorrect credential validation logic",
           "Session management issue",
           "Token expiration or refresh problem",
           "Authentication service unavailable"
       ])

   return hypotheses
```

### Component-Specific Debugging Techniques

#### 1. Network Component Debugging

**Network Issue Investigation:**
```python
def debug_network_issues():
   """Debug network-related problems systematically."""

   # 1. Connection State Analysis
   connection_analysis = {
       'active_connections': check_active_connections(),
       'connection_pool_status': check_connection_pool(),
       'network_interfaces': check_network_interfaces(),
       'routing_table': check_routing_table()
   }

   # 2. Protocol-Level Debugging
   protocol_debug = {
       'message_flow': trace_message_flow(),
       'handshake_process': debug_handshake_process(),
       'encryption_negotiation': debug_crypto_negotiation(),
       'error_handling': debug_error_handling()
   }

   # 3. Performance Analysis
   performance_analysis = {
       'latency_measurements': measure_latency(),
       'throughput_analysis': analyze_throughput(),
       'packet_loss_detection': detect_packet_loss(),
       'bandwidth_utilization': check_bandwidth_usage()
   }

   return {
       'connection_analysis': connection_analysis,
       'protocol_debug': protocol_debug,
       'performance_analysis': performance_analysis
   }
```

**Network Packet Tracing:**
```python
def trace_network_packets(component_name="message_protocol"):
   """Trace network packets for debugging."""

   import socket
   import struct

   def packet_tracer():
       # Create raw socket for packet capture
       try:
           sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
       except PermissionError:
           print("Need root privileges for packet tracing")
           return

       # Capture packets
       packets = []
       for _ in range(100):  # Capture 100 packets
           try:
               packet = sock.recvfrom(65565)
               packets.append(packet)
           except socket.timeout:
               break

       # Analyze packets for the component
       component_packets = []
       for packet_data, addr in packets:
           # Basic packet analysis
           if len(packet_data) >= 14:
               dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', packet_data[:14])

               if eth_proto == 0x0800:  # IP packet
                   # Further analysis for IP packets
                   packet_info = {
                       'timestamp': time.time(),
                       'source_mac': ':'.join(f'{b:02x}' for b in src_mac),
                       'dest_mac': ':'.join(f'{b:02x}' for b in dest_mac),
                       'protocol': 'IP'
                   }
                   component_packets.append(packet_info)

       return component_packets
```

#### 2. Cryptography Component Debugging

**Crypto Operation Debugging:**
```python
def debug_crypto_operations():
   """Debug cryptographic operations and key management."""

   # 1. Key Management Analysis
   key_analysis = {
       'key_generation': test_key_generation(),
       'key_storage': verify_key_storage(),
       'key_rotation': check_key_rotation(),
       'key_backup': verify_key_backup()
   }

   # 2. Encryption/Decryption Testing
   crypto_testing = {
       'symmetric_encryption': test_symmetric_crypto(),
       'asymmetric_encryption': test_asymmetric_crypto(),
       'key_exchange': test_key_exchange(),
       'signature_verification': test_signature_verification()
   }

   # 3. Security Analysis
   security_analysis = {
       'randomness_quality': test_randomness_quality(),
       'key_strength': analyze_key_strength(),
       'algorithm_correctness': verify_algorithm_implementation(),
       'side_channel_protection': check_side_channel_protection()
   }

   return {
       'key_analysis': key_analysis,
       'crypto_testing': crypto_testing,
       'security_analysis': security_analysis
   }
```

**Key Management Debugging:**
```python
def debug_key_management_issues():
   """Debug key management and storage issues."""

   # Test key generation
   def test_key_generation_process():
       from src.crypto.key_management import KeyManager
       from pathlib import Path

       try:
           # Test key generation
           storage_path = Path("/tmp/debug_keys")
           key_manager = KeyManager(storage_path, "debug_password")

           # Generate test keys
           identity_key = key_manager.generate_identity_key()
           signed_prekey = key_manager.generate_signed_prekey()
           one_time_prekeys = key_manager.generate_one_time_prekeys(count=5)

           print(f"✓ Generated identity key: {len(identity_key) > 0}")
           print(f"✓ Generated signed prekey: {len(signed_prekey) > 0}")
           print(f"✓ Generated {len(one_time_prekeys)} one-time prekeys")

           # Test key storage
           stored_keys = key_manager.get_stored_prekeys()
           print(f"✓ Stored prekeys: {len(stored_keys)}")

           return True

       except Exception as e:
           print(f"✗ Key generation failed: {e}")
           return False

   # Test key encryption/decryption
   def test_key_crypto_operations():
       try:
           # Test key encryption
           test_data = b"test_key_data"
           encrypted = key_manager.encrypt_key_data(test_data)
           decrypted = key_manager.decrypt_key_data(encrypted)

           if decrypted == test_data:
               print("✓ Key encryption/decryption working")
               return True
           else:
               print("✗ Key encryption/decryption failed")
               return False

       except Exception as e:
           print(f"✗ Key crypto test failed: {e}")
           return False

   return {
       'key_generation': test_key_generation_process(),
       'key_crypto': test_key_crypto_operations()
   }
```

#### 3. Storage Component Debugging

**Database Debugging:**
```python
def debug_storage_issues():
   """Debug storage and database problems."""

   # 1. Database Connection Analysis
   connection_analysis = {
       'connection_pool': analyze_connection_pool(),
       'query_performance': analyze_query_performance(),
       'transaction_handling': check_transaction_handling(),
       'connection_leaks': detect_connection_leaks()
   }

   # 2. Data Integrity Checks
   integrity_checks = {
       'schema_validation': validate_database_schema(),
       'data_consistency': check_data_consistency(),
       'index_health': check_index_health(),
       'constraint_validation': validate_constraints()
   }

   # 3. Performance Analysis
   performance_analysis = {
       'query_optimization': analyze_query_plans(),
       'lock_analysis': analyze_locking_issues(),
       'cache_effectiveness': check_cache_performance(),
       'i/o_patterns': analyze_io_patterns()
   }

   return {
       'connection_analysis': connection_analysis,
       'integrity_checks': integrity_checks,
       'performance_analysis': performance_analysis
   }
```

**Database Query Debugging:**
```python
def debug_database_queries():
   """Debug database query issues."""

   def analyze_query_performance():
       """Analyze slow or problematic queries."""
       import sqlite3
       import time

       # Enable query profiling
       conn = sqlite3.connect(':memory:')
       conn.set_trace_callback(lambda query: print(f"Executing: {query}"))

       # Test query performance
       cursor = conn.cursor()

       # Create test table
       cursor.execute('''
           CREATE TABLE test_performance (
               id INTEGER PRIMARY KEY,
               data TEXT,
               created_at TIMESTAMP
           )
       ''')

       # Insert test data
       for i in range(1000):
           cursor.execute("INSERT INTO test_performance VALUES (?, ?, ?)",
                        (i, f"data_{i}", time.time()))

       # Test different query patterns
       queries = [
           "SELECT * FROM test_performance WHERE id = ?",
           "SELECT * FROM test_performance WHERE data LIKE ?",
           "SELECT COUNT(*) FROM test_performance",
           "SELECT * FROM test_performance ORDER BY created_at DESC LIMIT 10"
       ]

       for query in queries:
           start_time = time.time()
           if '?' in query:
               cursor.execute(query, (f"data_{500}",))
           else:
               cursor.execute(query)

           results = cursor.fetchall()
           end_time = time.time()

           print(f"Query: {query}")
           print(f"  Execution time: {end_time - start_time".4f"}s")
           print(f"  Results: {len(results)} rows")

       conn.close()

   def check_database_integrity():
       """Check database integrity and consistency."""
       try:
           from src.storage.database_fixed import StorageManager
           from pathlib import Path

           # Test database operations
           db_path = Path("/tmp/debug_db")
           storage = StorageManager(db_path, "debug_password")

           # Test basic operations
           test_contact = {
               'contact_id': 'debug_user_123',
               'display_name': 'Debug User',
               'public_key': b'debug_public_key_data'
           }

           # Test insert
           insert_result = storage.add_contact(test_contact)
           print(f"✓ Contact insert: {insert_result}")

           # Test retrieve
           retrieved = storage.get_contact('debug_user_123')
           print(f"✓ Contact retrieve: {retrieved is not None}")

           # Test update
           update_result = storage.update_contact('debug_user_123', {'display_name': 'Updated Debug User'})
           print(f"✓ Contact update: {update_result}")

           # Test delete
           delete_result = storage.delete_contact('debug_user_123')
           print(f"✓ Contact delete: {delete_result}")

           return True

       except Exception as e:
           print(f"✗ Database integrity check failed: {e}")
           return False

   return {
       'query_performance': analyze_query_performance(),
       'integrity_check': check_database_integrity()
   }
```

#### 4. GUI Component Debugging

**GUI Debugging Techniques:**
```python
def debug_gui_issues():
   """Debug GUI-related problems."""

   # 1. Component State Analysis
   component_analysis = {
       'widget_hierarchy': analyze_widget_hierarchy(),
       'event_handling': debug_event_handling(),
       'layout_issues': check_layout_problems(),
       'styling_problems': debug_styling_issues()
   }

   # 2. User Interaction Debugging
   interaction_debug = {
       'input_validation': test_input_validation(),
       'button_responses': test_button_responses(),
       'menu_operations': test_menu_operations(),
       'keyboard_shortcuts': test_keyboard_shortcuts()
   }

   # 3. Rendering Analysis
   rendering_analysis = {
       'paint_events': analyze_paint_events(),
       'resize_handling': test_resize_handling(),
       'theme_application': check_theme_application(),
       'font_rendering': test_font_rendering()
   }

   return {
       'component_analysis': component_analysis,
       'interaction_debug': interaction_debug,
       'rendering_analysis': rendering_analysis
   }
```

**GUI Event Tracing:**
```python
def trace_gui_events():
   """Trace GUI events for debugging."""

   def event_tracer():
       """Create a GUI event tracer."""
       event_log = []

       def log_event(event_type, widget_info, event_data):
           event_entry = {
               'timestamp': time.time(),
               'event_type': event_type,
               'widget': widget_info,
               'data': event_data
           }
           event_log.append(event_entry)

           # Print significant events
           if event_type in ['button_clicked', 'key_pressed', 'window_closed']:
               print(f"GUI Event: {event_type} on {widget_info}")

       # This would be integrated with the actual GUI event system
       # For demonstration, simulate event tracing
       simulated_events = [
           ('window_opened', 'MainWindow', {'size': '1200x800'}),
           ('button_clicked', 'SendButton', {'enabled': True}),
           ('key_pressed', 'MessageInput', {'key': 'Enter'}),
           ('window_resized', 'MainWindow', {'new_size': '1400x900'})
       ]

       for event in simulated_events:
           log_event(*event)

       return event_log

   return event_tracer()
```

### Advanced Debugging Workflows

#### 1. Reproducible Test Case Development

**Creating Minimal Test Cases:**
```python
def create_minimal_test_case(original_issue):
   """Create a minimal test case that reproduces the issue."""

   def extract_minimal_code():
       """Extract minimal code that reproduces the problem."""

       # 1. Identify the core functionality
       core_components = identify_core_components(original_issue)

       # 2. Create isolated test
       test_code = f"""
       # Minimal test case for: {original_issue}
       import sys
       from pathlib import Path

       # Add source path
       src_path = Path(__file__).parent / 'src'
       if str(src_path) not in sys.path:
           sys.path.insert(0, str(src_path))

       try:
           # Import only necessary components
           from {core_components[0]} import {core_components[1]}

           # Reproduce the issue
           def reproduce_issue():
               # Minimal reproduction code here
               pass

           reproduce_issue()

       except Exception as e:
           print(f"Issue reproduced: {e}")
           import traceback
           traceback.print_exc()
       """

       return test_code

   def create_test_script():
       """Create a standalone test script."""

       script_content = f'''#!/usr/bin/env python3
"""
Minimal test case for issue reproduction
Issue: {original_issue}
"""

{extract_minimal_code()}

if __name__ == "__main__":
   reproduce_issue()
'''

       return script_content

   return create_test_script()
```

#### 2. Binary Search Debugging

**Binary Search for Bug Localization:**
```python
def binary_search_debugging(source_file, issue_description):
   """Use binary search to locate bugs in source code."""

   def bisect_code_file():
       """Bisect a source file to find problematic sections."""

       # Read the source file
       with open(source_file, 'r') as f:
           lines = f.readlines()

       print(f"Bisecting {source_file} ({len(lines)} lines)")

       # Binary search approach
       def test_code_section(start_line, end_line):
           """Test a section of code."""
           section_code = ''.join(lines[start_line:end_line])

           # Create temporary test file
           test_file = f"temp_test_{start_line}_{end_line}.py"
           with open(test_file, 'w') as f:
               f.write(section_code)

           try:
               # Test the section
               result = subprocess.run([
                   sys.executable, test_file
               ], capture_output=True, text=True, timeout=30)

               if result.returncode == 0:
                   print(f"✓ Section {start_line}-{end_line}: OK")
                   return True
               else:
                   print(f"✗ Section {start_line}-{end_line}: Failed")
                   print(f"  Error: {result.stderr}")
                   return False

           except subprocess.TimeoutExpired:
               print(f"⚠ Section {start_line}-{end_line}: Timeout")
               return None
           except Exception as e:
               print(f"⚠ Section {start_line}-{end_line}: Error - {e}")
               return None
           finally:
               # Clean up test file
               if os.path.exists(test_file):
                   os.remove(test_file)

       # Binary search through the file
       left, right = 0, len(lines)
       problematic_sections = []

       while left < right:
           mid = (left + right) // 2

           # Test first half
           first_half_ok = test_code_section(left, mid)

           # Test second half
           second_half_ok = test_code_section(mid, right)

           if first_half_ok is False:
               # Problem in first half
               right = mid
               problematic_sections.append((left, mid))
           elif second_half_ok is False:
               # Problem in second half
               left = mid
               problematic_sections.append((mid, right))
           else:
               # Both halves OK, problem might be in interaction
               break

       return problematic_sections

   return bisect_code_file()
```

#### 3. Interactive Debugging Sessions

**Interactive Debugging Console:**
```python
def create_interactive_debug_session():
   """Create an interactive debugging session."""

   class DebugSession:
       """Interactive debugging session."""

       def __init__(self):
           self.debug_context = {}
           self.breakpoints = []
           self.watch_variables = []

       def set_breakpoint(self, file_path, line_number):
           """Set a breakpoint for debugging."""
           breakpoint_info = {
               'file': file_path,
               'line': line_number,
               'enabled': True,
               'condition': None
           }

           self.breakpoints.append(breakpoint_info)
           print(f"✓ Breakpoint set at {file_path}:{line_number}")

       def watch_variable(self, variable_name, scope='local'):
           """Watch a variable for changes."""
           watch_info = {
               'name': variable_name,
               'scope': scope,
               'history': []
           }

           self.watch_variables.append(watch_info)
           print(f"✓ Watching variable: {variable_name}")

       def inspect_object(self, obj):
           """Inspect an object's properties and methods."""
           inspection = {
               'type': type(obj).__name__,
               'module': type(obj).__module__,
               'attributes': [attr for attr in dir(obj) if not attr.startswith('_')],
               'methods': [method for method in dir(obj) if not method.startswith('_') and callable(getattr(obj, method))],
               'docstring': getattr(obj, '__doc__', None)
           }

           print("Object Inspection:")
           print(f"  Type: {inspection['type']}")
           print(f"  Module: {inspection['module']}")
           print(f"  Attributes: {len(inspection['attributes'])}")
           print(f"  Methods: {len(inspection['methods'])}")

           return inspection

       def trace_execution(self, function_name):
           """Trace function execution."""
           def trace_decorator(func):
               def wrapper(*args, **kwargs):
                   print(f"→ Entering {function_name}")
                   start_time = time.time()

                   try:
                       result = func(*args, **kwargs)
                       end_time = time.time()
                       print(f"← Exiting {function_name} ({end_time - start_time".4f"}s)")
                       return result
                   except Exception as e:
                       end_time = time.time()
                       print(f"✗ Exception in {function_name} ({end_time - start_time".4f"}s): {e}")
                       raise

               return wrapper

           return trace_decorator

   return DebugSession()
```

### Debugging Tools and Utilities

#### 1. Custom Debugging Utilities

**Memory Usage Debugger:**
```python
def create_memory_debugger():
   """Create a memory usage debugging tool."""

   class MemoryDebugger:
       """Debug memory usage patterns."""

       def __init__(self):
           self.memory_snapshots = []
           self.tracking_enabled = False

       def start_tracking(self):
           """Start memory tracking."""
           import tracemalloc

           if not self.tracking_enabled:
               tracemalloc.start()
               self.tracking_enabled = True
               print("✓ Memory tracking started")

       def take_snapshot(self, label=""):
           """Take a memory snapshot."""
           if not self.tracking_enabled:
               self.start_tracking()

           import tracemalloc

           snapshot = tracemalloc.take_snapshot()
           snapshot_info = {
               'timestamp': time.time(),
               'label': label,
               'snapshot': snapshot
           }

           self.memory_snapshots.append(snapshot_info)
           print(f"✓ Memory snapshot taken: {label}")

           return snapshot

       def compare_snapshots(self, start_label, end_label):
           """Compare two memory snapshots."""
           start_snapshot = None
           end_snapshot = None

           for snapshot_info in self.memory_snapshots:
               if snapshot_info['label'] == start_label:
                   start_snapshot = snapshot_info['snapshot']
               elif snapshot_info['label'] == end_label:
                   end_snapshot = snapshot_info['snapshot']

           if start_snapshot and end_snapshot:
               # Compare snapshots
               stats = end_snapshot.compare_to(start_snapshot, 'lineno')

               print(f"Memory comparison: {start_label} → {end_label}")
               print("Top memory differences:"
               for stat in stats[:10]:
                   print(f"  {stat}")

               return stats

           return None

       def detect_memory_leaks(self, threshold_mb=10):
           """Detect potential memory leaks."""
           if len(self.memory_snapshots) < 2:
               print("Need at least 2 snapshots for leak detection")
               return None

           # Compare consecutive snapshots
           leak_indicators = []

           for i in range(1, len(self.memory_snapshots)):
               current = self.memory_snapshots[i]
               previous = self.memory_snapshots[i-1]

               stats = current['snapshot'].compare_to(previous['snapshot'], 'lineno')

               # Look for significant memory increases
               total_increase = sum(stat.size_diff for stat in stats if stat.size_diff > 0)

               if total_increase > threshold_mb * 1024 * 1024:  # Convert MB to bytes
                   leak_indicators.append({
                       'from_snapshot': previous['label'],
                       'to_snapshot': current['label'],
                       'memory_increase': total_increase,
                       'top_allocations': stats[:5]
                   })

           return leak_indicators

   return MemoryDebugger()
```

**Performance Profiler:**
```python
def create_performance_profiler():
   """Create a performance profiling tool."""

   class PerformanceProfiler:
       """Profile application performance."""

       def __init__(self):
           self.profiles = {}
           self.timers = {}

       def start_timer(self, name):
           """Start a performance timer."""
           self.timers[name] = time.time()
           print(f"⏱ Timer started: {name}")

       def stop_timer(self, name):
           """Stop a performance timer."""
           if name in self.timers:
               start_time = self.timers[name]
               end_time = time.time()
               duration = end_time - start_time

               print(f"⏱ Timer stopped: {name} ({duration".4f"}s)")

               # Store profile data
               if name not in self.profiles:
                   self.profiles[name] = []

               self.profiles[name].append({
                   'duration': duration,
                   'start_time': start_time,
                   'end_time': end_time
               })

               del self.timers[name]
               return duration

           return None

       def profile_function(self, func):
           """Profile a function's execution."""
           def wrapper(*args, **kwargs):
               func_name = func.__name__
               self.start_timer(func_name)

               try:
                   result = func(*args, **kwargs)
                   self.stop_timer(func_name)
                   return result
               except Exception as e:
                   self.stop_timer(func_name)
                   raise

           return wrapper

       def get_profile_summary(self):
           """Get performance profile summary."""
           summary = {}

           for name, timings in self.profiles.items():
               if timings:
                   durations = [t['duration'] for t in timings]
                   summary[name] = {
                       'count': len(durations),
                       'total_time': sum(durations),
                       'avg_time': sum(durations) / len(durations),
                       'min_time': min(durations),
                       'max_time': max(durations)
                   }

           return summary

       def print_profile_report(self):
           """Print a formatted profile report."""
           summary = self.get_profile_summary()

           print("\n=== Performance Profile Report ===")
           print(f"Total profiled functions: {len(summary)}")

           for func_name, stats in summary.items():
               print(f"\n{func_name}:")
               print(f"  Calls: {stats['count']}")
               print(f"  Total time: {stats['total_time']".4f"}s")
               print(f"  Average time: {stats['avg_time']".4f"}s")
               print(f"  Min time: {stats['min_time']".4f"}s")
               print(f"  Max time: {stats['max_time']".4f"}s")

   return PerformanceProfiler()
```

#### 2. Automated Debugging Scripts

**Component Health Checker:**
```python
#!/usr/bin/env python3
"""
Component Health Checker for Privatus-chat
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime

class ComponentHealthChecker:
   """Check the health of all major components."""

   def __init__(self):
       self.results = {}
       self.start_time = time.time()

   def check_all_components(self):
       """Check all major components."""
       print("=== Component Health Check ===")
       print(f"Started at: {datetime.utcnow().isoformat()}")

       components = {
           'crypto': self.check_crypto_component,
           'network': self.check_network_component,
           'storage': self.check_storage_component,
           'gui': self.check_gui_component,
           'security': self.check_security_component,
           'performance': self.check_performance_component
       }

       for component_name, check_function in components.items():
           print(f"\n--- Checking {component_name.upper()} ---")
           try:
               result = check_function()
               self.results[component_name] = result
               print(f"✓ {component_name}: {'PASS' if result['status'] == 'healthy' else 'FAIL'}")
           except Exception as e:
               print(f"✗ {component_name}: ERROR - {e}")
               self.results[component_name] = {
                   'status': 'error',
                   'error': str(e),
                   'check_time': time.time()
               }

       self.print_summary()

   def check_crypto_component(self):
       """Check cryptographic component health."""
       try:
           from src.crypto.key_management import KeyManager
           from pathlib import Path

           # Test key generation
           test_path = Path("/tmp/health_check_keys")
           key_manager = KeyManager(test_path, "health_check_password")

           # Generate test keys
           identity_key = key_manager.generate_identity_key()
           signed_prekey = key_manager.generate_signed_prekey()

           # Test encryption/decryption
           test_data = b"health_check_data"
           encrypted = key_manager.encrypt_key_data(test_data)
           decrypted = key_manager.decrypt_key_data(encrypted)

           if decrypted == test_data:
               return {
                   'status': 'healthy',
                   'key_generation': 'ok',
                   'encryption': 'ok',
                   'check_time': time.time()
               }
           else:
               return {
                   'status': 'unhealthy',
                   'issue': 'encryption_decryption_mismatch',
                   'check_time': time.time()
               }

       except Exception as e:
           return {
               'status': 'error',
               'error': str(e),
               'check_time': time.time()
           }

   def check_network_component(self):
       """Check network component health."""
       try:
           from src.network.message_protocol import MessageSerializer

           # Test message serialization
           serializer = MessageSerializer()

           test_message = {
               'type': 'test',
               'content': 'health_check',
               'timestamp': time.time()
           }

           # Test serialization/deserialization
           serialized = serializer.serialize_message(test_message)
           deserialized = serializer.deserialize_message(serialized)

           if deserialized.get('content') == 'health_check':
               return {
                   'status': 'healthy',
                   'serialization': 'ok',
                   'check_time': time.time()
               }
           else:
               return {
                   'status': 'unhealthy',
                   'issue': 'serialization_error',
                   'check_time': time.time()
               }

       except Exception as e:
           return {
               'status': 'error',
               'error': str(e),
               'check_time': time.time()
           }

   def check_storage_component(self):
       """Check storage component health."""
       try:
           from src.storage.database_fixed import StorageManager
           from pathlib import Path

           # Test database operations
           test_path = Path("/tmp/health_check_db")
           storage = StorageManager(test_path, "health_check_password")

           # Test basic operations
           test_contact = {
               'contact_id': 'health_check_user',
               'display_name': 'Health Check User'
           }

           # Test CRUD operations
           storage.add_contact(test_contact)
           retrieved = storage.get_contact('health_check_user')
           storage.delete_contact('health_check_user')

           if retrieved and retrieved.get('display_name') == 'Health Check User':
               return {
                   'status': 'healthy',
                   'crud_operations': 'ok',
                   'check_time': time.time()
               }
           else:
               return {
                   'status': 'unhealthy',
                   'issue': 'storage_operation_error',
                   'check_time': time.time()
               }

       except Exception as e:
           return {
               'status': 'error',
               'error': str(e),
               'check_time': time.time()
           }

   def check_gui_component(self):
       """Check GUI component health."""
       try:
           # Test GUI imports (without actually creating GUI)
           from src.gui.components import *
           from src.gui.main_window import *

           return {
               'status': 'healthy',
               'imports': 'ok',
               'check_time': time.time()
           }

       except Exception as e:
           return {
               'status': 'error',
               'error': str(e),
               'check_time': time.time()
           }

   def check_security_component(self):
       """Check security component health."""
       try:
           from src.security.security_monitor import SecurityMonitor

           # Test security monitoring
           monitor = SecurityMonitor()

           return {
               'status': 'healthy',
               'monitoring': 'ok',
               'check_time': time.time()
           }

       except Exception as e:
           return {
               'status': 'error',
               'error': str(e),
               'check_time': time.time()
           }

   def check_performance_component(self):
       """Check performance component health."""
       try:
           from src.performance.performance_monitor import PerformanceMonitor

           # Test performance monitoring
           monitor = PerformanceMonitor()

           return {
               'status': 'healthy',
               'monitoring': 'ok',
               'check_time': time.time()
           }

       except Exception as e:
           return {
               'status': 'error',
               'error': str(e),
               'check_time': time.time()
           }

   def print_summary(self):
       """Print health check summary."""
       end_time = time.time()
       duration = end_time - self.start_time

       print(f"\n=== Health Check Summary ===")
       print(f"Duration: {duration".2f"}s")
       print(f"Components checked: {len(self.results)}")

       healthy_count = sum(1 for r in self.results.values() if r['status'] == 'healthy')
       unhealthy_count = sum(1 for r in self.results.values() if r['status'] == 'unhealthy')
       error_count = sum(1 for r in self.results.values() if r['status'] == 'error')

       print(f"Healthy: {healthy_count}")
       print(f"Unhealthy: {unhealthy_count}")
       print(f"Errors: {error_count}")

       # Show issues
       if unhealthy_count > 0 or error_count > 0:
           print("\nIssues found:")
           for component, result in self.results.items():
               if result['status'] != 'healthy':
                   print(f"  {component}: {result.get('error', result.get('issue', 'Unknown issue'))}")

       # Overall status
       if error_count == 0 and unhealthy_count == 0:
           print("\n✓ All components healthy")
       elif error_count > 0:
           print(f"\n✗ {error_count} component(s) have errors")
       else:
           print(f"\n⚠ {unhealthy_count} component(s) unhealthy")

def main():
   checker = ComponentHealthChecker()
   checker.check_all_components()

if __name__ == "__main__":
   main()
```

### Debugging Best Practices and Patterns

#### 1. Error Pattern Recognition

**Common Error Patterns and Solutions:**
```python
def identify_common_error_patterns(error_logs):
   """Identify and classify common error patterns."""

   error_patterns = {
       'connection_issues': {
           'patterns': ['Connection refused', 'Connection timeout', 'Connection reset'],
           'likely_causes': ['Network configuration', 'Firewall rules', 'Service unavailable'],
           'debugging_steps': [
               'Check network configuration',
               'Verify firewall settings',
               'Test service availability',
               'Check connection pool settings'
           ]
       },
       'authentication_failures': {
           'patterns': ['Authentication failed', 'Invalid credentials', 'Token expired'],
           'likely_causes': ['Wrong credentials', 'Token management', 'Session timeout'],
           'debugging_steps': [
               'Verify credential format',
               'Check token expiration',
               'Review authentication flow',
               'Test session management'
           ]
       },
       'resource_exhaustion': {
           'patterns': ['Out of memory', 'Connection pool exhausted', 'Thread limit reached'],
           'likely_causes': ['Memory leak', 'Resource not released', 'High load'],
           'debugging_steps': [
               'Check for memory leaks',
               'Verify resource cleanup',
               'Monitor resource usage',
               'Review resource limits'
           ]
       },
       'data_corruption': {
           'patterns': ['Data integrity error', 'Corrupted data', 'Invalid data format'],
           'likely_causes': ['Storage corruption', 'Network transmission error', 'Encoding issue'],
           'debugging_steps': [
               'Check data integrity',
               'Verify storage system',
               'Test data transmission',
               'Review encoding/decoding'
           ]
       }
   }

   identified_patterns = []

   for pattern_category, pattern_info in error_patterns.items():
       for error_entry in error_logs:
           message = error_entry.get('message', '')

           if any(error_pattern in message for error_pattern in pattern_info['patterns']):
               identified_patterns.append({
                   'category': pattern_category,
                   'error': error_entry,
                   'likely_causes': pattern_info['likely_causes'],
                   'debugging_steps': pattern_info['debugging_steps']
               })

   return identified_patterns
```

#### 2. Debugging Workflow Templates

**Standard Debugging Workflow:**
```python
def standard_debugging_workflow(problem_report):
   """Execute a standard debugging workflow."""

   workflow_steps = [
       {
           'phase': 'problem_analysis',
           'steps': [
               'Define the problem clearly',
               'Gather all available information',
               'Identify affected components',
               'Determine problem scope'
           ]
       },
       {
           'phase': 'information_gathering',
           'steps': [
               'Collect relevant log entries',
               'Check system configuration',
               'Review recent changes',
               'Document reproduction steps'
           ]
       },
       {
           'phase': 'hypothesis_development',
           'steps': [
               'Develop possible explanations',
               'Prioritize hypotheses by likelihood',
               'Design tests for each hypothesis',
               'Predict expected outcomes'
           ]
       },
       {
           'phase': 'systematic_testing',
           'steps': [
               'Test hypotheses in order',
               'Document test results',
               'Refine hypotheses based on results',
               'Isolate the root cause'
           ]
       },
       {
           'phase': 'solution_development',
           'steps': [
               'Develop fix for root cause',
               'Test fix thoroughly',
               'Verify no regressions',
               'Document the solution'
           ]
       }
   ]

   # Execute workflow
   current_phase = 0
   results = {}

   while current_phase < len(workflow_steps):
       phase = workflow_steps[current_phase]
       print(f"\n--- {phase['phase'].replace('_', ' ').title()} Phase ---")

       for step in phase['steps']:
           print(f"□ {step}")
           # In real implementation, this would execute the step

       # Simulate phase completion
       results[phase['phase']] = {
           'completed': True,
           'timestamp': time.time()
       }

       current_phase += 1

   return results
```

#### 3. Debugging Documentation

**Structured Debugging Notes:**
```python
def create_debugging_documentation():
   """Create structured documentation for debugging sessions."""

   debug_session = {
       'metadata': {
           'session_id': f"debug_{int(time.time())}",
           'start_time': datetime.utcnow().isoformat(),
           'problem_description': "",
           'environment': {},
           'participants': []
       },
       'problem_analysis': {
           'description': "",
           'symptoms': [],
           'affected_components': [],
           'scope_assessment': "",
           'priority': 'low|medium|high|critical'
       },
       'investigation': {
           'hypotheses': [],
           'tests_performed': [],
           'findings': [],
           'evidence': []
       },
       'solution': {
           'root_cause': "",
           'fix_implemented': "",
           'verification': [],
           'preventive_measures': []
       },
       'lessons_learned': {
           'what_worked': [],
           'what_did_not_work': [],
           'improvements': [],
           'follow_up_actions': []
       }
   }

   return debug_session
```

## Log Analysis Tools and Best Practices

### Essential Log Analysis Tools

#### 1. Command-Line Log Analysis Tools

**Basic Log Processing Commands:**
```bash
# Count log entries by level
cut -d',' -f2 privatus-chat.log | sort | uniq -c

# Filter logs by time range (last 2 hours)
grep "$(date -d '2 hours ago' '+%Y-%m-%d %H')" privatus-chat.log

# Find errors in the last hour
grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" privatus-chat_errors.log

# Count unique error messages
cut -d',' -f3 privatus-chat_errors.log | sort | uniq -c | sort -nr

# Monitor logs in real-time
tail -f privatus-chat.log | grep -E "(ERROR|CRITICAL)"

# Extract specific fields from JSON logs
cat privatus-chat_buffered.jsonl | jq '.level' | sort | uniq -c

# Find logs containing specific text
grep -r "connection timeout" ~/.privatus-chat/logs/

# Get log statistics
wc -l ~/.privatus-chat/logs/privatus-chat*.log
```

**Advanced Log Processing Pipeline:**
```bash
#!/bin/bash
# Comprehensive log analysis pipeline

LOG_DIR="$HOME/.privatus-chat/logs"
HOURS_AGO=${1:-24}

echo "=== Log Analysis Pipeline ==="
echo "Time window: $HOURS_AGO hours"
echo "Log directory: $LOG_DIR"
echo "============================"

# 1. Basic statistics
echo -e "\n1. Basic Log Statistics:"
for log_file in "$LOG_DIR"/privatus-chat*.log; do
   if [ -f "$log_file" ]; then
       echo "File: $(basename "$log_file")"
       echo "  Lines: $(wc -l < "$log_file")"
       echo "  Size: $(du -h "$log_file" | cut -f1)"
       echo "  Errors: $(grep -c '"level":"ERROR"' "$log_file")"
       echo "  Critical: $(grep -c '"level":"CRITICAL"' "$log_file")"
   fi
done

# 2. Error analysis
echo -e "\n2. Error Analysis:"
for log_file in "$LOG_DIR"/privatus-chat*errors*.log; do
   if [ -f "$log_file" ]; then
       echo "Error log: $(basename "$log_file")"
       echo "  Top error messages:"
       cat "$log_file" | grep '"message"' | cut -d'"' -f4 | sort | uniq -c | sort -nr | head -10
   fi
done

# 3. Security events
echo -e "\n3. Security Events (last $HOURS_AGO hours):"
find "$LOG_DIR" -name "*security*.log" -exec grep -l "$(date -d "$HOURS_AGO hours ago" '+%Y-%m-%d')" {} \; | head -5 | xargs -I {} sh -c '
   echo "Security log: $(basename {})"
   grep "Security event:" {} | tail -5
'

# 4. Performance metrics
echo -e "\n4. Performance Metrics:"
find "$LOG_DIR" -name "*.jsonl" -exec grep -l "performance_metric" {} \; | head -3 | xargs -I {} sh -c '
   echo "Performance data in: $(basename {})"
   cat {} | grep "performance_metric" | jq -r ".extra.metric_name + \": \" + (.extra.value|tostring)" | sort | uniq -c | tail -5
'
```

#### 2. Python-Based Log Analysis Tools

**Log Parser and Analyzer:**
```python
#!/usr/bin/env python3
"""
Advanced Log Parser and Analyzer
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re

class AdvancedLogAnalyzer:
   """Advanced log analysis with multiple analysis modes."""

   def __init__(self, log_directory):
       self.log_dir = Path(log_directory)
       self.analysis_cache = {}

   def analyze_error_patterns(self, hours_back=24):
       """Analyze error patterns and frequencies."""
       print("=== Error Pattern Analysis ===")

       cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
       error_patterns = Counter()
       error_timeline = []

       # Analyze all error logs
       error_logs = [
           self.log_dir / 'privatus-chat_errors.log',
           self.log_dir / 'privatus-chat.log'
       ]

       for log_file in error_logs:
           if not log_file.exists():
               continue

           try:
               with open(log_file, 'r') as f:
                   for line in f:
                       if line.strip():
                           try:
                               entry = json.loads(line)

                               # Parse timestamp
                               timestamp_str = entry.get('timestamp')
                               if timestamp_str:
                                   try:
                                       entry_time = datetime.fromisoformat(
                                           timestamp_str.replace('Z', '+00:00')
                                       )

                                       if entry_time >= cutoff_time:
                                           if entry.get('level') in ['ERROR', 'CRITICAL']:
                                               message = entry.get('message', '')
                                               error_patterns[message] += 1

                                               error_timeline.append({
                                                   'time': entry_time,
                                                   'level': entry.get('level'),
                                                   'message': message
                                               })

                                   except ValueError:
                                       continue

                           except json.JSONDecodeError:
                               continue

           except Exception as e:
               print(f"Error reading {log_file}: {e}")

       # Print results
       print(f"Analyzed {len(error_timeline)} error entries")
       print("\nTop error patterns:"
       for message, count in error_patterns.most_common(10):
           print(f"  {count"3d"}x: {message}")

       # Analyze temporal distribution
       if error_timeline:
           print("
Error frequency by hour:")
           hourly_errors = defaultdict(int)

           for error in error_timeline:
               hour = error['time'].strftime('%Y-%m-%d %H:00')
               hourly_errors[hour] += 1

           for hour, count in sorted(hourly_errors.items()):
               print(f"  {hour}: {count} errors")

       return error_patterns, error_timeline

   def analyze_performance_trends(self, hours_back=24):
       """Analyze performance trends from logs."""
       print("\n=== Performance Trend Analysis ===")

       cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
       performance_metrics = defaultdict(list)

       # Look for performance data in buffered logs
       buffered_log = self.log_dir / 'privatus-chat_buffered.jsonl'

       if not buffered_log.exists():
           print("No buffered log file found")
           return None

       try:
           with open(buffered_log, 'r') as f:
               for line in f:
                   if line.strip():
                       try:
                           entry = json.loads(line)

                           # Parse timestamp
                           timestamp_str = entry.get('timestamp')
                           if timestamp_str:
                               try:
                                   entry_time = datetime.fromisoformat(
                                       timestamp_str.replace('Z', '+00:00')
                                   )

                                   if entry_time >= cutoff_time:
                                       # Extract performance metrics
                                       extra = entry.get('extra', {})
                                       if extra.get('performance_metric'):
                                           metric_name = extra.get('metric_name')
                                           value = extra.get('value')

                                           if metric_name and value is not None:
                                               performance_metrics[metric_name].append({
                                                   'time': entry_time,
                                                   'value': float(value)
                                               })

                               except ValueError:
                                   continue

                       except json.JSONDecodeError:
                           continue

       except Exception as e:
           print(f"Error reading buffered log: {e}")
           return None

       # Analyze trends
       for metric_name, data_points in performance_metrics.items():
           if len(data_points) >= 2:
               values = [point['value'] for point in data_points]

               print(f"\n{metric_name}:")
               print(f"  Samples: {len(values)}")
               print(f"  Average: {sum(values)/len(values)".2f"}")
               print(f"  Trend: {'↗️ Increasing' if values[-1] > values[0] else '↘️ Decreasing' if values[-1] < values[0] else '➡️ Stable'}")

               # Detect anomalies
               if len(values) >= 5:
                   recent_avg = sum(values[-3:]) / 3
                   overall_avg = sum(values) / len(values)

                   if abs(recent_avg - overall_avg) > overall_avg * 0.3:  # 30% change
                       print(f"  ⚠️ Significant change detected!")

       return performance_metrics

   def generate_log_report(self, hours_back=24):
       """Generate a comprehensive log analysis report."""
       print("
=== Comprehensive Log Analysis Report ===")
       print(f"Generated: {datetime.utcnow().isoformat()}")
       print(f"Analysis window: {hours_back} hours")
       print("=" * 60)

       # Run all analyses
       error_patterns, error_timeline = self.analyze_error_patterns(hours_back)
       performance_metrics = self.analyze_performance_trends(hours_back)

       # Generate summary
       total_errors = sum(error_patterns.values()) if error_patterns else 0

       print("
📊 SUMMARY:"        print(f"  Total errors analyzed: {total_errors}")
       print(f"  Unique error patterns: {len(error_patterns)}")
       print(f"  Performance metrics: {len(performance_metrics)}")

       if error_patterns:
           most_common_error = error_patterns.most_common(1)[0]
           print(f"  Most frequent error: {most_common_error[0]} ({most_common_error[1]} times)")

       # Recommendations
       print("
💡 RECOMMENDATIONS:"        if total_errors > 100:
           print("  ⚠️  High error volume - investigate root causes")
       elif total_errors == 0:
           print("  ✅ No errors found - system appears healthy")
       else:
           print("  ✅ Error volume within normal range")

       if performance_metrics:
           for metric, data in performance_metrics.items():
               if len(data) >= 5:
                   values = [point['value'] for point in data]
                   if values[-1] > max(values[:-1]) * 1.2:
                       print(f"  ⚠️  Performance degradation in {metric}")

       return {
           'timestamp': datetime.utcnow().isoformat(),
           'analysis_window': hours_back,
           'error_patterns': dict(error_patterns),
           'performance_metrics': performance_metrics,
           'total_errors': total_errors
       }

def main():
   parser = argparse.ArgumentParser(description='Advanced log analysis tool')
   parser.add_argument('--log-dir', default='~/.privatus-chat/logs',
                      help='Log directory path')
   parser.add_argument('--hours', type=int, default=24,
                      help='Hours to analyze')
   parser.add_argument('--mode', choices=['errors', 'performance', 'full'],
                      default='full', help='Analysis mode')

   args = parser.parse_args()

   # Expand user path
   log_dir = Path(args.log_dir).expanduser()

   if not log_dir.exists():
       print(f"Log directory not found: {log_dir}")
       sys.exit(1)

   analyzer = AdvancedLogAnalyzer(log_dir)

   if args.mode == 'errors':
       analyzer.analyze_error_patterns(args.hours)
   elif args.mode == 'performance':
       analyzer.analyze_performance_trends(args.hours)
   else:
       analyzer.generate_log_report(args.hours)

if __name__ == "__main__":
   main()
```

#### 3. Real-Time Log Monitoring Tools

**Live Log Dashboard:**
```python
#!/usr/bin/env python3
"""
Real-Time Log Monitoring Dashboard
"""

import json
import time
import curses
import argparse
from pathlib import Path
from collections import deque, Counter
from datetime import datetime, timedelta

class LogDashboard:
   """Real-time log monitoring dashboard."""

   def __init__(self, log_file):
       self.log_file = Path(log_file)
       self.error_counts = Counter()
       self.recent_errors = deque(maxlen=20)
       self.last_position = 0
       self.start_time = time.time()

   def run_dashboard(self):
       """Run the real-time dashboard."""
       try:
           curses.wrapper(self._dashboard_loop)
       except KeyboardInterrupt:
           print("\nDashboard stopped")

   def _dashboard_loop(self, stdscr):
       """Main dashboard loop."""
       curses.curs_set(0)  # Hide cursor
       stdscr.nodelay(1)   # Non-blocking input

       while True:
           stdscr.clear()

           # Check for user input
           try:
               key = stdscr.getch()
               if key == ord('q'):
                   break
           except:
               pass

           # Update log data
           self._update_log_data()

           # Draw dashboard
           self._draw_dashboard(stdscr)

           stdscr.refresh()
           time.sleep(2)  # Update every 2 seconds

   def _update_log_data(self):
       """Update log data from file."""
       try:
           current_size = self.log_file.stat().st_size

           if current_size > self.last_position:
               # Read new content
               with open(self.log_file, 'r') as f:
                   f.seek(self.last_position)
                   new_content = f.read()
                   self.last_position = current_size

               # Process new lines
               for line in new_content.split('\n'):
                   if line.strip():
                       self._process_log_line(line)

       except FileNotFoundError:
           pass  # File might not exist yet

   def _process_log_line(self, line):
       """Process a single log line."""
       try:
           entry = json.loads(line)

           level = entry.get('level', 'INFO')
           message = entry.get('message', '')

           if level in ['ERROR', 'CRITICAL']:
               self.error_counts[level] += 1
               self.recent_errors.append({
                   'time': entry.get('timestamp', ''),
                   'level': level,
                   'message': message[:50] + '...' if len(message) > 50 else message
               })

       except json.JSONDecodeError:
           pass

   def _draw_dashboard(self, stdscr):
       """Draw the dashboard interface."""
       height, width = stdscr.getmaxyx()

       # Title
       title = "Privatus-chat Log Monitor"
       stdscr.addstr(0, (width - len(title)) // 2, title, curses.A_BOLD)

       # Runtime
       runtime = int(time.time() - self.start_time)
       runtime_str = f"Runtime: {runtime}s"
       stdscr.addstr(1, width - len(runtime_str) - 1, runtime_str)

       # Error counts
       y_pos = 3
       stdscr.addstr(y_pos, 2, "Error Counts:", curses.A_BOLD)
       y_pos += 1

       for level, count in self.error_counts.most_common():
           stdscr.addstr(y_pos, 4, f"{level}: {count}")
           y_pos += 1

       # Recent errors
       y_pos += 1
       stdscr.addstr(y_pos, 2, "Recent Errors:", curses.A_BOLD)
       y_pos += 1

       for error in list(self.recent_errors)[-8:]:  # Show last 8 errors
           if y_pos >= height - 2:
               break

           time_str = error['time'].split('T')[1][:8] if 'T' in error['time'] else '??:??:??'
           error_line = f"[{time_str}] {error['level']}: {error['message']}"

           if len(error_line) > width - 4:
               error_line = error_line[:width - 7] + "..."

           stdscr.addstr(y_pos, 4, error_line)
           y_pos += 1

       # Instructions
       if y_pos < height - 1:
           stdscr.addstr(height - 1, 2, "Press 'q' to quit")

def main():
   parser = argparse.ArgumentParser(description='Real-time log monitoring dashboard')
   parser.add_argument('--log-file', default='~/.privatus-chat/logs/privatus-chat.log',
                      help='Log file to monitor')

   args = parser.parse_args()

   # Expand user path
   log_file = Path(args.log_file).expanduser()

   dashboard = LogDashboard(log_file)
   dashboard.run_dashboard()

if __name__ == "__main__":
   main()
```

### Log Analysis Best Practices

#### 1. Systematic Log Investigation Workflow

**Step-by-Step Investigation Process:**
```python
def systematic_log_investigation_workflow(problem_statement):
   """Execute a systematic log investigation workflow."""

   investigation_steps = {
       'step_1_preparation': {
           'name': 'Define Investigation Scope',
           'actions': [
               'Clearly define the problem statement',
               'Identify affected time periods',
               'Determine relevant components',
               'Set investigation boundaries'
           ]
       },
       'step_2_data_collection': {
           'name': 'Collect Relevant Data',
           'actions': [
               'Gather logs from all relevant sources',
               'Collect system and configuration data',
               'Document environmental factors',
               'Preserve evidence for analysis'
           ]
       },
       'step_3_initial_analysis': {
           'name': 'Initial Pattern Analysis',
           'actions': [
               'Identify obvious error patterns',
               'Look for temporal correlations',
               'Check for common failure modes',
               'Document initial findings'
           ]
       },
       'step_4_deep_dive': {
           'name': 'Deep Dive Analysis',
           'actions': [
               'Correlate events across log files',
               'Analyze performance metrics',
               'Check for security implications',
               'Identify root cause candidates'
           ]
       },
       'step_5_validation': {
           'name': 'Validate Findings',
           'actions': [
               'Test hypotheses with additional data',
               'Verify findings with domain experts',
               'Check for alternative explanations',
               'Document evidence strength'
           ]
       },
       'step_6_reporting': {
           'name': 'Document and Report',
           'actions': [
               'Summarize findings clearly',
               'Provide actionable recommendations',
               'Document investigation methodology',
               'Suggest preventive measures'
           ]
       }
   }

   # Execute workflow
   current_step = 1
   results = {}

   for step_key, step_info in investigation_steps.items():
       print(f"\n--- Step {current_step}: {step_info['name']} ---")

       for action in step_info['actions']:
           print(f"□ {action}")
           # In real implementation, execute the action

       results[step_key] = {
           'completed': True,
           'timestamp': time.time(),
           'findings': f"Completed {step_info['name']}"
       }

       current_step += 1

   return results
```

#### 2. Log Search Optimization

**Efficient Search Strategies:**
```python
def optimize_log_searches():
   """Optimize log search operations for better performance."""

   search_strategies = {
       'time_based_filtering': {
           'description': 'Filter by time first to reduce search space',
           'implementation': '''
           # Always filter by time first
           cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
           time_filtered_logs = [log for log in all_logs if log.time >= cutoff_time]
           ''',
           'benefit': 'Reduces search space by 80-90%'
       },
       'level_based_filtering': {
           'description': 'Filter by log level before content search',
           'implementation': '''
           # Filter by level first
           error_logs = [log for log in logs if log.level in ['ERROR', 'CRITICAL']]
           # Then search within filtered results
           ''',
           'benefit': 'Eliminates 70-80% of irrelevant logs'
       },
       'component_based_filtering': {
           'description': 'Filter by component before detailed analysis',
           'implementation': '''
           # Group logs by component
           component_logs = defaultdict(list)
           for log in all_logs:
               component_logs[log.component].append(log)
           ''',
           'benefit': 'Enables focused analysis per component'
       },
       'pattern_based_search': {
           'description': 'Use regex patterns for complex searches',
           'implementation': '''
           # Use compiled regex for efficiency
           pattern = re.compile(r'error|exception|failed', re.IGNORECASE)
           matching_logs = [log for log in logs if pattern.search(log.message)]
           ''',
           'benefit': 'Handles complex search requirements efficiently'
       }
   }

   return search_strategies
```

#### 3. Log Analysis Performance Optimization

**Performance Optimization Techniques:**
```python
def optimize_log_analysis_performance():
   """Optimize log analysis for large log files."""

   optimization_techniques = {
       'chunked_processing': {
           'description': 'Process logs in chunks to manage memory',
           'implementation': '''
           def process_logs_in_chunks(file_path, chunk_size=10000):
               with open(file_path, 'r') as f:
                   chunk = []
                   for line_num, line in enumerate(f, 1):
                       chunk.append(line)
                       if line_num % chunk_size == 0:
                           process_chunk(chunk)
                           chunk = []
                   if chunk:
                       process_chunk(chunk)
           ''',
           'benefit': 'Constant memory usage regardless of file size'
       },
       'indexed_search': {
           'description': 'Create search indexes for faster queries',
           'implementation': '''
           def create_log_index(log_file):
               index = {
                   'timestamps': [],
                   'levels': defaultdict(list),
                   'messages': defaultdict(list)
               }

               with open(log_file, 'r') as f:
                   for line_num, line in enumerate(f, 1):
                       entry = json.loads(line)
                       index['timestamps'].append((line_num, entry.get('timestamp')))
                       index['levels'][entry.get('level')].append(line_num)

               return index
           ''',
           'benefit': 'Sub-second searches in million-line log files'
       },
       'parallel_processing': {
           'description': 'Process multiple log files in parallel',
           'implementation': '''
           def analyze_logs_parallel(log_files):
               with concurrent.futures.ThreadPoolExecutor() as executor:
                   results = list(executor.map(analyze_single_log, log_files))
               return combine_results(results)
           ''',
           'benefit': 'Linear speedup with multiple CPU cores'
       },
       'incremental_analysis': {
           'description': 'Analyze only new log entries since last run',
           'implementation': '''
           def incremental_log_analysis(last_position):
               with open(log_file, 'r') as f:
                   f.seek(last_position)
                   new_entries = []
                   for line in f:
                       new_entries.append(json.loads(line))
                   return analyze_new_entries(new_entries)
           ''',
           'benefit': 'Fast analysis of large log files over time'
       }
   }

   return optimization_techniques
```

### Log Analysis Tools Integration

#### 1. External Tools Integration

**Grafana Dashboard Setup:**
```python
def setup_grafana_dashboard():
   """Setup Grafana dashboard for log analysis."""

   grafana_config = {
       'dashboard': {
           'title': 'Privatus-chat Log Analysis',
           'timezone': 'UTC',
           'panels': [
               {
                   'title': 'Error Rate Trend',
                   'type': 'graph',
                   'targets': [
                       {
                           'expr': 'rate(privatus_chat_log_entries_total{level="ERROR"}[5m])',
                           'legendFormat': 'Error Rate'
                       }
                   ],
                   'yAxes': [
                       {'label': 'Errors/min', 'min': 0}
                   ]
               },
               {
                   'title': 'Log Level Distribution',
                   'type': 'piechart',
                   'targets': [
                       {
                           'expr': 'privatus_chat_log_entries_by_level',
                           'legendFormat': '{{ level }}'
                       }
                   ]
               },
               {
                   'title': 'Top Error Messages',
                   'type': 'table',
                   'targets': [
                       {
                           'expr': 'topk(10, privatus_chat_error_messages_total)',
                           'legendFormat': '{{ message }}'
                       }
                   ]
               },
               {
                   'title': 'Performance Metrics',
                   'type': 'graph',
                   'targets': [
                       {
                           'expr': 'privatus_chat_performance_metrics',
                           'legendFormat': '{{ metric_name }}'
                       }
                   ]
               }
           ],
           'time': {
               'from': 'now-24h',
               'to': 'now'
           },
           'refresh': '30s'
       }
   }

   return grafana_config
```

**Prometheus Metrics Export:**
```python
def setup_prometheus_metrics():
   """Setup Prometheus metrics for log analysis."""

   prometheus_config = '''
   # Prometheus configuration for log metrics

   global:
     scrape_interval: 30s

   scrape_configs:
     - job_name: 'privatus-chat-logs'
       static_configs:
         - targets: ['localhost:9090']
       metrics_path: '/metrics'
       scrape_interval: 15s

   # Alert rules for log analysis
   groups:
     - name: log_alerts
       rules:
         - alert: HighErrorRate
           expr: rate(privatus_chat_errors_total[5m]) > 10
           for: 2m
           labels:
             severity: warning
           annotations:
             summary: "High error rate detected"
             description: "Error rate is {{ $value }} errors/min"

         - alert: CriticalErrors
           expr: increase(privatus_chat_critical_total[10m]) > 5
           for: 0m
           labels:
             severity: critical
           annotations:
             summary: "Critical errors detected"
             description: "{{ $value }} critical errors in last 10 minutes"
   '''

   return prometheus_config
```

#### 2. Custom Log Analysis Scripts

**Automated Daily Log Report:**
```python
#!/usr/bin/env python3
"""
Automated Daily Log Analysis Report
"""

import json
import smtplib
from email.mime.text import MimeText
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter

class DailyLogReporter:
   """Generate automated daily log reports."""

   def __init__(self, log_directory, report_config=None):
       self.log_dir = Path(log_directory)
       self.report_config = report_config or {
           'email_recipients': ['admin@privatus-chat.com'],
           'smtp_server': 'localhost',
           'report_hours': 24
       }

   def generate_daily_report(self):
       """Generate and send daily log report."""
       print("Generating daily log report...")

       # Collect data for the last 24 hours
       report_data = self.collect_report_data()

       # Generate report content
       report_content = self.format_report(report_data)

       # Send report via email
       if self.report_config.get('email_recipients'):
           self.send_email_report(report_content)

       # Save report to file
       self.save_report_file(report_content)

       return report_content

   def collect_report_data(self):
       """Collect all data for the report."""
       cutoff_time = datetime.utcnow() - timedelta(hours=self.report_config['report_hours'])

       report_data = {
           'timestamp': datetime.utcnow().isoformat(),
           'period_hours': self.report_config['report_hours'],
           'log_files': {},
           'error_summary': {},
           'performance_summary': {},
           'security_summary': {},
           'recommendations': []
       }

       # Analyze each log file
       log_files = {
           'main': self.log_dir / 'privatus-chat.log',
           'errors': self.log_dir / 'privatus-chat_errors.log',
           'security': self.log_dir / 'privatus-chat_security.log',
           'buffered': self.log_dir / 'privatus-chat_buffered.jsonl'
       }

       for log_type, log_path in log_files.items():
           if log_path.exists():
               file_stats = self.analyze_log_file(log_path, cutoff_time)
               report_data['log_files'][log_type] = file_stats

       # Generate summaries
       report_data['error_summary'] = self.generate_error_summary(report_data['log_files'])
       report_data['performance_summary'] = self.generate_performance_summary(report_data['log_files'])
       report_data['security_summary'] = self.generate_security_summary(report_data['log_files'])
       report_data['recommendations'] = self.generate_recommendations(report_data)

       return report_data

   def analyze_log_file(self, log_path, cutoff_time):
       """Analyze a single log file."""
       stats = {
           'total_entries': 0,
           'entries_in_period': 0,
           'level_counts': Counter(),
           'error_count': 0,
           'critical_count': 0,
           'recent_errors': []
       }

       try:
           with open(log_path, 'r') as f:
               for line in f:
                   if line.strip():
                       try:
                           entry = json.loads(line)
                           stats['total_entries'] += 1

                           # Parse timestamp
                           timestamp_str = entry.get('timestamp')
                           if timestamp_str:
                               try:
                                   entry_time = datetime.fromisoformat(
                                       timestamp_str.replace('Z', '+00:00')
                                   )

                                   if entry_time >= cutoff_time:
                                       stats['entries_in_period'] += 1
                                       level = entry.get('level', 'UNKNOWN')
                                       stats['level_counts'][level] += 1

                                       if level == 'ERROR':
                                           stats['error_count'] += 1
                                       elif level == 'CRITICAL':
                                           stats['critical_count'] += 1

                                       # Keep recent errors
                                       if level in ['ERROR', 'CRITICAL']:
                                           stats['recent_errors'].append({
                                               'time': timestamp_str,
                                               'level': level,
                                               'message': entry.get('message', '')[:100]
                                           })

                               except ValueError:
                                   continue

                       except json.JSONDecodeError:
                           continue

       except Exception as e:
           stats['error'] = str(e)

       return stats

   def generate_error_summary(self, log_files):
       """Generate error summary."""
       total_errors = 0
       total_critical = 0
       top_errors = Counter()

       for log_type, stats in log_files.items():
           if 'error_count' in stats:
               total_errors += stats['error_count']
               total_critical += stats['critical_count']

               # Collect error messages for frequency analysis
               for error in stats.get('recent_errors', []):
                   top_errors[error['message']] += 1

       return {
           'total_errors': total_errors,
           'total_critical': total_critical,
           'error_rate_per_hour': total_errors / self.report_config['report_hours'],
           'top_error_messages': top_errors.most_common(5)
       }

   def generate_performance_summary(self, log_files):
       """Generate performance summary."""
       performance_metrics = Counter()

       # Look for performance data in buffered logs
       buffered_stats = log_files.get('buffered', {})
       performance_metrics['entries_with_performance_data'] = len([
           e for e in buffered_stats.get('recent_errors', [])
           if 'performance' in str(e).lower()
       ])

       return {
           'performance_data_points': performance_metrics['entries_with_performance_data'],
           'performance_trend': 'stable'  # Would be calculated from actual metrics
       }

   def generate_security_summary(self, log_files):
       """Generate security summary."""
       security_stats = log_files.get('security', {})
       security_events = len(security_stats.get('recent_errors', []))

       return {
           'security_events': security_events,
           'security_rate_per_hour': security_events / self.report_config['report_hours'],
           'risk_level': 'low' if security_events < 5 else 'medium' if security_events < 20 else 'high'
       }

   def generate_recommendations(self, report_data):
       """Generate actionable recommendations."""
       recommendations = []

       error_summary = report_data['error_summary']
       security_summary = report_data['security_summary']

       if error_summary['total_errors'] > 100:
           recommendations.append({
               'priority': 'high',
               'category': 'errors',
               'message': f"High error volume ({error_summary['total_errors']} errors) - investigate root causes",
               'action': 'Review top error messages and implement fixes'
           })

       if error_summary['total_critical'] > 0:
           recommendations.append({
               'priority': 'critical',
               'category': 'critical_errors',
               'message': f"Critical errors detected ({error_summary['total_critical']}) - immediate attention required",
               'action': 'Investigate and resolve critical errors immediately'
           })

       if security_summary['risk_level'] == 'high':
           recommendations.append({
               'priority': 'high',
               'category': 'security',
               'message': 'High security event volume - potential security incident',
               'action': 'Review security logs and assess for breach indicators'
           })

       return recommendations

   def format_report(self, report_data):
       """Format the report as readable text."""
       lines = []
       lines.append("=" * 80)
       lines.append("PRIVATUS-CHAT DAILY LOG ANALYSIS REPORT")
       lines.append("=" * 80)
       lines.append(f"Generated: {report_data['timestamp']}")
       lines.append(f"Analysis Period: {report_data['period_hours']} hours")
       lines.append("")

       # Error Summary
       error_summary = report_data['error_summary']
       lines.append("ERROR SUMMARY:")
       lines.append(f"  Total Errors: {error_summary['total_errors']}")
       lines.append(f"  Critical Errors: {error_summary['total_critical']}")
       lines.append(f"  Error Rate: {error_summary['error_rate_per_hour']".2f"}/hour")

       if error_summary['top_error_messages']:
           lines.append("  Top Error Messages:")
           for message, count in error_summary['top_error_messages']:
               lines.append(f"    {count"3d"}x: {message}")
       lines.append("")

       # Security Summary
       security_summary = report_data['security_summary']
       lines.append("SECURITY SUMMARY:")
       lines.append(f"  Security Events: {security_summary['security_events']}")
       lines.append(f"  Risk Level: {security_summary['risk_level'].upper()}")
       lines.append("")

       # Recommendations
       if report_data['recommendations']:
           lines.append("RECOMMENDATIONS:")
           for rec in report_data['recommendations']:
               priority_icon = {'critical': '🚨', 'high': '⚠️', 'medium': 'ℹ️', 'low': '💡'}[rec['priority']]
               lines.append(f"  {priority_icon} [{rec['priority'].upper()}] {rec['message']}")
               lines.append(f"     Action: {rec['action']}")
           lines.append("")

       lines.append("=" * 80)

       return '\n'.join(lines)

   def send_email_report(self, report_content):
       """Send report via email."""
       try:
           msg = MimeText(report_content)
           msg['Subject'] = f"Privatus-chat Daily Log Report - {datetime.utcnow().strftime('%Y-%m-%d')}"
           msg['From'] = 'log-analyzer@privatus-chat.com'
           msg['To'] = ', '.join(self.report_config['email_recipients'])

           # Send email (requires SMTP server configuration)
           # smtp = smtplib.SMTP(self.report_config['smtp_server'])
           # smtp.send_message(msg)
           # smtp.quit()

           print("Email report sent (SMTP disabled in demo)")

       except Exception as e:
           print(f"Failed to send email report: {e}")

   def save_report_file(self, report_content):
       """Save report to file."""
       try:
           reports_dir = self.log_dir / 'reports'
           reports_dir.mkdir(exist_ok=True)

           report_file = reports_dir / f"daily_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"

           with open(report_file, 'w') as f:
               f.write(report_content)

           print(f"Report saved to: {report_file}")

       except Exception as e:
           print(f"Failed to save report file: {e}")

def main():
   # Configuration
   log_directory = Path.home() / '.privatus-chat' / 'logs'

   if not log_directory.exists():
       print(f"Log directory not found: {log_directory}")
       return

   reporter = DailyLogReporter(log_directory)
   reporter.generate_daily_report()

if __name__ == "__main__":
   main()
```

## Debugging Scenarios and Case Studies

### Real-World Debugging Scenarios

#### Scenario 1: Intermittent Connection Failures

**Problem Description:**
Users report random connection drops during messaging sessions. The issue occurs sporadically and seems to affect multiple users simultaneously.

**Debugging Approach:**

**Step 1: Problem Definition and Initial Assessment**
```python
def investigate_connection_failures():
    """Investigate intermittent connection failures."""

    # Define the problem clearly
    problem = {
        'description': 'Intermittent connection drops during messaging',
        'symptoms': [
            'Random disconnections during active conversations',
            'Multiple users affected simultaneously',
            'No clear pattern in timing or frequency',
            'Reconnection usually succeeds after a few seconds'
        ],
        'affected_components': ['network', 'message_protocol', 'connection_manager'],
        'severity': 'high',
        'business_impact': 'User experience degradation, potential message loss'
    }

    # Initial scope assessment
    scope = assess_problem_scope(problem['symptoms'])
    print(f"Problem scope: {scope}")  # Likely 'systemic' or 'intermittent'

    return problem
```

**Step 2: Log-Based Investigation**
```python
def analyze_connection_logs():
    """Analyze logs for connection failure patterns."""

    # Search for connection-related errors
    connection_errors = search_logs(
        query='connection.*(timeout|reset|refused|drop)',
        log_types=['main', 'errors'],
        hours_back=48,
        level=['ERROR', 'WARNING']
    )

    print(f"Found {len(connection_errors)} connection-related errors")

    # Analyze temporal patterns
    error_timeline = analyze_error_timeline(connection_errors)

    # Look for correlation with network events
    network_events = correlate_with_network_events(connection_errors)

    # Check for patterns around specific times
    peak_hours = identify_peak_error_hours(error_timeline)

    return {
        'total_errors': len(connection_errors),
        'timeline': error_timeline,
        'peak_hours': peak_hours,
        'correlations': network_events
    }
```

**Step 3: Network Component Debugging**
```python
def debug_network_components():
    """Debug network components for connection issues."""

    # Test connection manager
    connection_manager = get_connection_manager()

    # Check active connections
    active_connections = connection_manager.get_active_connections()
    print(f"Active connections: {len(active_connections)}")

    # Check connection pool status
    pool_status = connection_manager.get_connection_pool_status()
    print(f"Connection pool: {pool_status}")

    # Test message protocol
    message_protocol = get_message_protocol()

    # Test serialization/deserialization
    test_message = {'type': 'ping', 'timestamp': time.time()}
    serialized = message_protocol.serialize_message(test_message)
    deserialized = message_protocol.deserialize_message(serialized)

    if deserialized.get('type') == 'ping':
        print("✓ Message protocol working correctly")
    else:
        print("✗ Message protocol error")

    # Check for resource leaks
    resource_usage = check_network_resource_usage()
    print(f"Network resource usage: {resource_usage}")

    return {
        'active_connections': len(active_connections),
        'pool_status': pool_status,
        'protocol_test': 'pass' if deserialized.get('type') == 'ping' else 'fail',
        'resource_usage': resource_usage
    }
```

**Step 4: Root Cause Analysis**
```python
def identify_root_cause():
    """Identify the root cause of connection failures."""

    # Analyze error patterns
    error_analysis = analyze_connection_error_patterns()

    # Check for common causes
    potential_causes = {
        'network_congestion': check_network_congestion(),
        'resource_exhaustion': check_resource_exhaustion(),
        'configuration_issues': check_network_configuration(),
        'timing_issues': check_timing_issues(),
        'external_dependencies': check_external_dependencies()
    }

    # Correlate findings
    if error_analysis['pattern'] == 'burst_pattern':
        if potential_causes['network_congestion']['detected']:
            root_cause = 'network_congestion'
        elif potential_causes['resource_exhaustion']['detected']:
            root_cause = 'resource_exhaustion'
        else:
            root_cause = 'unknown_burst_pattern'
    elif error_analysis['pattern'] == 'gradual_increase':
        root_cause = 'resource_leak'
    else:
        root_cause = 'configuration_issue'

    return {
        'root_cause': root_cause,
        'confidence': calculate_confidence_level(error_analysis, potential_causes),
        'evidence': compile_evidence(error_analysis, potential_causes),
        'recommended_fix': get_recommended_fix(root_cause)
    }
```

**Step 5: Solution Implementation and Verification**
```python
def implement_and_verify_solution(root_cause_analysis):
    """Implement and verify the solution."""

    root_cause = root_cause_analysis['root_cause']

    # Implement fix based on root cause
    if root_cause == 'network_congestion':
        fix = implement_congestion_control()
    elif root_cause == 'resource_exhaustion':
        fix = implement_resource_management()
    elif root_cause == 'resource_leak':
        fix = fix_resource_leak()
    else:
        fix = implement_configuration_fix()

    # Verify the fix
    verification_results = verify_fix_effectiveness(fix)

    # Monitor for regression
    monitoring_setup = setup_post_fix_monitoring()

    return {
        'fix_implemented': fix,
        'verification': verification_results,
        'monitoring': monitoring_setup
    }
```

**Findings and Resolution:**
Based on the investigation, the connection failures were caused by network congestion during peak usage hours. The solution involved implementing better connection pool management and adding retry logic with exponential backoff.

#### Scenario 2: Memory Leak Investigation

**Problem Description:**
Application memory usage gradually increases over time, leading to performance degradation and eventual crashes after extended operation.

**Debugging Approach:**

**Step 1: Memory Usage Analysis**
```python
def investigate_memory_leak():
    """Investigate potential memory leak."""

    # Monitor memory usage over time
    memory_monitor = create_memory_monitor()

    # Take initial snapshot
    initial_snapshot = memory_monitor.take_snapshot("initial")

    # Run application for a period
    run_application_load_test()

    # Take final snapshot
    final_snapshot = memory_monitor.take_snapshot("final")

    # Compare snapshots
    memory_diff = memory_monitor.compare_snapshots("initial", "final")

    print(f"Memory increase: {memory_diff.get('total_increase', 0)} bytes")
    print(f"Top memory consumers: {memory_diff.get('top_allocations', [])}")

    return memory_diff
```

**Step 2: Component Memory Profiling**
```python
def profile_component_memory():
    """Profile memory usage by component."""

    components = ['crypto', 'network', 'storage', 'gui', 'messaging']

    component_memory = {}

    for component in components:
        # Profile each component
        profiler = create_component_profiler(component)

        # Measure memory before and after operations
        memory_before = get_memory_usage()

        # Run component operations
        run_component_operations(component)

        memory_after = get_memory_usage()

        memory_used = memory_after - memory_before

        component_memory[component] = {
            'memory_used': memory_used,
            'memory_per_operation': memory_used / get_operation_count(component),
            'potential_leak': memory_used > expected_memory_usage(component)
        }

        print(f"{component}: {memory_used} bytes, leak: {component_memory[component]['potential_leak']}")

    return component_memory
```

**Step 3: Object Lifecycle Analysis**
```python
def analyze_object_lifecycles():
    """Analyze object creation and cleanup patterns."""

    # Track object creation
    object_tracker = create_object_tracker()

    # Monitor for a period
    with object_tracker.monitor():
        run_typical_application_operations()

    # Analyze object lifecycle
    lifecycle_analysis = object_tracker.analyze_lifecycles()

    # Look for objects that should be garbage collected but aren't
    leaked_objects = lifecycle_analysis.get_leaked_objects()

    print(f"Potential leaked objects: {len(leaked_objects)}")

    for obj in leaked_objects[:10]:  # Show top 10
        print(f"  {obj['type']}: {obj['size']} bytes, created at {obj['created_at']}")

    return lifecycle_analysis
```

**Step 4: Memory Leak Fix Implementation**
```python
def implement_memory_leak_fix(leak_analysis):
    """Implement fix for identified memory leak."""

    if leak_analysis['primary_component'] == 'crypto':
        fix = fix_crypto_memory_leak()
    elif leak_analysis['primary_component'] == 'network':
        fix = fix_network_memory_leak()
    elif leak_analysis['primary_component'] == 'storage':
        fix = fix_storage_memory_leak()
    else:
        fix = fix_general_memory_leak()

    # Implement the fix
    fix_result = apply_memory_fix(fix)

    # Verify fix effectiveness
    verification = verify_memory_fix(fix_result)

    return {
        'fix_applied': fix_result,
        'verification': verification,
        'monitoring': setup_memory_monitoring()
    }
```

**Findings and Resolution:**
The memory leak was traced to the crypto component where encryption buffers were not being properly released. The fix involved ensuring all buffer objects were explicitly freed after use.

#### Scenario 3: Authentication System Failure

**Problem Description:**
Users cannot authenticate to the system. The authentication service appears to be rejecting all login attempts.

**Debugging Approach:**

**Step 1: Authentication Flow Analysis**
```python
def debug_authentication_failure():
    """Debug authentication system failure."""

    # Test authentication service availability
    auth_service_status = check_authentication_service_status()

    if not auth_service_status['available']:
        print("Authentication service is down")
        return investigate_service_outage()

    # Test authentication flow
    auth_flow_test = test_authentication_flow()

    if auth_flow_test['failed']:
        print(f"Authentication flow failed at: {auth_flow_test['failure_point']}")
    else:
        print("Authentication flow working correctly")

    return {
        'service_status': auth_service_status,
        'flow_test': auth_flow_test
    }
```

**Step 2: Security Log Analysis**
```python
def analyze_authentication_security_logs():
    """Analyze security logs for authentication issues."""

    # Get recent security events
    security_events = get_security_events(hours_back=24)

    # Filter for authentication events
    auth_events = [
        event for event in security_events
        if 'auth' in event.get('message', '').lower()
    ]

    print(f"Authentication events in last 24h: {len(auth_events)}")

    # Analyze failure patterns
    auth_failures = [event for event in auth_events if 'fail' in event.get('message', '').lower()]
    auth_successes = [event for event in auth_events if 'success' in event.get('message', '').lower()]

    print(f"Authentication failures: {len(auth_failures)}")
    print(f"Authentication successes: {len(auth_successes)}")

    # Look for attack patterns
    attack_indicators = detect_attack_patterns(auth_events)

    return {
        'total_auth_events': len(auth_events),
        'failures': len(auth_failures),
        'successes': len(auth_successes),
        'attack_indicators': attack_indicators
    }
```

**Step 3: Credential Validation Debugging**
```python
def debug_credential_validation():
    """Debug credential validation process."""

    # Test credential validation with known good credentials
    test_credentials = {
        'username': 'test_user',
        'password': 'test_password'
    }

    validation_result = test_credential_validation(test_credentials)

    if validation_result['valid']:
        print("Credential validation working correctly")
    else:
        print(f"Credential validation failed: {validation_result['reason']}")

    # Check credential storage
    credential_storage_status = check_credential_storage()

    # Test password hashing
    password_hash_test = test_password_hashing()

    return {
        'validation_test': validation_result,
        'storage_status': credential_storage_status,
        'hash_test': password_hash_test
    }
```

**Findings and Resolution:**
The authentication failure was caused by a database connection issue in the credential storage system. The authentication service was trying to validate credentials against an unavailable database.

### Case Study: Performance Degradation Investigation

#### Background
A production Privatus-chat deployment experienced gradual performance degradation over several days, affecting user experience and system responsiveness.

#### Investigation Timeline

**Day 1: Initial Detection**
- Users reported slow response times
- Monitoring showed increased error rates
- Initial assessment indicated systemic performance issue

**Day 2: Log Analysis**
- Analyzed 48 hours of logs using automated tools
- Identified increasing error patterns in network component
- Found correlation with memory usage growth

**Day 3: Component Analysis**
- Isolated issue to connection management
- Found connection pool exhaustion patterns
- Identified resource leak in connection handling

**Day 4: Root Cause Identification**
- Traced leak to improper connection cleanup
- Found missing connection.close() calls in error paths
- Identified similar patterns in other components

**Day 5: Fix Implementation**
- Implemented proper connection cleanup
- Added connection pool monitoring
- Deployed fix with rollback plan

**Day 6: Verification**
- Monitored system for 24 hours post-fix
- Confirmed performance improvement
- Verified no regressions

#### Technical Details

**Root Cause:**
```python
# Problematic code pattern found in connection handling
def handle_message_connection(connection, message):
    try:
        # Process message
        result = process_message(connection, message)

        # Missing connection cleanup in success path
        # connection.close()  # This was missing

        return result

    except Exception as e:
        # Connection cleanup in error path
        connection.close()  # Only cleaned up on error
        raise
```

**Solution Implemented:**
```python
def handle_message_connection_fixed(connection, message):
    try:
        # Process message
        result = process_message(connection, message)
        return result

    finally:
        # Always cleanup connection
        connection.close()
```

**Verification Metrics:**
- Memory usage stabilized
- Connection pool utilization normalized
- Error rates returned to baseline
- Response times improved by 60%

### Case Study: Security Incident Response

#### Background
Security monitoring detected suspicious authentication patterns suggesting a potential brute force attack on the Privatus-chat system.

#### Investigation Timeline

**Hour 1: Initial Alert**
- Security monitoring triggered high-priority alert
- Multiple authentication failures from various IP addresses
- Pattern suggested coordinated attack

**Hour 2: Initial Assessment**
- Analyzed security logs for attack patterns
- Identified 50+ unique IP addresses attempting authentication
- Attack focused on specific user accounts

**Hour 3: Attack Analysis**
- Correlated attack across multiple log sources
- Identified attack vectors and methods
- Assessed potential impact and data exposure

**Hour 4: Containment**
- Implemented IP blocking for attacking addresses
- Enhanced authentication rate limiting
- Notified security team

**Hour 6: Recovery and Analysis**
- Restored normal authentication for legitimate users
- Analyzed attack methods for future prevention
- Updated security monitoring rules

#### Technical Findings

**Attack Pattern Identified:**
```python
def analyze_brute_force_pattern():
    """Analyze brute force attack pattern."""

    # Attack characteristics
    attack_pattern = {
        'time_window': '2 hours',
        'source_ips': 50,
        'target_accounts': 5,
        'attempts_per_ip': '100-500',
        'success_rate': '0%',
        'attack_vector': 'credential_stuffing'
    }

    # Log analysis showed clear pattern
    auth_failures = get_authentication_failures(hours_back=2)

    # Group by source IP
    failures_by_ip = group_failures_by_ip(auth_failures)

    # Identify attack signature
    attack_signature = {
        'high_frequency': any(count > 100 for count in failures_by_ip.values()),
        'multiple_targets': len(set(get_target_accounts(auth_failures))) > 3,
        'coordinated_timing': check_timing_coordination(auth_failures),
        'geographic_distribution': check_geographic_distribution(failures_by_ip.keys())
    }

    return attack_signature
```

**Security Enhancements Implemented:**
```python
def implement_security_enhancements():
    """Implement security enhancements post-incident."""

    enhancements = {
        'rate_limiting': {
            'description': 'Enhanced authentication rate limiting',
            'implementation': '50 attempts per IP per hour',
            'monitoring': 'Alert on rate limit violations'
        },
        'ip_blocking': {
            'description': 'Automatic IP blocking for suspicious patterns',
            'implementation': 'Block IPs with >100 failures in 1 hour',
            'duration': '24 hours'
        },
        'monitoring': {
            'description': 'Enhanced security event monitoring',
            'implementation': 'Real-time analysis of authentication patterns',
            'alerting': 'Immediate alerts for attack indicators'
        },
        'authentication': {
            'description': 'Strengthened authentication requirements',
            'implementation': 'Multi-factor authentication for all accounts',
            'password_policy': 'Enhanced password complexity requirements'
        }
    }

    return enhancements
```

### Debugging Workflow Case Studies

#### Case Study 1: Database Corruption Issue

**Problem:** Database corruption causing data loss and application crashes.

**Workflow Applied:**
1. **Problem Definition**: Identified specific corruption symptoms and affected data types
2. **Log Analysis**: Correlated error patterns across application and system logs
3. **Component Testing**: Isolated database operations and tested integrity
4. **Root Cause**: Found storage driver compatibility issue with specific file system
5. **Solution**: Updated storage driver and implemented data validation

**Key Lessons:**
- Always check for environmental factors (filesystem, storage driver)
- Implement comprehensive data validation before database operations
- Use transaction rollbacks for corruption recovery

#### Case Study 2: Race Condition in Multi-threading

**Problem:** Intermittent crashes and data corruption in multi-threaded messaging system.

**Workflow Applied:**
1. **Problem Definition**: Identified timing-dependent failures
2. **Reproduction**: Created minimal test case that reliably reproduced the issue
3. **Code Analysis**: Used binary search to isolate problematic code sections
4. **Root Cause**: Found unsafe shared resource access between threads
5. **Solution**: Implemented proper thread synchronization

**Key Lessons:**
- Race conditions require systematic reproduction techniques
- Binary search debugging is highly effective for code isolation
- Always verify thread safety in multi-threaded code

#### Case Study 3: External Service Dependency Failure

**Problem:** Application failures caused by external service outages.

**Workflow Applied:**
1. **Problem Definition**: Identified external dependency as likely cause
2. **Service Analysis**: Tested external service availability and response times
3. **Fallback Testing**: Verified fallback mechanism functionality
4. **Root Cause**: Found missing timeout handling for external service calls
5. **Solution**: Implemented proper timeout and retry logic

**Key Lessons:**
- Always check external dependencies first in outage scenarios
- Implement proper timeout and retry mechanisms
- Have fallback mechanisms for critical external services

### Debugging Best Practices from Case Studies

#### 1. Systematic Information Gathering

**Always collect:**
- Complete error messages and stack traces
- System and environment information
- Recent changes and deployments
- User actions leading to the issue
- Time stamps and sequence of events

**Tools for Information Gathering:**
```python
def comprehensive_information_gathering():
    """Gather comprehensive debugging information."""

    info_collectors = {
        'system_info': collect_system_information(),
        'environment': collect_environment_details(),
        'recent_changes': collect_recent_changes(),
        'error_context': collect_error_context(),
        'user_actions': collect_user_action_history(),
        'performance_metrics': collect_performance_metrics(),
        'network_status': collect_network_status(),
        'external_dependencies': collect_external_dependency_status()
    }

    # Correlate information
    correlations = find_information_correlations(info_collectors)

    return {
        'collected_info': info_collectors,
        'correlations': correlations,
        'analysis_ready': True
    }
```

#### 2. Pattern Recognition and Correlation

**Common Patterns to Look For:**
- **Temporal Patterns**: Events occurring at specific times or intervals
- **Cascading Failures**: One failure triggering multiple related failures
- **Resource Patterns**: Failures correlated with resource exhaustion
- **Configuration Patterns**: Issues appearing after configuration changes
- **Load Patterns**: Problems occurring under specific load conditions

**Pattern Analysis Techniques:**
```python
def analyze_debugging_patterns(debugging_data):
    """Analyze patterns in debugging data."""

    patterns = {
        'temporal': analyze_temporal_patterns(debugging_data),
        'causal': analyze_causal_patterns(debugging_data),
        'resource': analyze_resource_patterns(debugging_data),
        'configuration': analyze_configuration_patterns(debugging_data),
        'load': analyze_load_patterns(debugging_data)
    }

    # Identify most likely pattern
    pattern_scores = {
        name: calculate_pattern_strength(data)
        for name, data in patterns.items()
    }

    most_likely_pattern = max(pattern_scores, key=pattern_scores.get)

    return {
        'identified_patterns': patterns,
        'most_likely': most_likely_pattern,
        'confidence': pattern_scores[most_likely_pattern],
        'recommended_actions': get_actions_for_pattern(most_likely_pattern)
    }
```

#### 3. Root Cause Validation

**Validation Techniques:**
- **Hypothesis Testing**: Test each potential root cause systematically
- **Controlled Experiments**: Isolate variables to confirm cause-effect relationships
- **Reproduction Testing**: Verify that the fix resolves the original issue
- **Regression Testing**: Ensure the fix doesn't break existing functionality

**Validation Framework:**
```python
def validate_root_cause(hypothesized_cause, evidence):
    """Validate hypothesized root cause."""

    validation_tests = [
        {
            'test': 'reproduction_test',
            'description': 'Can we reproduce the issue consistently?',
            'result': test_issue_reproduction()
        },
        {
            'test': 'hypothesis_test',
            'description': 'Does the hypothesized cause explain all symptoms?',
            'result': test_hypothesis_explanation(hypothesized_cause, evidence)
        },
        {
            'test': 'fix_effectiveness',
            'description': 'Does the proposed fix resolve the issue?',
            'result': test_proposed_fix(hypothesized_cause)
        },
        {
            'test': 'side_effect_check',
            'description': 'Does the fix introduce any side effects?',
            'result': test_for_side_effects(hypothesized_cause)
        }
    ]

    # Calculate overall validation score
    passed_tests = sum(1 for test in validation_tests if test['result']['passed'])
    validation_score = passed_tests / len(validation_tests)

    return {
        'validation_tests': validation_tests,
        'score': validation_score,
        'confidence': 'high' if validation_score >= 0.8 else 'medium' if validation_score >= 0.6 else 'low',
        'validated': validation_score >= 0.8
    }
```

### Debugging Tools and Scripts from Case Studies

#### 1. Automated Issue Reproducer

**Create Test Cases from Real Issues:**
```python
def create_issue_reproducer(original_issue_data):
    """Create automated reproducer for real issues."""

    reproducer_script = f'''#!/usr/bin/env python3
"""
Automated reproducer for: {original_issue_data['description']}
Generated from case study investigation
"""

import sys
import time
from pathlib import Path

# Add source path
src_path = Path(__file__).parent / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

def reproduce_issue():
    """Reproduce the original issue."""
    try:
        # Setup test environment
        setup_test_environment()

        # Execute steps that led to original issue
        steps = {original_issue_data['reproduction_steps']}

        for step_num, step in enumerate(steps, 1):
            print(f"Step {step_num}: {step['description']}")
            execute_step(step)

            # Check for expected failure
            if step_num == {original_issue_data['failure_step']}:
                print(f"Expected failure at step {step_num}")
                break

        # Verify issue reproduction
        if verify_issue_reproduction():
            print("✓ Issue successfully reproduced")
            return True
        else:
            print("✗ Issue reproduction failed")
            return False

    except Exception as e:
        print(f"Reproduction error: {e}")
        import traceback
        traceback.print_exc()
        return False

def setup_test_environment():
    """Setup environment for issue reproduction."""
    # Configure test environment to match original conditions
    pass

def execute_step(step):
    """Execute a single reproduction step."""
    # Execute the step based on its type
    if step['type'] == 'api_call':
        make_api_call(step['parameters'])
    elif step['type'] == 'user_action':
        simulate_user_action(step['parameters'])
    elif step['type'] == 'system_operation':
        perform_system_operation(step['parameters'])

def verify_issue_reproduction():
    """Verify that the issue was reproduced."""
    # Check for expected symptoms
    expected_symptoms = {original_issue_data['expected_symptoms']}
    actual_symptoms = collect_current_symptoms()

    return all(symptom in actual_symptoms for symptom in expected_symptoms)

if __name__ == "__main__":
    success = reproduce_issue()
    sys.exit(0 if success else 1)
'''

    return reproducer_script
```

#### 2. Debugging Session Recorder

**Document Debugging Sessions:**
```python
def create_debugging_session_recorder():
    """Create a tool to record debugging sessions."""

    class DebuggingSessionRecorder:
        """Record debugging sessions for future reference."""

        def __init__(self):
            self.session_data = {
                'start_time': datetime.utcnow().isoformat(),
                'problem_statement': '',
                'investigation_steps': [],
                'findings': [],
                'conclusions': '',
                'lessons_learned': []
            }

        def start_session(self, problem_statement):
            """Start recording a debugging session."""
            self.session_data['problem_statement'] = problem_statement
            print(f"Debugging session started: {problem_statement}")

        def record_step(self, step_description, findings=None, evidence=None):
            """Record a debugging step."""
            step_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'description': step_description,
                'findings': findings,
                'evidence': evidence
            }

            self.session_data['investigation_steps'].append(step_record)
            print(f"Step recorded: {step_description}")

        def record_finding(self, finding, confidence='medium', impact='medium'):
            """Record a significant finding."""
            finding_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'finding': finding,
                'confidence': confidence,
                'impact': impact
            }

            self.session_data['findings'].append(finding_record)
            print(f"Finding recorded: {finding} (confidence: {confidence})")

        def conclude_session(self, conclusion, lessons_learned=None):
            """Conclude the debugging session."""
            self.session_data['conclusions'] = conclusion

            if lessons_learned:
                self.session_data['lessons_learned'] = lessons_learned

            # Save session
            self.save_session()

            print(f"Session concluded: {conclusion}")

        def save_session(self):
            """Save the debugging session to file."""
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"debugging_session_{timestamp}.json"

            try:
                with open(filename, 'w') as f:
                    json.dump(self.session_data, f, indent=2)

                print(f"Session saved to: {filename}")

            except Exception as e:
                print(f"Failed to save session: {e}")

    return DebuggingSessionRecorder()
```

## Version Control and Collaboration Issues

### Git Repository Problems

**Problem**: Issues with version control and Git operations.

**Solutions**:

1. **Check Git Repository Status**:
   ```bash
   # Check repository status
   git status

   # Check for uncommitted changes
   git diff --name-only

   # Check branch status
   git branch -v

   # Check remote repositories
   git remote -v
   ```

2. **Test Git Operations**:
   ```bash
   # Test basic Git operations
   git log --oneline -5

   # Check for merge conflicts
   git diff --check

   # Verify .gitignore is working
   git status --ignored
   ```

3. **Check Repository Configuration**:
   ```python
   # Verify Git configuration for development
   import subprocess

   def check_git_config():
       try:
           # Check user configuration
           result = subprocess.run(['git', 'config', 'user.name'],
                                 capture_output=True, text=True)
           if result.returncode == 0:
               print(f"✓ Git user: {result.stdout.strip()}")
           else:
               print("✗ Git user not configured")

           # Check email configuration
           result = subprocess.run(['git', 'config', 'user.email'],
                                 capture_output=True, text=True)
           if result.returncode == 0:
               print(f"✓ Git email: {result.stdout.strip()}")
           else:
               print("✗ Git email not configured")

       except Exception as e:
           print(f"✗ Git config check failed: {e}")
   ```

### Code Review and Quality Issues

**Problem**: Code quality tools not working or configured incorrectly.

**Solutions**:

1. **Check Code Quality Tools**:
   ```bash
   # Check if code quality tools are installed
   python -c "import flake8; print('Flake8 OK')" 2>/dev/null || echo "Flake8 missing"
   python -c "import black; print('Black OK')" 2>/dev/null || echo "Black missing"
   python -c "import mypy; print('MyPy OK')" 2>/dev/null || echo "MyPy missing"
   ```

2. **Run Code Quality Checks**:
   ```bash
   # Run code quality checks
   find src -name "*.py" -exec python -m py_compile {} \;

   # Run style checks if available
   python -m flake8 src/ --max-line-length=100 || echo "Flake8 not available"

   # Run type checks if available
   python -m mypy src/ || echo "MyPy not available"
   ```

3. **Check Code Coverage**:
   ```bash
   # Run tests with coverage
   python -m pytest --cov=src --cov-report=html tests/

   # Check coverage report
   ls -la htmlcov/index.html 2>/dev/null || echo "No coverage report generated"
   ```

## Build and Deployment Problems

### Build Script Issues

**Problem**: Build scripts failing or not working correctly.

**Solutions**:

1. **Test Build Process**:
   ```bash
   # Test build script execution
   python deployment/build.py --help

   # Check build dependencies
   python -c "
   import PyInstaller
   import cryptography
   print('Build dependencies OK')
   "
   ```

2. **Debug Build Configuration**:
   ```python
   # Check build configuration
   def check_build_config():
       try:
           # Check if build configuration exists
           build_config = Path('deployment/config')
           if build_config.exists():
               print(f"✓ Build config directory: {build_config}")

               # Check platform configs
               configs = list(build_config.glob('*.json'))
               print(f"✓ Platform configs: {len(configs)}")
           else:
               print("○ Build config directory not found")

       except Exception as e:
           print(f"✗ Build config check failed: {e}")
   ```

3. **Test Build Output**:
   ```bash
   # Check build output directory
   ls -la deployment/
   ls -la dist/ 2>/dev/null || echo "No dist directory"

   # Check for build artifacts
   find . -name "*.spec" -o -name "build.py" | head -5
   ```

### Deployment Configuration Issues

**Problem**: Deployment configuration not working correctly.

**Solutions**:

1. **Check Deployment Scripts**:
   ```bash
   # Test deployment script execution
   python deployment/deploy.py --help

   # Check deployment configuration
   ls -la deployment/config/
   ls -la deployment/config/environments/
   ```

2. **Verify Environment Configuration**:
   ```python
   # Check environment-specific configuration
   def check_deployment_config():
       try:
           # Check development config
           dev_config = Path('config/development.env')
           if dev_config.exists():
               print("✓ Development config exists")
           else:
               print("○ Development config not found")

           # Check production config
           prod_config = Path('config/production.env')
           if prod_config.exists():
               print("✓ Production config exists")
           else:
               print("○ Production config not found")

       except Exception as e:
           print(f"✗ Deployment config check failed: {e}")
   ```

3. **Test Deployment Tools**:
   ```python
   # Test deployment tool functionality
   def test_deployment_tools():
       try:
           # Test Docker deployment if available
           import subprocess

           result = subprocess.run(['docker', '--version'],
                                 capture_output=True, text=True)

           if result.returncode == 0:
               print(f"✓ Docker available: {result.stdout.strip()}")
           else:
               print("○ Docker not available")

           # Test build tools
           result = subprocess.run(['python', 'deployment/build.py', '--dry-run'],
                                 capture_output=True, text=True)

           if result.returncode == 0:
               print("✓ Build tools working")
           else:
               print(f"✗ Build tools issue: {result.stderr}")

       except Exception as e:
           print(f"✗ Deployment tools test failed: {e}")
   ```

## Performance Profiling Issues

### Profiler Not Working

**Problem**: Performance profiling tools not functioning correctly.

**Solutions**:

1. **Test Profiling Tools**:
   ```python
   # Test Python profiling tools
   def test_profiling_tools():
       # Test cProfile
       try:
           import cProfile

           profiler = cProfile.Profile()
           profiler.enable()

           # Run some test code
           sum(range(100000))

           profiler.disable()

           # Analyze results
           import pstats
           stats = pstats.Stats(profiler)
           print("✓ cProfile working")

       except Exception as e:
           print(f"✗ cProfile failed: {e}")

       # Test line profiler if available
       try:
           import line_profiler
           print("✓ Line profiler available")
       except ImportError:
           print("○ Line profiler not available")
   ```

2. **Profile Specific Functions**:
   ```python
   # Profile specific functions during development
   def profile_function(func):
       def wrapper(*args, **kwargs):
           profiler = cProfile.Profile()
           profiler.enable()

           try:
               result = func(*args, **kwargs)
               return result
           finally:
               profiler.disable()

               # Save profile results
               stats = pstats.Stats(profiler)
               stats.sort_stats('cumulative')
               stats.print_stats(10)  # Top 10 functions

       return wrapper

   # Usage example
   @profile_function
   def test_function():
       return sum(range(10000))
   ```

3. **Memory Profiling**:
   ```python
   # Test memory profiling
   def test_memory_profiling():
       try:
           import tracemalloc

           # Start tracing
           tracemalloc.start()

           # Run test code
           test_data = [i for i in range(10000)]

           # Take snapshot
           snapshot = tracemalloc.take_snapshot()

           # Analyze memory usage
           top_stats = snapshot.statistics('lineno')
           print("✓ Memory profiling working")

           for stat in top_stats[:5]:
               print(f"  {stat}")

           tracemalloc.stop()

       except Exception as e:
           print(f"✗ Memory profiling failed: {e}")
   ```

### Performance Data Collection Issues

**Problem**: Cannot collect or analyze performance data.

**Solutions**:

1. **Test Performance Monitor Integration**:
   ```python
   # Test performance monitor in development
   def test_performance_monitor():
       try:
           from src.performance.performance_monitor import PerformanceMonitor

           monitor = PerformanceMonitor(monitoring_interval=0.1)

           # Test metric recording
           monitor.record_timer('test_operation', 0.1)
           monitor.increment_counter('test_counter', 5)

           # Get stats
           stats = monitor.get_comprehensive_stats()
           print(f"✓ Performance monitor: {len(stats)} metrics")

       except Exception as e:
           print(f"✗ Performance monitor test failed: {e}")
   ```

2. **Check Benchmark Tools**:
   ```python
   # Test benchmarking functionality
   def test_benchmark_tools():
       try:
           from src.performance.enhanced_benchmarks import EnhancedBenchmarkSuite

           benchmark_suite = EnhancedBenchmarkSuite()

           # Test crypto benchmarks
           crypto_results = benchmark_suite.run_crypto_benchmarks()
           print(f"✓ Crypto benchmarks: {len(crypto_results)} tests")

           # Test network benchmarks
           network_results = benchmark_suite.run_network_benchmarks()
           print(f"✓ Network benchmarks: {len(network_results)} tests")

       except Exception as e:
           print(f"✗ Benchmark tools failed: {e}")
   ```

3. **Verify Performance Dashboard**:
   ```python
   # Test performance dashboard functionality
   def test_performance_dashboard():
       try:
           from src.performance.monitoring_dashboard import PerformanceDashboard

           dashboard = PerformanceDashboard(port=8081)

           # Test dashboard creation
           print("✓ Performance dashboard created")

           # Check if dashboard can start
           # dashboard.start()  # Don't actually start in test

       except Exception as e:
           print(f"✗ Performance dashboard failed: {e}")
   ```

## Development Tools and IDE Problems

### IDE Integration Issues

**Problem**: Development environment not integrating properly with IDE.

**Solutions**:

1. **Check IDE Configuration**:
   ```python
   # Test IDE-specific functionality
   def check_ide_integration():
       # Check for common IDE files
       ide_files = ['.vscode', '.idea', 'project.pbxproj']

       found_ide = []
       for ide_file in ide_files:
           if Path(ide_file).exists():
               found_ide.append(ide_file)

       if found_ide:
           print(f"✓ IDE files found: {found_ide}")
       else:
           print("○ No IDE configuration files found")

       # Check Python path for IDE
       import sys
       print(f"✓ Python path length: {len(sys.path)}")
   ```

2. **Test Debugging Integration**:
   ```python
   # Test debugging capabilities
   def test_debugging_integration():
       # Test breakpoint functionality
       def test_function():
           x = 1
           y = 2
           z = x + y  # Potential breakpoint location
           return z

       # Test function execution
       result = test_function()
       print(f"✓ Debug test function works: {result}")

       # Test variable inspection
       test_vars = {'a': 1, 'b': 'test', 'c': [1, 2, 3]}
       print(f"✓ Test variables: {test_vars}")
   ```

3. **Check Code Completion**:
   ```python
   # Test code completion and introspection
   def test_code_completion():
       # Test module introspection
       import src.crypto.key_management

       # Get module members
       members = dir(src.crypto.key_management)
       print(f"✓ Module members: {len(members)}")

       # Test class introspection
       from src.crypto.key_management import KeyManager

       methods = [m for m in dir(KeyManager) if not m.startswith('_')]
       print(f"✓ KeyManager methods: {len(methods)}")

       # Test method signatures
       import inspect
       init_signature = inspect.signature(KeyManager.__init__)
       print(f"✓ Method signature: {init_signature}")
   ```

### Hot Reload and Development Server Issues

**Problem**: Development server or hot reload not working.

**Solutions**:

1. **Test Development Server**:
   ```python
   # Test development server functionality
   def test_development_server():
       try:
           # Check if development server script exists
           dev_server = Path('launch_gui.py')
           if dev_server.exists():
               print("✓ Development server script exists")

               # Test server imports
               import launch_gui
               print("✓ Development server imports successfully")
           else:
               print("○ Development server script not found")

       except Exception as e:
           print(f"✗ Development server test failed: {e}")
   ```

2. **Check File Monitoring**:
   ```python
   # Test file change monitoring for hot reload
   def test_file_monitoring():
       try:
           # Test file modification detection
           test_file = Path('test_reload.txt')

           # Create test file
           test_file.write_text('initial')

           # Check modification time
           initial_mtime = test_file.stat().st_mtime

           # Modify file
           import time
           time.sleep(0.1)
           test_file.write_text('modified')

           # Check if modification detected
           new_mtime = test_file.stat().st_mtime

           if new_mtime > initial_mtime:
               print("✓ File modification detection works")
           else:
               print("✗ File modification detection failed")

           # Cleanup
           test_file.unlink()

       except Exception as e:
           print(f"✗ File monitoring test failed: {e}")
   ```

3. **Test Auto-Restart Functionality**:
   ```python
   # Test development auto-restart
   def test_auto_restart():
       try:
           # This would test if the development server
           # can automatically restart on file changes

           # For now, just check if restart mechanism exists
           restart_script = Path('scripts/restart_dev_server.py')
           if restart_script.exists():
               print("✓ Auto-restart script exists")
           else:
               print("○ Auto-restart script not found")

       except Exception as e:
           print(f"✗ Auto-restart test failed: {e}")
   ```

## Diagnostic Tools and Commands

### Development Environment Diagnostics Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Development Environment Diagnostics Tool
"""

import sys
import os
import subprocess
from pathlib import Path

def run_development_diagnostics():
    print("=== Development Environment Diagnostics ===\n")

    # 1. Python environment check
    print("1. Checking Python environment...")
    print(f"   Python version: {sys.version}")
    print(f"   Python executable: {sys.executable}")
    print(f"   Python path length: {len(sys.path)}")

    # 2. Virtual environment check
    print("\n2. Checking virtual environment...")
    venv_path = os.environ.get('VIRTUAL_ENV')
    if venv_path:
        print(f"   ✓ Virtual environment: {venv_path}")
    else:
        print("   ○ No virtual environment detected")

    # 3. Package dependencies check
    print("\n3. Checking package dependencies...")
    required_packages = [
        'PyQt6', 'cryptography', 'pytest', 'pytest_asyncio',
        'coverage', 'flake8', 'black', 'mypy'
    ]

    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"   ✓ {package}")
        except ImportError:
            print(f"   ○ {package} (optional)")

    # 4. Source code structure check
    print("\n4. Checking source code structure...")
    src_path = Path('src')
    if src_path.exists():
        print(f"   ✓ Source directory: {src_path}")

        # Count Python files
        py_files = list(src_path.rglob('*.py'))
        print(f"   ✓ Python files: {len(py_files)}")

        # Check for __init__.py files
        missing_init = []
        for py_file in py_files:
            init_file = py_file.parent / '__init__.py'
            if not init_file.exists():
                missing_init.append(str(py_file))

        if missing_init:
            print(f"   ⚠ Missing __init__.py files: {len(missing_init)}")
        else:
            print("   ✓ All __init__.py files present")

    else:
        print(f"   ✗ Source directory not found: {src_path}")

    # 5. Test structure check
    print("\n5. Checking test structure...")
    test_path = Path('tests')
    if test_path.exists():
        print(f"   ✓ Test directory: {test_path}")

        # Count test files
        test_files = list(test_path.glob('test_*.py'))
        print(f"   ✓ Test files: {len(test_files)}")

        # Check test naming
        properly_named = [f for f in test_files if f.name.startswith('test_')]
        print(f"   ✓ Properly named tests: {len(properly_named)}")

    else:
        print(f"   ✗ Test directory not found: {test_path}")

    # 6. Git repository check
    print("\n6. Checking Git repository...")
    try:
        result = subprocess.run(['git', 'status', '--porcelain'],
                              capture_output=True, text=True)

        if result.returncode == 0:
            uncommitted = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            print(f"   ✓ Git repository active")
            print(f"   ✓ Uncommitted changes: {uncommitted}")

            # Check current branch
            branch_result = subprocess.run(['git', 'branch', '--show-current'],
                                         capture_output=True, text=True)
            if branch_result.returncode == 0:
                print(f"   ✓ Current branch: {branch_result.stdout.strip()}")

        else:
            print("   ○ Not a Git repository")

    except Exception as e:
        print(f"   ✗ Git check failed: {e}")

    # 7. Build system check
    print("\n7. Checking build system...")
    build_files = ['deployment/build.py', 'pyproject.toml', 'setup.py']

    for build_file in build_files:
        if Path(build_file).exists():
            print(f"   ✓ {build_file}")
        else:
            print(f"   ○ {build_file}")

    # 8. Documentation check
    print("\n8. Checking documentation...")
    docs_path = Path('docs')
    if docs_path.exists():
        print(f"   ✓ Documentation directory: {docs_path}")

        # Count documentation files
        md_files = list(docs_path.rglob('*.md'))
        print(f"   ✓ Markdown files: {len(md_files)}")

    else:
        print(f"   ○ Documentation directory not found: {docs_path}")

    print("\n=== Development Diagnostics Complete ===")

if __name__ == "__main__":
    run_development_diagnostics()
```

### Test Runner Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Test Runner with Debugging
"""

import subprocess
import sys
import os
from pathlib import Path

def run_tests_with_debugging():
    """Run tests with comprehensive debugging."""

    print("=== Test Runner with Debugging ===\n")

    # 1. Pre-test environment check
    print("1. Checking test environment...")

    # Check if virtual environment is active
    venv = os.environ.get('VIRTUAL_ENV')
    if venv:
        print(f"   ✓ Virtual environment: {venv}")
    else:
        print("   ○ No virtual environment")

    # Check Python path
    print(f"   ✓ Python path: {len(sys.path)} entries")

    # 2. Test discovery
    print("\n2. Discovering tests...")

    try:
        # Run pytest discovery
        result = subprocess.run([
            sys.executable, '-m', 'pytest',
            '--collect-only', 'tests/',
            '-q'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            test_count = result.stdout.count('::test_')
            print(f"   ✓ Discovered {test_count} tests")
        else:
            print(f"   ✗ Test discovery failed: {result.stderr}")

    except Exception as e:
        print(f"   ✗ Test discovery error: {e}")

    # 3. Run tests with different configurations
    print("\n3. Running tests...")

    test_configs = [
        {
            'name': 'Basic Tests',
            'args': ['-v', 'tests/']
        },
        {
            'name': 'Tests with Coverage',
            'args': ['--cov=src', '--cov-report=term-missing', 'tests/']
        },
        {
            'name': 'Async Tests Only',
            'args': ['-k', 'asyncio', '-v', 'tests/']
        },
        {
            'name': 'Unit Tests Only',
            'args': ['-m', 'unit', '-v', 'tests/']
        }
    ]

    for config in test_configs:
        print(f"\n   Running: {config['name']}")

        try:
            result = subprocess.run([
                sys.executable, '-m', 'pytest'
            ] + config['args'], capture_output=True, text=True)

            if result.returncode == 0:
                print(f"     ✓ {config['name']} passed")
            else:
                print(f"     ✗ {config['name']} failed")
                print(f"       Errors: {result.stderr[:200]}...")

        except Exception as e:
            print(f"     ✗ {config['name']} error: {e}")

    # 4. Performance tests
    print("\n4. Running performance tests...")

    try:
        result = subprocess.run([
            sys.executable, '-m', 'pytest',
            'tests/test_performance.py',
            '-v', '-s'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("   ✓ Performance tests passed")
        else:
            print("   ✗ Performance tests failed")
            print(f"     Output: {result.stdout[-500:]}")

    except Exception as e:
        print(f"   ✗ Performance test error: {e}")

    print("\n=== Test Runner Complete ===")

if __name__ == "__main__":
    run_tests_with_debugging()
```

### Debug Console Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Interactive Debug Console
"""

import code
import sys
import os
from pathlib import Path

class DebugConsole(code.InteractiveConsole):
    """Enhanced interactive console for debugging."""

    def __init__(self, locals=None):
        super().__init__(locals)

        # Add debugging utilities
        self.locals.update({
            'debug_info': self.debug_info,
            'check_imports': self.check_imports,
            'test_component': self.test_component,
            'profile_code': self.profile_code,
            'memory_usage': self.memory_usage,
        })

    def debug_info(self):
        """Print debug information."""
        print("=== Debug Information ===")
        print(f"Python version: {sys.version}")
        print(f"Current directory: {os.getcwd()}")
        print(f"Python path length: {len(sys.path)}")

        # Check loaded modules
        src_modules = [m for m in sys.modules.keys() if m.startswith('src')]
        print(f"Loaded src modules: {len(src_modules)}")

        # Check system resources
        import psutil
        memory = psutil.virtual_memory()
        print(f"Memory usage: {memory.percent:.1f}%")

        print("=========================")

    def check_imports(self, module_pattern="*"):
        """Check module imports."""
        import importlib

        modules_to_check = [
            'src.crypto.key_management',
            'src.network.connection_manager',
            'src.storage.database_fixed',
            'src.gui.gui_app',
        ]

        for module_name in modules_to_check:
            try:
                module = importlib.import_module(module_name)
                print(f"✓ {module_name}")
            except ImportError as e:
                print(f"✗ {module_name}: {e}")

    def test_component(self, component_name):
        """Test a specific component."""
        try:
            if component_name == 'crypto':
                from src.crypto.key_management import KeyManager
                from pathlib import Path

                # Test key manager
                storage_path = Path("/tmp/test_keys")
                manager = KeyManager(storage_path, "test_password")
                print("✓ Crypto component working")

            elif component_name == 'network':
                from src.network.message_protocol import MessageSerializer

                # Test message protocol
                serializer = MessageSerializer()
                print("✓ Network component working")

            elif component_name == 'storage':
                from src.storage.database_fixed import StorageManager
                from pathlib import Path

                # Test storage manager
                storage_path = Path("/tmp/test_db")
                storage = StorageManager(storage_path, "test_password")
                print("✓ Storage component working")

            else:
                print(f"○ Unknown component: {component_name}")

        except Exception as e:
            print(f"✗ Component test failed: {e}")

    def profile_code(self, code_string):
        """Profile code execution."""
        import cProfile
        import pstats
        import io

        try:
            profiler = cProfile.Profile()
            profiler.enable()

            # Execute the code
            exec(code_string, self.locals)

            profiler.disable()

            # Show results
            stats = pstats.Stats(profiler)
            stats.sort_stats('cumulative')

            # Capture output
            output = io.StringIO()
            stats.print_stats(10, stream=output)
            print(output.getvalue())

        except Exception as e:
            print(f"✗ Profiling failed: {e}")

    def memory_usage(self):
        """Show memory usage information."""
        try:
            import psutil
            import os

            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / 1024 / 1024

            print(f"Current memory usage: {memory_mb:.1f}MB")

            # Show top memory consumers if tracemalloc available
            try:
                import tracemalloc

                if not tracemalloc.is_tracing():
                    tracemalloc.start()

                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics('lineno')

                print("Top memory consumers:")
                for stat in top_stats[:5]:
                    print(f"  {stat}")

            except ImportError:
                print("Tracemalloc not available")

        except Exception as e:
            print(f"✗ Memory check failed: {e}")

def start_debug_console():
    """Start interactive debug console."""

    print("Privatus-chat Debug Console")
    print("Available commands:")
    print("  debug_info()     - Show debug information")
    print("  check_imports()  - Check module imports")
    print("  test_component() - Test specific components")
    print("  profile_code()   - Profile code execution")
    print("  memory_usage()   - Show memory usage")
    print("  exit             - Exit console")
    print()

    # Setup console environment
    console_locals = {
        'sys': sys,
        'os': os,
        'Path': Path,
    }

    # Add source path
    src_path = Path(__file__).parent / 'src'
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    console = DebugConsole(console_locals)

    try:
        console.interact("Debug Console - Type 'debug_info()' for help")
    except KeyboardInterrupt:
        print("\nExiting debug console...")

if __name__ == "__main__":
    start_debug_console()
```

## Emergency Procedures

### Development Environment Reset

```python
# Emergency development environment reset
def emergency_dev_environment_reset():
    """Reset development environment to clean state."""

    print("WARNING: Emergency Development Environment Reset")
    print("This will reset the development environment.")

    confirmation = input("Type 'RESET' to confirm: ")
    if confirmation != 'RESET':
        print("Reset cancelled")
        return

    try:
        # 1. Clean virtual environment
        if os.path.exists('venv'):
            import shutil
            shutil.rmtree('venv')
            print("✓ Virtual environment removed")

        # 2. Recreate virtual environment
        subprocess.run([sys.executable, '-m', 'venv', 'venv'])
        print("✓ Virtual environment recreated")

        # 3. Reinstall dependencies
        pip_path = os.path.join('venv', 'bin', 'pip') if os.name != 'nt' else os.path.join('venv', 'Scripts', 'pip.exe')

        subprocess.run([pip_path, 'install', '-r', 'requirements.txt'])
        subprocess.run([pip_path, 'install', '-r', 'requirements-dev.txt'])
        print("✓ Dependencies reinstalled")

        # 4. Clean temporary files
        temp_dirs = ['__pycache__', '.pytest_cache', 'htmlcov', '.coverage']
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                if os.path.isdir(temp_dir):
                    shutil.rmtree(temp_dir)
                else:
                    os.remove(temp_dir)

        print("✓ Temporary files cleaned")

        print("✓ Emergency reset complete")

    except Exception as e:
        print(f"✗ Emergency reset failed: {e}")
```

### Debug Mode Activation

```python
# Force enable debug mode for troubleshooting
def force_enable_debug_mode():
    """Force enable all debug features."""

    try:
        # 1. Set all debug environment variables
        debug_vars = {
            'PRIVATUS_DEBUG': '1',
            'PRIVATUS_LOG_LEVEL': 'DEBUG',
            'PYTHONASYNCIODEBUG': '1',
            'PYTHONDONTWRITEBYTECODE': '1',
        }

        for var, value in debug_vars.items():
            os.environ[var] = value
            print(f"✓ Set {var}={value}")

        # 2. Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )

        # Enable all loggers
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('src').setLevel(logging.DEBUG)
        logging.getLogger('tests').setLevel(logging.DEBUG)

        print("✓ Debug logging configured")

        # 3. Enable profiling
        import cProfile
        profiler = cProfile.Profile()
        profiler.enable()
        print("✓ Code profiling enabled")

        print("✓ Debug mode fully activated")

    except Exception as e:
        print(f"✗ Debug mode activation failed: {e}")
```

## Prevention and Best Practices

### Development Workflow Best Practices

1. **Code Quality Automation**:
   ```python
   # Implement automated code quality checks
   def setup_code_quality_checks():
       # Run tests before commits
       def pre_commit_hook():
           # Run tests
           test_result = subprocess.run(['python', '-m', 'pytest', 'tests/'],
                                      capture_output=True)

           if test_result.returncode != 0:
               print("✗ Tests failed - commit blocked")
               return False

           # Run code quality checks
           style_result = subprocess.run(['python', '-m', 'flake8', 'src/'],
                                       capture_output=True)

           if style_result.returncode != 0:
               print("✗ Style check failed - commit blocked")
               return False

           print("✓ All checks passed")
           return True

       # Setup as git hook
       print("✓ Code quality checks configured")
   ```

2. **Development Environment Consistency**:
   ```python
   # Ensure consistent development environment
   def ensure_environment_consistency():
       # Check Python version
       required_version = (3, 8)
       current_version = sys.version_info[:2]

       if current_version < required_version:
           print(f"✗ Python version too old: {current_version}")
       else:
           print(f"✓ Python version OK: {current_version}")

       # Check required packages
       required_packages = ['PyQt6', 'cryptography']
       for package in required_packages:
           try:
               __import__(package)
               print(f"✓ {package}")
           except ImportError:
               print(f"✗ {package} missing")

       print("✓ Environment consistency check complete")
   ```

3. **Automated Testing Integration**:
   ```python
   # Integrate testing into development workflow
   def integrate_testing_workflow():
       # Run tests on file changes
       def watch_and_test():
           import time

           last_run = 0
           while True:
               # Check for file changes
               current_time = time.time()
               if current_time - last_run > 10:  # Every 10 seconds
                   # Run quick test suite
                   result = subprocess.run(['python', '-m', 'pytest', 'tests/', '-x'],
                                         capture_output=True)
                   last_run = current_time

               time.sleep(1)

       # Start test watcher
       print("✓ Test integration configured")
   ```

### Debugging Best Practices

1. **Systematic Debugging Approach**:
   ```python
   # Implement systematic debugging
   def systematic_debugging(target_function):
       def debug_wrapper(*args, **kwargs):
           print(f"DEBUG: Calling {target_function.__name__}")

           # Log arguments
           print(f"DEBUG: Args: {args}")
           print(f"DEBUG: Kwargs: {kwargs}")

           # Time execution
           start_time = time.time()

           try:
               result = target_function(*args, **kwargs)
               end_time = time.time()

               print(f"DEBUG: Success in {end_time - start_time:.3f}s")
               print(f"DEBUG: Result: {result}")
               return result

           except Exception as e:
               end_time = time.time()
               print(f"DEBUG: Failed in {end_time - start_time:.3f}s")
               print(f"DEBUG: Exception: {e}")
               raise

       return debug_wrapper
   ```

2. **Interactive Debugging Setup**:
   ```python
   # Setup interactive debugging environment
   def setup_interactive_debugging():
       # Create debug namespace
       debug_namespace = {
           'sys': sys,
           'os': os,
           'time': time,
           'Path': Path,
       }

       # Add debugging utilities
       def quick_test():
           print("Quick test function available")

       def inspect_object(obj):
           print(f"Object type: {type(obj)}")
           print(f"Object dir: {dir(obj)}")

       debug_namespace.update({
           'quick_test': quick_test,
           'inspect': inspect_object,
       })

       print("✓ Interactive debugging environment ready")
       return debug_namespace
   ```

3. **Performance Debugging**:
   ```python
   # Debug performance issues systematically
   def debug_performance_issues():
       # Profile different components
       components = ['crypto', 'network', 'storage', 'gui']

       for component in components:
           print(f"Profiling {component}...")

           # Profile component operations
           start_time = time.time()

           if component == 'crypto':
               # Test crypto operations
               pass
           elif component == 'network':
               # Test network operations
               pass
           # ... other components

           end_time = time.time()
           print(f"{component} profiling: {end_time - start_time:.3f}s")

       print("✓ Performance debugging complete")
   ```

## Getting Help

### Self-Service Resources

1. **Documentation**:
   - [Development Guide](docs/developer/developer-guide.md)
   - [API Reference](docs/developer/api-reference.md)
   - [Architecture Guide](docs/developer/architecture.md)

2. **Community Support**:
   - [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
   - [Development Discussions](https://github.com/privatus-chat/privatus-chat/discussions/categories/development)

### Reporting Development Issues

When reporting development issues, please include:

1. **Environment Information**:
   - Operating system and version
   - Python version and virtual environment
   - IDE and version

2. **Development Setup**:
   - Installation method used
   - Configuration files
   - Environment variables

3. **Problem Details**:
   - Exact error messages
   - Steps to reproduce
   - Diagnostic output

4. **Code Context**:
   - Relevant code snippets
   - Test cases if applicable
   - Configuration files

---

*Remember: Development issues often have simple solutions. Always check your environment setup, dependencies, and configuration before assuming deeper problems.*

*Last updated: January 2025*
*Version: 1.0.0*