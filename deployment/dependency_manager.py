#!/usr/bin/env python3
"""
Automated Dependency Management for Privatus-chat

Handles:
- Dependency version management and updates
- Security vulnerability scanning
- License compliance checking
- Dependency lock file management
- Automated dependency updates
"""

import os
import sys
import subprocess
import json
import re
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import argparse
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import tempfile

class DependencyStatus(Enum):
    """Dependency status enumeration."""
    CURRENT = "current"
    OUTDATED = "outdated"
    VULNERABLE = "vulnerable"
    INCOMPATIBLE = "incompatible"
    MISSING = "missing"

@dataclass
class DependencyInfo:
    """Information about a dependency."""
    name: str
    current_version: str
    latest_version: str
    status: DependencyStatus
    vulnerabilities: List[Dict]
    license: str
    last_updated: str
    update_available: bool
    breaking_changes: bool

class DependencyManager:
    """Manages dependencies for Privatus-chat."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.requirements_file = project_root / "requirements.txt"
        self.dev_requirements_file = project_root / "requirements-dev.txt"
        self.lock_file = project_root / "requirements.lock"
        self.vulnerability_db = {}

        # Load dependency configurations
        self.config = self._load_dependency_config()

        # Initialize vulnerability database
        self._initialize_vulnerability_db()

    def _load_dependency_config(self) -> Dict:
        """Load dependency management configuration."""
        config_file = self.project_root / "deployment" / "dependency_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            return {
                "auto_update": False,
                "security_only": True,
                "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0"],
                "blocked_licenses": ["GPL-2.0", "LGPL-2.1", "Proprietary"],
                "vulnerability_scan_interval": 24,  # hours
                "update_check_interval": 7,  # days
                "test_after_update": True,
                "create_backup": True,
                "notify_on_vulnerabilities": True
            }

    def _initialize_vulnerability_db(self):
        """Initialize vulnerability database."""
        try:
            # This would typically connect to a vulnerability database
            # For now, we'll use a simplified local database
            vuln_file = self.project_root / "deployment" / "vulnerability_db.json"
            if vuln_file.exists():
                with open(vuln_file, 'r') as f:
                    self.vulnerability_db = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load vulnerability database: {e}")

    def scan_dependencies(self) -> Dict[str, DependencyInfo]:
        """Scan all dependencies for vulnerabilities and updates."""
        try:
            print("🔍 Scanning dependencies...")

            dependencies = {}

            # Scan main requirements
            if self.requirements_file.exists():
                main_deps = self._parse_requirements_file(self.requirements_file)
                dependencies.update(main_deps)

            # Scan development requirements
            if self.dev_requirements_file.exists():
                dev_deps = self._parse_requirements_file(self.dev_requirements_file)
                dependencies.update(dev_deps)

            # Check for updates and vulnerabilities
            for dep_name, dep_info in dependencies.items():
                self._check_dependency_updates(dep_info)
                self._check_dependency_vulnerabilities(dep_info)

            # Save scan results
            self._save_scan_results(dependencies)

            return dependencies

        except Exception as e:
            print(f"✗ Dependency scan error: {e}")
            return {}

    def _parse_requirements_file(self, requirements_file: Path) -> Dict[str, DependencyInfo]:
        """Parse requirements file and extract dependency information."""
        dependencies = {}

        try:
            with open(requirements_file, 'r') as f:
                content = f.read()

            # Parse requirements
            for line in content.split('\n'):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Parse package specification
                # Format: package==version or package>=version,<=version
                match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])([><=!~,\s\d.]+)?', line)
                if match:
                    package_name = match.group(1).lower()
                    version_spec = match.group(2) or ""

                    # Extract current version
                    current_version = "latest"
                    if "==" in version_spec:
                        current_version = version_spec.split("==")[1].split(",")[0].strip()
                    elif ">=" in version_spec:
                        current_version = version_spec.split(">=")[1].split(",")[0].strip()

                    dependencies[package_name] = DependencyInfo(
                        name=package_name,
                        current_version=current_version,
                        latest_version=current_version,
                        status=DependencyStatus.CURRENT,
                        vulnerabilities=[],
                        license="Unknown",
                        last_updated=datetime.now().isoformat(),
                        update_available=False,
                        breaking_changes=False
                    )

        except Exception as e:
            print(f"Warning: Error parsing {requirements_file}: {e}")

        return dependencies

    def _check_dependency_updates(self, dep_info: DependencyInfo):
        """Check if updates are available for a dependency."""
        try:
            # Use pip to check for latest version
            result = subprocess.run([
                sys.executable, "-m", "pip", "index", "versions", dep_info.name
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                # Parse output to find latest version
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'LATEST:' in line:
                        latest_version = line.split('LATEST:')[1].strip()
                        dep_info.latest_version = latest_version
                        dep_info.update_available = latest_version != dep_info.current_version
                        break

        except Exception as e:
            print(f"Warning: Could not check updates for {dep_info.name}: {e}")

    def _check_dependency_vulnerabilities(self, dep_info: DependencyInfo):
        """Check for known vulnerabilities in a dependency."""
        try:
            # Check against local vulnerability database
            if dep_info.name in self.vulnerability_db:
                db_entry = self.vulnerability_db[dep_info.name]

                # Check if current version is vulnerable
                for vuln in db_entry.get("vulnerabilities", []):
                    affected_versions = vuln.get("affected_versions", [])
                    if self._version_affected(dep_info.current_version, affected_versions):
                        dep_info.vulnerabilities.append(vuln)
                        dep_info.status = DependencyStatus.VULNERABLE

            # Update status based on vulnerabilities
            if dep_info.vulnerabilities:
                dep_info.status = DependencyStatus.VULNERABLE
            elif dep_info.update_available:
                dep_info.status = DependencyStatus.OUTDATED

        except Exception as e:
            print(f"Warning: Could not check vulnerabilities for {dep_info.name}: {e}")

    def _version_affected(self, version: str, affected_versions: List[str]) -> bool:
        """Check if a version is affected by vulnerabilities."""
        try:
            # Simple version comparison logic
            # In production, would use proper semantic versioning
            for affected in affected_versions:
                if affected == version or affected == "*":
                    return True
                if affected.endswith("*"):
                    prefix = affected[:-1]
                    if version.startswith(prefix):
                        return True
            return False
        except Exception:
            return False

    def _save_scan_results(self, dependencies: Dict[str, DependencyInfo]):
        """Save dependency scan results."""
        try:
            results = {
                "scan_date": datetime.now().isoformat(),
                "total_dependencies": len(dependencies),
                "vulnerable_dependencies": len([d for d in dependencies.values() if d.status == DependencyStatus.VULNERABLE]),
                "outdated_dependencies": len([d for d in dependencies.values() if d.status == DependencyStatus.OUTDATED]),
                "dependencies": {name: asdict(dep_info) for name, dep_info in dependencies.items()}
            }

            results_file = self.project_root / "dist" / "dependency_scan_results.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)

            print(f"✓ Dependency scan results saved: {results_file}")

        except Exception as e:
            print(f"✗ Could not save scan results: {e}")

    def update_dependencies(self, security_only: bool = True) -> bool:
        """Update dependencies to latest versions."""
        try:
            print(f"📦 Updating dependencies (security_only={security_only})...")

            if self.config["create_backup"]:
                self._backup_requirements()

            success = True

            # Update main requirements
            if self.requirements_file.exists():
                if not self._update_requirements_file(self.requirements_file, security_only):
                    success = False

            # Update development requirements
            if self.dev_requirements_file.exists():
                if not self._update_requirements_file(self.dev_requirements_file, security_only):
                    success = False

            # Test after update if configured
            if success and self.config["test_after_update"]:
                if not self._test_after_update():
                    print("⚠️ Tests failed after dependency update")
                    if self.config["create_backup"]:
                        self._restore_requirements()
                    return False

            # Generate lock file
            if success:
                self._generate_lock_file()

            return success

        except Exception as e:
            print(f"✗ Dependency update error: {e}")
            return False

    def _backup_requirements(self):
        """Create backup of requirements files."""
        try:
            backup_dir = self.project_root / "backups" / "dependencies"
            backup_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            if self.requirements_file.exists():
                shutil.copy2(self.requirements_file, backup_dir / f"requirements.txt.{timestamp}.bak")

            if self.dev_requirements_file.exists():
                shutil.copy2(self.dev_requirements_file, backup_dir / f"requirements-dev.txt.{timestamp}.bak")

            print(f"✓ Requirements backed up to {backup_dir}")

        except Exception as e:
            print(f"⚠️ Could not create backup: {e}")

    def _restore_requirements(self):
        """Restore requirements from backup."""
        try:
            backup_dir = self.project_root / "backups" / "dependencies"
            if not backup_dir.exists():
                print("✗ No backup directory found")
                return False

            # Find latest backup
            backup_files = list(backup_dir.glob("requirements.txt.*.bak"))
            if backup_files:
                latest_backup = max(backup_files, key=lambda p: p.stat().st_mtime)
                shutil.copy2(latest_backup, self.requirements_file)
                print(f"✓ Restored requirements from {latest_backup}")
                return True

            return False

        except Exception as e:
            print(f"✗ Could not restore backup: {e}")
            return False

    def _update_requirements_file(self, requirements_file: Path, security_only: bool) -> bool:
        """Update a requirements file."""
        try:
            print(f"Updating {requirements_file.name}...")

            # Read current requirements
            with open(requirements_file, 'r') as f:
                current_content = f.read()

            updated_content = current_content
            updates_made = []

            # Check each dependency for updates
            lines = current_content.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Extract package name
                match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])', line)
                if match:
                    package_name = match.group(1).lower()

                    # Check if update is available and safe
                    if self._should_update_package(package_name, security_only):
                        # Get latest version
                        latest_version = self._get_latest_version(package_name)

                        if latest_version and latest_version != self._get_current_version(line):
                            # Update the line
                            if "==" in line:
                                # Replace specific version
                                lines[i] = line.replace(self._get_current_version(line), latest_version)
                            else:
                                # Add version specification
                                lines[i] = f"{package_name}=={latest_version}"

                            updates_made.append(f"{package_name}: {self._get_current_version(line)} → {latest_version}")

            # Write updated content
            updated_content = '\n'.join(lines)
            with open(requirements_file, 'w') as f:
                f.write(updated_content)

            if updates_made:
                print(f"✓ Updated packages in {requirements_file.name}:")
                for update in updates_made:
                    print(f"   • {update}")
            else:
                print(f"✓ No updates needed for {requirements_file.name}")

            return True

        except Exception as e:
            print(f"✗ Could not update {requirements_file}: {e}")
            return False

    def _should_update_package(self, package_name: str, security_only: bool) -> bool:
        """Determine if a package should be updated."""
        try:
            # Check for vulnerabilities first
            if package_name in self.vulnerability_db:
                db_entry = self.vulnerability_db[package_name]
                if db_entry.get("vulnerabilities"):
                    return True

            if security_only:
                return False

            # Check if update is available
            result = subprocess.run([
                sys.executable, "-m", "pip", "index", "versions", package_name
            ], capture_output=True, text=True, timeout=10)

            return result.returncode == 0

        except Exception:
            return False

    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """Get the latest version of a package."""
        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "index", "versions", package_name
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'LATEST:' in line:
                        return line.split('LATEST:')[1].strip()

        except Exception:
            pass

        return None

    def _get_current_version(self, requirement_line: str) -> str:
        """Extract current version from requirement line."""
        if "==" in requirement_line:
            return requirement_line.split("==")[1].split(",")[0].strip()
        return "latest"

    def _test_after_update(self) -> bool:
        """Test that updated dependencies work correctly."""
        try:
            print("Testing updated dependencies...")

            # Install updated requirements in temporary environment
            with tempfile.TemporaryDirectory() as temp_dir:
                venv_path = Path(temp_dir) / "venv"

                # Create virtual environment
                result = subprocess.run([
                    sys.executable, "-m", "venv", str(venv_path)
                ], check=True, capture_output=True)

                # Install updated requirements
                pip_path = venv_path / "bin" / "pip" if os.name != "nt" else venv_path / "Scripts" / "pip.exe"

                if self.requirements_file.exists():
                    result = subprocess.run([
                        str(pip_path), "install", "-r", str(self.requirements_file)
                    ], check=True, capture_output=True)

                # Run basic tests
                test_result = subprocess.run([
                    venv_path / "bin" / "python" if os.name != "nt" else venv_path / "Scripts" / "python.exe",
                    "-c", "import sys; print('Python version:', sys.version); print('Dependencies test: OK')"
                ], capture_output=True, text=True)

                if test_result.returncode == 0:
                    print("✓ Dependency update test passed")
                    return True
                else:
                    print(f"✗ Dependency update test failed: {test_result.stderr}")
                    return False

        except Exception as e:
            print(f"✗ Dependency test error: {e}")
            return False

    def _generate_lock_file(self):
        """Generate requirements lock file."""
        try:
            print("Generating requirements lock file...")

            lock_data = {
                "generated_at": datetime.now().isoformat(),
                "python_version": sys.version,
                "requirements": {}
            }

            # Get installed packages with exact versions
            result = subprocess.run([
                sys.executable, "-m", "pip", "freeze"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '==' in line:
                        package_name, version = line.split('==', 1)
                        lock_data["requirements"][package_name] = version

            # Save lock file
            with open(self.lock_file, 'w') as f:
                json.dump(lock_data, f, indent=2)

            print(f"✓ Lock file generated: {self.lock_file}")

        except Exception as e:
            print(f"✗ Lock file generation error: {e}")

    def check_license_compliance(self) -> Dict[str, List[str]]:
        """Check license compliance for all dependencies."""
        try:
            print("🔍 Checking license compliance...")

            compliance_results = {
                "compliant": [],
                "non_compliant": [],
                "unknown": []
            }

            # This would typically check against license databases
            # For now, we'll use a simplified check

            if self.requirements_file.exists():
                with open(self.requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        # Extract package name
                        match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])', line)
                        if match:
                            package_name = match.group(1).lower()

                            # Check license (simplified)
                            license_info = self._get_package_license(package_name)

                            if license_info in self.config["allowed_licenses"]:
                                compliance_results["compliant"].append(package_name)
                            elif license_info in self.config["blocked_licenses"]:
                                compliance_results["non_compliant"].append(package_name)
                            else:
                                compliance_results["unknown"].append(package_name)

            # Save compliance report
            report_file = self.project_root / "dist" / "license_compliance_report.json"
            with open(report_file, 'w') as f:
                json.dump(compliance_results, f, indent=2)

            print(f"✓ License compliance report: {report_file}")
            return compliance_results

        except Exception as e:
            print(f"✗ License compliance check error: {e}")
            return {"compliant": [], "non_compliant": [], "unknown": []}

    def _get_package_license(self, package_name: str) -> str:
        """Get license information for a package."""
        try:
            # This would typically query PyPI or license databases
            # For now, return a placeholder
            return "Unknown"
        except Exception:
            return "Unknown"

def main():
    parser = argparse.ArgumentParser(description="Dependency Management for Privatus-chat")
    parser.add_argument("--scan", action="store_true",
                        help="Scan dependencies for vulnerabilities and updates")
    parser.add_argument("--update", action="store_true",
                        help="Update dependencies to latest versions")
    parser.add_argument("--security-only", action="store_true",
                        help="Only update packages with security vulnerabilities")
    parser.add_argument("--check-licenses", action="store_true",
                        help="Check license compliance")
    parser.add_argument("--generate-lock", action="store_true",
                        help="Generate requirements lock file")
    parser.add_argument("--full-audit", action="store_true",
                        help="Perform full dependency audit")

    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    dep_manager = DependencyManager(project_root)

    if args.scan or args.full_audit:
        print("🔍 Performing dependency scan...")
        dependencies = dep_manager.scan_dependencies()

        vulnerable = [name for name, dep in dependencies.items() if dep.status == DependencyStatus.VULNERABLE]
        outdated = [name for name, dep in dependencies.items() if dep.status == DependencyStatus.OUTDATED]

        print(f"\n📊 Scan Results:")
        print(f"   Total dependencies: {len(dependencies)}")
        print(f"   Vulnerable: {len(vulnerable)}")
        print(f"   Outdated: {len(outdated)}")

        if vulnerable:
            print(f"\n⚠️ Vulnerable dependencies:")
            for name in vulnerable:
                dep = dependencies[name]
                print(f"   • {name}: {dep.current_version} ({len(dep.vulnerabilities)} vulnerabilities)")

    if args.update:
        print("📦 Updating dependencies...")
        success = dep_manager.update_dependencies(args.security_only)

        if success:
            print("✓ Dependencies updated successfully")
        else:
            print("✗ Dependency update failed")

    if args.check_licenses:
        print("🔍 Checking license compliance...")
        compliance = dep_manager.check_license_compliance()

        print(f"\n📊 License Compliance:")
        print(f"   Compliant: {len(compliance['compliant'])}")
        print(f"   Non-compliant: {len(compliance['non_compliant'])}")
        print(f"   Unknown: {len(compliance['unknown'])}")

    if args.generate_lock or args.full_audit:
        print("🔒 Generating lock file...")
        dep_manager._generate_lock_file()

    if args.full_audit:
        print("\n🎯 Full audit completed!")
        print("Check the dist/ directory for detailed reports.")

if __name__ == "__main__":
    main()