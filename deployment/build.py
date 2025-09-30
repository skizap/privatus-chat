#!/usr/bin/env python3
"""
Enhanced Production Build Script for Privatus-chat

Creates standalone executables and packages for different platforms with:
- Enhanced feature support (file transfer, voice calls, performance monitoring, security testing)
- Platform-specific optimizations
- Security hardening
- Automated dependency management
- Multi-stage Docker builds
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import platform
import argparse
import json
import hashlib
from datetime import datetime

class ProductionBuilder:
    """Enhanced production builder for Privatus-chat with feature support."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.dist_dir = project_root / "dist"
        self.build_dir = project_root / "build"
        self.temp_dir = project_root / "temp"
        self.deployment_dir = project_root / "deployment"

        # Create directories
        for dir_path in [self.dist_dir, self.build_dir, self.temp_dir]:
            dir_path.mkdir(exist_ok=True)

        # Load build configuration
        self.config = self._load_build_config()

        # Feature flags
        self.features = {
            'file_transfer': True,
            'voice_calls': True,
            'performance_monitoring': True,
            'security_testing': True,
            'gui_enhancements': True,
            'crypto_optimizations': True
        }

    def build_executable(self, target_platform: str = None) -> bool:
        """Build standalone executable using PyInstaller."""
        try:
            print("Building standalone executable...")

            # Determine platform if not specified
            if not target_platform:
                target_platform = platform.system().lower()

            # PyInstaller command
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",  # Single executable file
                "--windowed",  # GUI application (no console on Windows)
                "--name", "privatus-chat",
                "--distpath", str(self.dist_dir),
                "--workpath", str(self.build_dir),
                "--clean",  # Clean cache
                "--noconfirm",  # Don't ask for confirmation
            ]

            # Add platform-specific options
            if target_platform == "windows":
                cmd.extend([
                    "--icon", "resources/icon.ico",  # Add icon if available
                    "--version-file", "version_info.txt"  # Version info for Windows
                ])
            elif target_platform in ["linux", "darwin"]:
                cmd.extend([
                    "--hidden-import", "PyQt6.QtCore",
                    "--hidden-import", "PyQt6.QtGui",
                    "--hidden-import", "PyQt6.QtWidgets",
                ])

            # Main script
            main_script = self.project_root / "launch_gui.py"
            cmd.append(str(main_script))

            # Run PyInstaller
            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✓ Executable built successfully: {self.dist_dir}/privatus-chat")
                return True
            else:
                print(f"✗ Build failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ Build error: {e}")
            return False

    def create_installer(self, target_platform: str = None) -> bool:
        """Create platform-specific installer."""
        try:
            print("Creating installer package...")

            if not target_platform:
                target_platform = platform.system().lower()

            if target_platform == "windows":
                return self._create_windows_installer()
            elif target_platform == "linux":
                return self._create_linux_package()
            elif target_platform == "darwin":
                return self._create_macos_app()
            else:
                print(f"✗ Unsupported platform: {target_platform}")
                return False

        except Exception as e:
            print(f"✗ Installer creation error: {e}")
            return False

    def _create_windows_installer(self) -> bool:
        """Create Windows MSI installer."""
        try:
            # Check if WiX Toolset is available (would need to be installed separately)
            # For now, create a simple ZIP package
            import zipfile

            exe_path = self.dist_dir / "privatus-chat.exe"
            if not exe_path.exists():
                print("✗ Executable not found, run build_executable first")
                return False

            zip_path = self.dist_dir / "privatus-chat-windows.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(exe_path, "privatus-chat.exe")
                # Add README and other files
                readme = self.project_root / "README.md"
                if readme.exists():
                    zipf.write(readme, "README.md")

            print(f"✓ Windows package created: {zip_path}")
            return True

        except Exception as e:
            print(f"✗ Windows installer creation error: {e}")
            return False

    def _create_linux_package(self) -> bool:
        """Create Linux AppImage or DEB package."""
        try:
            exe_path = self.dist_dir / "privatus-chat"
            if not exe_path.exists():
                print("✗ Executable not found, run build_executable first")
                return False

            # Create a simple tar.gz package for now
            import tarfile

            tar_path = self.dist_dir / "privatus-chat-linux.tar.gz"
            with tarfile.open(tar_path, 'w:gz') as tar:
                tar.add(exe_path, arcname="privatus-chat")
                # Add README and other files
                readme = self.project_root / "README.md"
                if readme.exists():
                    tar.add(readme, arcname="README.md")

            print(f"✓ Linux package created: {tar_path}")
            return True

        except Exception as e:
            print(f"✗ Linux package creation error: {e}")
            return False

    def _create_macos_app(self) -> bool:
        """Create macOS .app bundle."""
        try:
            exe_path = self.dist_dir / "privatus-chat"
            if not exe_path.exists():
                print("✗ Executable not found, run build_executable first")
                return False

            # Create a simple ZIP package for now
            import zipfile

            zip_path = self.dist_dir / "privatus-chat-macos.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(exe_path, "privatus-chat")
                # Add README and other files
                readme = self.project_root / "README.md"
                if readme.exists():
                    zipf.write(readme, "README.md")

            print(f"✓ macOS package created: {zip_path}")
            return True

        except Exception as e:
            print(f"✗ macOS package creation error: {e}")
            return False

    def create_deployment_package(self) -> bool:
        """Create deployment package with all necessary files."""
        try:
            print("Creating deployment package...")

            deploy_dir = self.dist_dir / "deployment"
            deploy_dir.mkdir(exist_ok=True)

            # Copy executable
            exe_name = "privatus-chat.exe" if platform.system() == "Windows" else "privatus-chat"
            exe_path = self.dist_dir / exe_name
            if exe_path.exists():
                shutil.copy2(exe_path, deploy_dir / exe_name)

            # Copy documentation
            docs_dir = self.project_root / "docs"
            if docs_dir.exists():
                shutil.copytree(docs_dir, deploy_dir / "docs", dirs_exist_ok=True)

            # Copy configuration templates
            config_dir = self.project_root / "config"
            if config_dir.exists():
                shutil.copytree(config_dir, deploy_dir / "config", dirs_exist_ok=True)

            # Create deployment archive
            import zipfile
            archive_path = self.dist_dir / f"privatus-chat-deployment-{platform.system().lower()}.zip"
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in deploy_dir.rglob('*'):
                    if file_path.is_file():
                        zipf.write(file_path, file_path.relative_to(deploy_dir))

            print(f"✓ Deployment package created: {archive_path}")
            return True

        except Exception as e:
            print(f"✗ Deployment package creation error: {e}")
            return False

    def run_tests(self) -> bool:
        """Run test suite before building."""
        try:
            print("Running tests...")
            result = subprocess.run([
                sys.executable, "-m", "pytest",
                "tests/",
                "--tb=short",
                "-q"
            ], cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print("✓ All tests passed")
                return True
            else:
                print(f"✗ Tests failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ Test execution error: {e}")
            return False

    def clean_build_artifacts(self):
        """Clean build artifacts."""
        try:
            if self.build_dir.exists():
                shutil.rmtree(self.build_dir)
            if self.dist_dir.exists():
                shutil.rmtree(self.dist_dir)
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            print("✓ Build artifacts cleaned")
        except Exception as e:
            print(f"✗ Clean error: {e}")

    def _load_build_config(self) -> Dict:
        """Load build configuration."""
        config_file = self.deployment_dir / "build_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            # Default configuration
            return {
                "version": "3.0.0",
                "build_date": datetime.now().isoformat(),
                "features": self.features,
                "platforms": ["windows", "linux", "darwin"],
                "security": {
                    "enable_hardening": True,
                    "strip_binaries": True,
                    "code_signing": False
                },
                "optimization": {
                    "level": "standard",
                    "include_debug_info": False
                }
            }

    def _save_build_config(self):
        """Save current build configuration."""
        config_file = self.deployment_dir / "build_config.json"
        self.config["build_date"] = datetime.now().isoformat()

        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)

    def verify_features(self) -> bool:
        """Verify that all enabled features are available."""
        try:
            print("Verifying enabled features...")

            # Check file transfer feature
            if self.features['file_transfer']:
                file_transfer_path = self.project_root / "src" / "messaging" / "file_transfer.py"
                if not file_transfer_path.exists():
                    print("⚠️ File transfer feature enabled but module not found")
                    return False

            # Check voice calls feature
            if self.features['voice_calls']:
                voice_calls_path = self.project_root / "src" / "communication" / "voice_calls.py"
                if not voice_calls_path.exists():
                    print("⚠️ Voice calls feature enabled but module not found")
                    return False

            # Check performance monitoring feature
            if self.features['performance_monitoring']:
                perf_monitor_path = self.project_root / "src" / "performance" / "performance_monitor.py"
                if not perf_monitor_path.exists():
                    print("⚠️ Performance monitoring feature enabled but module not found")
                    return False

            # Check security testing feature
            if self.features['security_testing']:
                security_test_path = self.project_root / "src" / "security" / "vulnerability_scanner.py"
                if not security_test_path.exists():
                    print("⚠️ Security testing feature enabled but module not found")
                    return False

            print("✓ All enabled features verified")
            return True

        except Exception as e:
            print(f"✗ Feature verification error: {e}")
            return False

    def build_with_features(self, target_platform: str = None) -> bool:
        """Build executable with enhanced features."""
        try:
            print("Building enhanced executable with features...")

            # Verify features first
            if not self.verify_features():
                print("✗ Feature verification failed")
                return False

            # Determine platform if not specified
            if not target_platform:
                target_platform = platform.system().lower()

            # Enhanced PyInstaller command with feature-specific hidden imports
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile",
                "--windowed",
                "--name", "privatus-chat",
                "--distpath", str(self.dist_dir),
                "--workpath", str(self.build_dir),
                "--clean",
                "--noconfirm",
            ]

            # Add feature-specific hidden imports
            feature_imports = [
                # Core features
                "--hidden-import", "src.messaging.file_transfer",
                "--hidden-import", "src.communication.voice_calls",
                "--hidden-import", "src.performance.performance_monitor",
                "--hidden-import", "src.security.vulnerability_scanner",

                # GUI enhancements
                "--hidden-import", "src.gui.privacy_dashboard",
                "--hidden-import", "src.gui.onboarding_wizard",

                # Crypto optimizations
                "--hidden-import", "src.crypto.double_ratchet",
                "--hidden-import", "src.crypto.key_management",

                # Network features
                "--hidden-import", "src.network.message_protocol",
                "--hidden-import", "src.network.p2p_node",

                # Anonymity features
                "--hidden-import", "src.anonymity.anonymous_identity",
                "--hidden-import", "src.anonymity.onion_routing",
                "--hidden-import", "src.anonymity.traffic_analysis",
            ]

            cmd.extend(feature_imports)

            # Add platform-specific options
            if target_platform == "windows":
                cmd.extend([
                    "--icon", "resources/icon.ico",
                    "--version-file", "version_info.txt",
                    "--add-data", "src/gui/themes;themes",
                    "--add-data", "config;config",
                ])
            elif target_platform in ["linux", "darwin"]:
                cmd.extend([
                    "--add-data", "src/gui/themes:themes",
                    "--add-data", "config:config",
                ])

            # Add security hardening
            if self.config["security"]["enable_hardening"]:
                cmd.extend([
                    "--strip",  # Strip debug information
                    "--noupx",  # Don't use UPX compression for security
                ])

            # Main script
            main_script = self.project_root / "launch_gui.py"
            cmd.append(str(main_script))

            # Run PyInstaller
            print(f"Running PyInstaller for {target_platform}...")
            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✓ Enhanced executable built successfully: {self.dist_dir}/privatus-chat")
                return True
            else:
                print(f"✗ Enhanced build failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ Enhanced build error: {e}")
            return False

    def create_platform_packages(self, target_platform: str = None) -> List[Path]:
        """Create platform-specific packages using enhanced builders."""
        try:
            print(f"Creating platform-specific packages for {target_platform or 'all platforms'}...")

            if not target_platform:
                target_platform = platform.system().lower()

            created_packages = []

            # Import platform-specific builders
            if target_platform == "windows":
                try:
                    from deployment.windows_installer import create_windows_installer
                    msi_path = create_windows_installer(self.project_root, self.dist_dir)
                    if msi_path:
                        created_packages.append(msi_path)
                except ImportError:
                    print("⚠️ Windows installer module not available")

            elif target_platform == "darwin":
                try:
                    from deployment.macos_dmg_builder import create_macos_dmg
                    dmg_path = create_macos_dmg(self.project_root, self.dist_dir)
                    if dmg_path:
                        created_packages.append(dmg_path)
                except ImportError:
                    print("⚠️ macOS DMG builder module not available")

            elif target_platform == "linux":
                try:
                    from deployment.linux_packages import create_linux_packages
                    linux_packages = create_linux_packages(self.project_root, self.dist_dir)
                    created_packages.extend(linux_packages)
                except ImportError:
                    print("⚠️ Linux packages module not available")

            # Create Docker image
            try:
                docker_image = self._create_enhanced_docker_image()
                if docker_image:
                    created_packages.append(docker_image)
            except Exception as e:
                print(f"⚠️ Docker image creation failed: {e}")

            return created_packages

        except Exception as e:
            print(f"✗ Platform packages creation error: {e}")
            return []

    def _create_enhanced_docker_image(self) -> Optional[Path]:
        """Create enhanced Docker image with multi-stage builds."""
        try:
            print("Creating enhanced Docker image...")

            dockerfile = self.deployment_dir / "Dockerfile.multistage"
            if not dockerfile.exists():
                print("⚠️ Enhanced Dockerfile not found, using basic Dockerfile")
                dockerfile = self.deployment_dir / "Dockerfile"

            # Build Docker image
            image_name = f"privatus-chat:{self.config['version']}"
            cmd = ["docker", "build", "-t", image_name, "-f", str(dockerfile), "."]

            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✓ Enhanced Docker image {image_name} created successfully")

                # Save image info
                image_info = {
                    "name": image_name,
                    "version": self.config["version"],
                    "build_date": self.config["build_date"],
                    "features": self.features
                }

                info_file = self.dist_dir / "docker_image_info.json"
                with open(info_file, 'w') as f:
                    json.dump(image_info, f, indent=2)

                return info_file
            else:
                print(f"✗ Enhanced Docker build failed: {result.stderr}")
                return None

        except Exception as e:
            print(f"✗ Enhanced Docker image creation error: {e}")
            return None

    def generate_build_manifest(self) -> Path:
        """Generate build manifest with all features and configurations."""
        try:
            print("Generating build manifest...")

            manifest = {
                "build_info": {
                    "version": self.config["version"],
                    "build_date": self.config["build_date"],
                    "platform": platform.system(),
                    "architecture": platform.machine(),
                    "python_version": sys.version,
                },
                "features": self.features,
                "security": self.config["security"],
                "optimization": self.config["optimization"],
                "files": {}
            }

            # Generate checksums for distribution files
            if self.dist_dir.exists():
                for file_path in self.dist_dir.iterdir():
                    if file_path.is_file():
                        checksum = self._calculate_checksum(file_path)
                        manifest["files"][file_path.name] = {
                            "size": file_path.stat().st_size,
                            "checksum_sha256": checksum
                        }

            # Save manifest
            manifest_file = self.dist_dir / "build_manifest.json"
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)

            print(f"✓ Build manifest generated: {manifest_file}")
            return manifest_file

        except Exception as e:
            print(f"✗ Build manifest generation error: {e}")
            return None

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""

    def run_enhanced_tests(self) -> bool:
        """Run enhanced test suite including feature tests."""
        try:
            print("Running enhanced tests...")

            # Run standard tests
            test_result = subprocess.run([
                sys.executable, "-m", "pytest",
                "tests/",
                "--tb=short",
                "-q",
                "--durations=10"
            ], cwd=self.project_root, capture_output=True, text=True)

            if test_result.returncode != 0:
                print(f"✗ Standard tests failed: {test_result.stderr}")
                return False

            # Run feature-specific tests if features are enabled
            feature_tests = []

            if self.features['file_transfer']:
                feature_tests.append("tests/test_messaging.py")

            if self.features['voice_calls']:
                feature_tests.append("tests/test_communication.py")

            if self.features['performance_monitoring']:
                feature_tests.append("tests/test_performance.py")

            if self.features['security_testing']:
                feature_tests.append("tests/test_security.py")

            if feature_tests:
                print("Running feature-specific tests...")
                test_result = subprocess.run([
                    sys.executable, "-m", "pytest",
                    *feature_tests,
                    "--tb=short",
                    "-q"
                ], cwd=self.project_root, capture_output=True, text=True)

                if test_result.returncode != 0:
                    print(f"✗ Feature tests failed: {test_result.stderr}")
                    return False

            print("✓ All enhanced tests passed")
            return True

        except Exception as e:
            print(f"✗ Enhanced test execution error: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Enhanced Build System for Privatus-chat")
    parser.add_argument("--platform", choices=["windows", "linux", "darwin", "all"],
                        help="Target platform (default: current platform)")
    parser.add_argument("--skip-tests", action="store_true",
                        help="Skip running tests before building")
    parser.add_argument("--skip-features", action="store_true",
                        help="Skip feature verification")
    parser.add_argument("--clean", action="store_true",
                        help="Clean build artifacts first")
    parser.add_argument("--installer-only", action="store_true",
                        help="Only create platform packages, don't build executable")
    parser.add_argument("--enable-feature", action="append",
                        choices=["file_transfer", "voice_calls", "performance_monitoring",
                                "security_testing", "gui_enhancements", "crypto_optimizations"],
                        help="Enable specific features")
    parser.add_argument("--disable-feature", action="append",
                        choices=["file_transfer", "voice_calls", "performance_monitoring",
                                "security_testing", "gui_enhancements", "crypto_optimizations"],
                        help="Disable specific features")
    parser.add_argument("--docker-only", action="store_true",
                        help="Only build Docker image")
    parser.add_argument("--manifest-only", action="store_true",
                        help="Only generate build manifest")

    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    builder = ProductionBuilder(project_root)

    # Handle feature flags
    if args.enable_feature:
        for feature in args.enable_feature:
            builder.features[feature] = True

    if args.disable_feature:
        for feature in args.disable_feature:
            builder.features[feature] = False

    # Save updated configuration
    builder._save_build_config()

    if args.clean:
        builder.clean_build_artifacts()

    # Run enhanced tests unless skipped
    if not args.skip_tests and not args.installer_only and not args.manifest_only:
        if not builder.run_enhanced_tests():
            print("✗ Aborting build due to test failures")
            sys.exit(1)

    # Verify features unless skipped
    if not args.skip_features and not args.manifest_only:
        if not builder.verify_features():
            print("✗ Aborting build due to feature verification failure")
            sys.exit(1)

    # Build enhanced executable unless installer-only or manifest-only
    if not args.installer_only and not args.manifest_only:
        if not builder.build_with_features(args.platform):
            print("✗ Aborting due to enhanced build failure")
            sys.exit(1)

    # Create platform-specific packages
    if not args.docker_only and not args.manifest_only:
        created_packages = builder.create_platform_packages(args.platform)
        if not created_packages and not args.installer_only:
            print("⚠️ No platform packages were created")

    # Create Docker image
    if not args.manifest_only:
        docker_image = builder._create_enhanced_docker_image()
        if docker_image:
            print(f"✓ Docker image info: {docker_image}")

    # Generate build manifest
    manifest_file = builder.generate_build_manifest()
    if manifest_file:
        print(f"✓ Build manifest: {manifest_file}")

    # Handle specific build modes
    if args.docker_only:
        print("\n🐳 Docker-only build completed successfully!")
        print(f"Docker image info: {builder.dist_dir}/docker_image_info.json")
        print(f"Build manifest: {builder.dist_dir}/build_manifest.json")

    elif args.manifest_only:
        print("\n📋 Manifest-only build completed successfully!")
        print(f"Build manifest: {builder.dist_dir}/build_manifest.json")

    else:
        print("\n🎉 Enhanced production build completed successfully!")
        print(f"Output directory: {builder.dist_dir}")
        print(f"Build manifest: {builder.dist_dir}/build_manifest.json")

        # List created packages
        if 'created_packages' in locals() and created_packages:
            print(f"\n📦 Created {len(created_packages)} packages:")
            for package in created_packages:
                print(f"   • {package.name}")


if __name__ == "__main__":
    main()