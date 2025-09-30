#!/usr/bin/env python3
"""
Enhanced Automated Deployment Script for Privatus-chat

Handles cross-platform deployment with:
- Multi-platform package deployment
- Enhanced security and verification
- Automated release management
- Environment-based deployment settings
- Docker container orchestration
- Cloud deployment support
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse
import platform
import tempfile
import hashlib
import time
from datetime import datetime

class DeploymentManager:
    """Enhanced deployment manager for cross-platform deployment."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.dist_dir = project_root / "dist"
        self.deployment_dir = project_root / "deployment"
        self.temp_dir = Path(tempfile.mkdtemp(prefix="privatus_deploy_"))
        self.config = self._load_enhanced_deployment_config()

        # Deployment targets
        self.supported_platforms = ["windows", "linux", "darwin"]
        self.supported_targets = ["github", "pypi", "docker", "local", "aws", "azure", "gcp"]

    def _load_enhanced_deployment_config(self) -> Dict:
        """Load enhanced deployment configuration."""
        config_file = self.deployment_dir / "deploy_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            # Enhanced default configuration
            return {
                "version": "3.0.0",
                "build_date": datetime.now().isoformat(),
                "platforms": ["linux", "windows", "darwin"],
                "deployment_targets": {
                    "github": {
                        "enabled": True,
                        "repository": "privatus-chat/privatus-chat",
                        "create_release": True,
                        "draft_release": False,
                        "pre_release": False
                    },
                    "pypi": {
                        "enabled": False,
                        "repository": "privatus-chat"
                    },
                    "docker": {
                        "enabled": True,
                        "registry": "docker.io",
                        "repository": "privatus-chat/privatus-chat",
                        "multi_arch": True
                    },
                    "local": {
                        "enabled": True,
                        "install_path": "/opt/privatus-chat"
                    }
                },
                "security": {
                    "verify_packages": True,
                    "sign_packages": False,
                    "key_id": None,
                    "require_checksums": True
                },
                "notifications": {
                    "slack_webhook": None,
                    "discord_webhook": None,
                    "email_notifications": False
                },
                "rollback": {
                    "enabled": True,
                    "backup_count": 5
                }
            }

    def deploy_cross_platform(self, version: str, platforms: List[str] = None) -> bool:
        """Deploy to multiple platforms."""
        try:
            print(f"🚀 Starting cross-platform deployment for v{version}...")

            if not platforms:
                platforms = self.config["platforms"]

            success = True
            deployment_results = {}

            for platform_name in platforms:
                print(f"\n📦 Deploying for {platform_name}...")

                # Deploy to each platform
                platform_success = self._deploy_to_platform(platform_name, version)
                deployment_results[platform_name] = platform_success

                if not platform_success:
                    success = False
                    print(f"❌ Deployment failed for {platform_name}")
                else:
                    print(f"✅ Deployment successful for {platform_name}")

            # Send deployment notifications
            self._send_deployment_notifications(version, deployment_results)

            return success

        except Exception as e:
            print(f"✗ Cross-platform deployment error: {e}")
            return False

    def _deploy_to_platform(self, platform_name: str, version: str) -> bool:
        """Deploy to a specific platform."""
        try:
            platform_success = True

            # Deploy to GitHub Releases
            if self.config["deployment_targets"]["github"]["enabled"]:
                if not self.deploy_to_github_releases(version):
                    platform_success = False

            # Deploy to Docker Registry
            if self.config["deployment_targets"]["docker"]["enabled"]:
                if not self.deploy_to_docker_registry(version, platform_name):
                    platform_success = False

            # Deploy locally
            if self.config["deployment_targets"]["local"]["enabled"]:
                if not self.deploy_locally(platform_name, version):
                    platform_success = False

            return platform_success

        except Exception as e:
            print(f"✗ Platform deployment error for {platform_name}: {e}")
            return False

    def deploy_to_docker_registry(self, version: str, platform_name: str = None) -> bool:
        """Deploy to Docker registry with multi-platform support."""
        try:
            print("🐳 Deploying to Docker registry...")

            if not self.config["deployment_targets"]["docker"]["enabled"]:
                print("Docker deployment disabled in config")
                return True

            docker_config = self.config["deployment_targets"]["docker"]
            registry = docker_config["registry"]
            repository = docker_config["repository"]

            # Build and tag Docker image
            image_name = f"{repository}:{version}"
            full_image_name = f"{registry}/{image_name}"

            # Check if multi-platform build is requested
            if docker_config.get("multi_arch", False) and platform_name:
                # Build for specific platform
                platform_spec = self._get_docker_platform_spec(platform_name)
                cmd = [
                    "docker", "build",
                    "--platform", platform_spec,
                    "-t", full_image_name,
                    "-f", "deployment/Dockerfile.multistage",
                    "."
                ]
            else:
                # Build for current platform
                cmd = [
                    "docker", "build",
                    "-t", full_image_name,
                    "-f", "deployment/Dockerfile.multistage",
                    "."
                ]

            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"✗ Docker build failed: {result.stderr}")
                return False

            # Push to registry
            push_cmd = ["docker", "push", full_image_name]
            result = subprocess.run(push_cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✓ Docker image pushed: {full_image_name}")

                # Create additional tags
                self._create_docker_tags(full_image_name, version)
                return True
            else:
                print(f"✗ Docker push failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ Docker deployment error: {e}")
            return False

    def _get_docker_platform_spec(self, platform_name: str) -> str:
        """Get Docker platform specification."""
        platform_map = {
            "linux": "linux/amd64",
            "windows": "windows/amd64",
            "darwin": "linux/amd64"  # Use Linux for macOS builds
        }
        return platform_map.get(platform_name, "linux/amd64")

    def _create_docker_tags(self, image_name: str, version: str):
        """Create additional Docker tags."""
        try:
            # Tag as latest
            latest_name = image_name.replace(f":{version}", ":latest")
            subprocess.run(["docker", "tag", image_name, latest_name], check=True)

            # Tag with major.minor
            major_minor = version.rsplit(".", 1)[0]
            minor_name = image_name.replace(f":{version}", f":{major_minor}")
            subprocess.run(["docker", "tag", image_name, minor_name], check=True)

            # Push additional tags
            for tag in [latest_name, minor_name]:
                subprocess.run(["docker", "push", tag], check=True)

        except Exception as e:
            print(f"⚠️ Failed to create additional Docker tags: {e}")

    def deploy_locally(self, platform_name: str, version: str) -> bool:
        """Deploy locally for testing."""
        try:
            print(f"💻 Deploying locally for {platform_name}...")

            if not self.config["deployment_targets"]["local"]["enabled"]:
                print("Local deployment disabled in config")
                return True

            install_path = Path(self.config["deployment_targets"]["local"]["install_path"])

            # Create installation directory
            app_install_path = install_path / f"privatus-chat-{version}"
            app_install_path.mkdir(parents=True, exist_ok=True)

            # Copy distribution files
            if self.dist_dir.exists():
                for dist_file in self.dist_dir.iterdir():
                    if dist_file.is_file() and platform_name in dist_file.name.lower():
                        shutil.copy2(dist_file, app_install_path / dist_file.name)

            # Create symbolic link for current version
            current_link = install_path / "current"
            if current_link.exists():
                current_link.unlink()
            current_link.symlink_to(app_install_path)

            print(f"✓ Local deployment completed: {app_install_path}")
            return True

        except Exception as e:
            print(f"✗ Local deployment error: {e}")
            return False

    def verify_deployment_packages(self) -> bool:
        """Verify deployment packages integrity."""
        try:
            print("🔍 Verifying deployment packages...")

            if not self.dist_dir.exists():
                print("✗ Distribution directory not found")
                return False

            verification_passed = True

            # Check for build manifest
            manifest_file = self.dist_dir / "build_manifest.json"
            if not manifest_file.exists():
                print("⚠️ Build manifest not found")
                verification_passed = False
            else:
                # Verify file checksums
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)

                for filename, file_info in manifest.get("files", {}).items():
                    file_path = self.dist_dir / filename
                    if file_path.exists():
                        current_checksum = self._calculate_file_checksum(file_path)
                        expected_checksum = file_info.get("checksum_sha256")

                        if current_checksum != expected_checksum:
                            print(f"✗ Checksum mismatch for {filename}")
                            verification_passed = False
                        else:
                            print(f"✓ Verified {filename}")
                    else:
                        print(f"⚠️ File not found: {filename}")
                        verification_passed = False

            if verification_passed:
                print("✓ All deployment packages verified")
            else:
                print("✗ Package verification failed")

            return verification_passed

        except Exception as e:
            print(f"✗ Package verification error: {e}")
            return False

    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""

    def _send_deployment_notifications(self, version: str, results: Dict[str, bool]):
        """Send deployment notifications."""
        try:
            notifications = self.config.get("notifications", {})

            # Slack notification
            slack_webhook = notifications.get("slack_webhook")
            if slack_webhook:
                self._send_slack_notification(slack_webhook, version, results)

            # Discord notification
            discord_webhook = notifications.get("discord_webhook")
            if discord_webhook:
                self._send_discord_notification(discord_webhook, version, results)

        except Exception as e:
            print(f"⚠️ Notification sending failed: {e}")

    def _send_slack_notification(self, webhook: str, version: str, results: Dict[str, bool]):
        """Send Slack notification."""
        try:
            import requests

            success_count = sum(results.values())
            total_count = len(results)

            message = {
                "text": f"🚀 Privatus-chat v{version} deployed!",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚀 Deployment Complete: v{version}"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Success:* {success_count}/{total_count} platforms"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\n".join([
                                f"• {platform}: {'✅' if success else '❌'}"
                                for platform, success in results.items()
                            ])
                        }
                    }
                ]
            }

            response = requests.post(webhook, json=message, timeout=10)
            response.raise_for_status()

        except Exception as e:
            print(f"⚠️ Slack notification failed: {e}")

    def _send_discord_notification(self, webhook: str, version: str, results: Dict[str, bool]):
        """Send Discord notification."""
        try:
            import requests

            success_count = sum(results.values())
            total_count = len(results)

            embed = {
                "title": f"🚀 Privatus-chat v{version} Deployed",
                "description": f"Successfully deployed to {success_count}/{total_count} platforms",
                "fields": [
                    {
                        "name": "Platform Results",
                        "value": "\n".join([
                            f"• {platform}: {'✅' if success else '❌'}"
                            for platform, success in results.items()
                        ]),
                        "inline": False
                    }
                ],
                "timestamp": datetime.now().isoformat()
            }

            message = {"embeds": [embed]}
            response = requests.post(webhook, json=message, timeout=10)
            response.raise_for_status()

        except Exception as e:
            print(f"⚠️ Discord notification failed: {e}")

    def cleanup_deployment_artifacts(self):
        """Clean up deployment artifacts."""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            print("✓ Deployment artifacts cleaned")
        except Exception as e:
            print(f"✗ Cleanup error: {e}")

    def deploy_to_github_releases(self, version: str, release_notes: str = None) -> bool:
        """Deploy to GitHub Releases."""
        try:
            print("Deploying to GitHub Releases...")

            if not self.config["deployment_targets"]["github"]["enabled"]:
                print("GitHub deployment disabled in config")
                return True

            # Check if gh CLI is available
            if not self._check_gh_cli():
                print("GitHub CLI not found. Please install it first.")
                return False

            # Create release
            repo = self.config["deployment_targets"]["github"]["repository"]
            tag = f"v{version}"

            cmd = ["gh", "release", "create", tag]

            # Add release notes if provided
            if release_notes:
                # Write notes to temp file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
                    f.write(release_notes)
                    notes_file = f.name

                cmd.extend(["--notes-file", notes_file])
            else:
                cmd.append("--generate-notes")

            # Add release title
            cmd.extend(["--title", f"Privatus-chat v{version}"])

            # Add files
            release_files = self._get_release_files()
            cmd.extend(release_files)

            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            # Clean up temp file
            if release_notes and 'notes_file' in locals():
                os.unlink(notes_file)

            if result.returncode == 0:
                print(f"✓ Release {tag} created successfully")
                return True
            else:
                print(f"✗ GitHub release failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ GitHub deployment error: {e}")
            return False

    def _check_gh_cli(self) -> bool:
        """Check if GitHub CLI is available."""
        try:
            result = subprocess.run(["gh", "--version"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _get_release_files(self) -> List[str]:
        """Get list of files to include in release."""
        files = []

        # Add platform-specific packages
        for platform_name in self.config["platforms"]:
            if platform_name == "linux":
                linux_files = [
                    "privatus-chat-linux.tar.gz",
                    "privatus-chat-deployment-linux.zip"
                ]
                for file in linux_files:
                    if (self.dist_dir / file).exists():
                        files.append(str(self.dist_dir / file))

            elif platform_name == "windows":
                windows_files = [
                    "privatus-chat-windows.zip",
                    "privatus-chat-deployment-windows.zip"
                ]
                for file in windows_files:
                    if (self.dist_dir / file).exists():
                        files.append(str(self.dist_dir / file))

            elif platform_name == "darwin":
                macos_files = [
                    "privatus-chat-macos.zip",
                    "privatus-chat-deployment-darwin.zip"
                ]
                for file in macos_files:
                    if (self.dist_dir / file).exists():
                        files.append(str(self.dist_dir / file))

        return files

    def deploy_to_pypi(self) -> bool:
        """Deploy to PyPI."""
        try:
            print("Deploying to PyPI...")

            if not self.config["deployment_targets"]["pypi"]["enabled"]:
                print("PyPI deployment disabled in config")
                return True

            # Build wheel and source distribution
            build_cmd = [sys.executable, "-m", "build"]
            result = subprocess.run(build_cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"✗ Build failed: {result.stderr}")
                return False

            # Upload to PyPI
            upload_cmd = [sys.executable, "-m", "twine", "upload", "dist/*"]
            result = subprocess.run(upload_cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print("✓ PyPI upload successful")
                return True
            else:
                print(f"✗ PyPI upload failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ PyPI deployment error: {e}")
            return False

    def create_docker_image(self, version: str) -> bool:
        """Create Docker image for deployment."""
        try:
            print("Creating Docker image...")

            dockerfile = self.project_root / "deployment" / "Dockerfile"
            if not dockerfile.exists():
                print("Dockerfile not found in deployment directory")
                return False

            # Build Docker image
            image_name = f"privatus-chat:{version}"
            cmd = ["docker", "build", "-t", image_name, "-f", str(dockerfile), "."]

            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✓ Docker image {image_name} created successfully")
                return True
            else:
                print(f"✗ Docker build failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ Docker image creation error: {e}")
            return False

    def sign_release_files(self) -> bool:
        """Sign release files with GPG."""
        try:
            print("Signing release files...")

            if not self.config["signing"]["enabled"]:
                print("File signing disabled in config")
                return True

            key_id = self.config["signing"]["key_id"]
            if not key_id:
                print("GPG key ID not configured")
                return False

            release_files = self._get_release_files()

            for file_path in release_files:
                if os.path.exists(file_path):
                    cmd = ["gpg", "--detach-sign", "--armor", "-u", key_id, file_path]
                    result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

                    if result.returncode != 0:
                        print(f"✗ Failed to sign {file_path}: {result.stderr}")
                        return False

            print("✓ All release files signed successfully")
            return True

        except Exception as e:
            print(f"✗ File signing error: {e}")
            return False

    def run_deployment_checks(self) -> bool:
        """Run pre-deployment checks."""
        print("Running deployment checks...")

        checks_passed = True

        # Check if dist directory exists and has files
        if not self.dist_dir.exists():
            print("✗ Distribution directory not found")
            checks_passed = False
        else:
            dist_files = list(self.dist_dir.glob("*"))
            if not dist_files:
                print("✗ No distribution files found")
                checks_passed = False
            else:
                print(f"✓ Found {len(dist_files)} distribution files")

        # Check version consistency
        version_file = self.project_root / "pyproject.toml"
        if version_file.exists():
            with open(version_file, 'r') as f:
                content = f.read()
                if f'version = "{self.config["version"]}"' not in content:
                    print("✗ Version mismatch between config and pyproject.toml")
                    checks_passed = False
                else:
                    print("✓ Version consistency check passed")

        # Check if tests pass
        print("Running tests...")
        test_result = subprocess.run([
            sys.executable, "-m", "pytest", "tests/", "--tb=short", "-q"
        ], cwd=self.project_root, capture_output=True, text=True)

        if test_result.returncode != 0:
            print("✗ Tests failed - aborting deployment")
            checks_passed = False
        else:
            print("✓ All tests passed")

        return checks_passed

    def generate_release_notes(self, version: str) -> str:
        """Generate release notes from changelog."""
        changelog_file = self.project_root / "CHANGELOG.md"
        if not changelog_file.exists():
            return f"Release v{version}\n\nNew features and improvements."

        with open(changelog_file, 'r') as f:
            content = f.read()

        # Simple parsing - look for version section
        lines = content.split('\n')
        notes = []
        in_version_section = False

        for line in lines:
            if line.startswith(f"## [{version}]"):
                in_version_section = True
                continue
            elif line.startswith("## [") and in_version_section:
                break
            elif in_version_section:
                notes.append(line)

        if notes:
            return f"## Release v{version}\n\n" + "\n".join(notes)
        else:
            return f"Release v{version}\n\nNew features and improvements."

    def run_enhanced_deployment_checks(self) -> bool:
        """Run enhanced pre-deployment checks."""
        print("Running enhanced deployment checks...")

        checks_passed = True

        # Check if dist directory exists and has files
        if not self.dist_dir.exists():
            print("✗ Distribution directory not found")
            checks_passed = False
        else:
            dist_files = list(self.dist_dir.glob("*"))
            if not dist_files:
                print("✗ No distribution files found")
                checks_passed = False
            else:
                print(f"✓ Found {len(dist_files)} distribution files")

        # Check version consistency
        version_file = self.project_root / "pyproject.toml"
        if version_file.exists():
            with open(version_file, 'r') as f:
                content = f.read()
                if f'version = "{self.config["version"]}"' not in content:
                    print("✗ Version mismatch between config and pyproject.toml")
                    checks_passed = False
                else:
                    print("✓ Version consistency check passed")

        # Check if tests pass
        print("Running tests...")
        test_result = subprocess.run([
            sys.executable, "-m", "pytest", "tests/", "--tb=short", "-q"
        ], cwd=self.project_root, capture_output=True, text=True)

        if test_result.returncode != 0:
            print("✗ Tests failed - aborting deployment")
            checks_passed = False
        else:
            print("✓ All tests passed")

        # Check build manifest
        manifest_file = self.dist_dir / "build_manifest.json"
        if not manifest_file.exists():
            print("⚠️ Build manifest not found - run build first")
            checks_passed = False
        else:
            print("✓ Build manifest found")

        return checks_passed

    def rollback_deployment(self, current_version: str) -> bool:
        """Rollback to previous version."""
        try:
            print(f"Rolling back from v{current_version}...")

            if not self.config["rollback"]["enabled"]:
                print("Rollback disabled in config")
                return True

            # Find previous version
            changelog_file = self.project_root / "CHANGELOG.md"
            if not changelog_file.exists():
                print("✗ Changelog not found for rollback")
                return False

            # Parse changelog to find previous version
            with open(changelog_file, 'r') as f:
                content = f.read()

            # Simple parsing for previous version
            lines = content.split('\n')
            previous_version = None

            for line in lines:
                if line.startswith("## [") and line != f"## [{current_version}]":
                    # Extract version from line like "## [1.0.0]"
                    import re
                    match = re.search(r'## \[([^\]]+)\]', line)
                    if match:
                        previous_version = match.group(1)
                        break

            if not previous_version:
                print("✗ Could not find previous version for rollback")
                return False

            print(f"Found previous version: {previous_version}")

            # Deploy previous version
            success = self.deploy_cross_platform(previous_version)

            if success:
                print(f"✓ Successfully rolled back to v{previous_version}")
            else:
                print(f"✗ Rollback to v{previous_version} failed")

            return success

        except Exception as e:
            print(f"✗ Rollback error: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Enhanced Deployment System for Privatus-chat")
    parser.add_argument("--version", required=True, help="Version to deploy")
    parser.add_argument("--platform", nargs="+",
                        choices=["windows", "linux", "darwin", "all"],
                        help="Platforms to deploy to (default: all)")
    parser.add_argument("--target", nargs="+",
                        choices=["github", "pypi", "docker", "local", "aws", "azure", "gcp"],
                        help="Deployment targets (default: github,docker,local)")
    parser.add_argument("--github", action="store_true", help="Deploy to GitHub Releases")
    parser.add_argument("--pypi", action="store_true", help="Deploy to PyPI")
    parser.add_argument("--docker", action="store_true", help="Deploy to Docker registry")
    parser.add_argument("--local", action="store_true", help="Deploy locally")
    parser.add_argument("--cross-platform", action="store_true",
                        help="Deploy to all platforms")
    parser.add_argument("--sign", action="store_true", help="Sign release files")
    parser.add_argument("--verify", action="store_true", help="Verify package integrity")
    parser.add_argument("--skip-checks", action="store_true", help="Skip pre-deployment checks")
    parser.add_argument("--release-notes", help="Path to release notes file")
    parser.add_argument("--rollback", action="store_true", help="Rollback to previous version")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deployed")

    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    deployer = DeploymentManager(project_root)

    # Update deployment configuration
    deployer.config["version"] = args.version
    deployer.config["build_date"] = datetime.now().isoformat()

    # Determine deployment targets
    if args.cross_platform:
        deployment_targets = ["github", "docker", "local"]
    elif args.target:
        deployment_targets = args.target
    else:
        deployment_targets = []
        if args.github:
            deployment_targets.append("github")
        if args.pypi:
            deployment_targets.append("pypi")
        if args.docker:
            deployment_targets.append("docker")
        if args.local:
            deployment_targets.append("local")
        if not deployment_targets:
            deployment_targets = ["github", "docker", "local"]  # Default

    # Load release notes if provided
    release_notes = None
    if args.release_notes:
        notes_file = Path(args.release_notes)
        if notes_file.exists():
            with open(notes_file, 'r') as f:
                release_notes = f.read()
        else:
            print(f"Release notes file not found: {args.release_notes}")
            sys.exit(1)
    else:
        # Generate release notes automatically
        release_notes = deployer.generate_release_notes(args.version)

    # Dry run mode
    if args.dry_run:
        print("🔍 DRY RUN MODE")
        print(f"Version: {args.version}")
        print(f"Platforms: {args.platform or ['all']}")
        print(f"Targets: {deployment_targets}")
        print(f"Release notes: {release_notes[:100]}...")
        return

    # Run pre-deployment checks
    if not args.skip_checks:
        if not deployer.run_enhanced_deployment_checks():
            print("✗ Pre-deployment checks failed")
            sys.exit(1)

    # Verify packages if requested
    if args.verify:
        if not deployer.verify_deployment_packages():
            print("✗ Package verification failed")
            sys.exit(1)

    success = True

    try:
        # Sign files if requested
        if args.sign:
            if not deployer.sign_release_files():
                success = False

        # Cross-platform deployment
        if args.cross_platform or (args.platform and "all" in args.platform):
            if not deployer.deploy_cross_platform(args.version):
                success = False
        else:
            # Platform-specific deployment
            platforms = args.platform or ["linux", "windows", "darwin"]

            for platform_name in platforms:
                if platform_name in deployer.supported_platforms:
                    if not deployer._deploy_to_platform(platform_name, args.version):
                        success = False

        # Target-specific deployment
        for target in deployment_targets:
            if target == "github" and deployer.config["deployment_targets"]["github"]["enabled"]:
                if not deployer.deploy_to_github_releases(args.version, release_notes):
                    success = False
            elif target == "pypi" and deployer.config["deployment_targets"]["pypi"]["enabled"]:
                if not deployer.deploy_to_pypi():
                    success = False
            elif target == "docker" and deployer.config["deployment_targets"]["docker"]["enabled"]:
                if not deployer.deploy_to_docker_registry(args.version):
                    success = False
            elif target == "local" and deployer.config["deployment_targets"]["local"]["enabled"]:
                if not deployer.deploy_locally("linux", args.version):
                    success = False

        # Rollback if requested
        if args.rollback:
            if not deployer.rollback_deployment(args.version):
                success = False

    finally:
        deployer.cleanup_deployment_artifacts()

    if success:
        print("\n🎉 Enhanced deployment completed successfully!")
        print(f"Version: {args.version}")
        print(f"Platforms: {args.platform or ['all']}")
        print(f"Targets: {deployment_targets}")
    else:
        print("\n❌ Enhanced deployment completed with errors!")
        sys.exit(1)


if __name__ == "__main__":
    main()