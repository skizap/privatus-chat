#!/usr/bin/env python3
"""
Automated Release Management for Privatus-chat

Handles:
- Version bumping and management
- Release notes generation
- Changelog updates
- Tag creation and management
- Release automation
"""

import os
import sys
import subprocess
import shutil
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

class VersionType(Enum):
    """Version bump types."""
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"

@dataclass
class ReleaseInfo:
    """Release information."""
    version: str
    release_type: VersionType
    changes: List[str]
    breaking_changes: List[str]
    features: List[str]
    bug_fixes: List[str]
    release_date: str

class ReleaseManager:
    """Manages releases for Privatus-chat."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.config = self._load_release_config()

    def _load_release_config(self) -> Dict:
        """Load release configuration."""
        config_file = self.project_root / "deployment" / "release_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            return {
                "current_version": "3.0.0",
                "version_prefix": "v",
                "changelog_file": "CHANGELOG.md",
                "release_notes_template": "docs/release_notes_template.md",
                "auto_generate_notes": True,
                "require_tests": True,
                "create_git_tag": True,
                "push_changes": True
            }

    def bump_version(self, version_type: VersionType, pre_release: bool = False) -> str:
        """Bump version number."""
        try:
            current_version = self.config["current_version"]
            major, minor, patch = map(int, current_version.split('.'))

            if version_type == VersionType.MAJOR:
                new_version = f"{major + 1}.0.0"
            elif version_type == VersionType.MINOR:
                new_version = f"{major}.{minor + 1}.0"
            elif version_type == VersionType.PATCH:
                new_version = f"{major}.{minor}.{patch + 1}"

            if pre_release:
                new_version = f"{new_version}-pre"

            # Update configuration
            self.config["current_version"] = new_version

            # Save updated config
            config_file = self.project_root / "deployment" / "release_config.json"
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)

            print(f"✓ Version bumped to {new_version}")
            return new_version

        except Exception as e:
            print(f"✗ Version bump error: {e}")
            return current_version

    def update_version_files(self, new_version: str):
        """Update version in all relevant files."""
        try:
            print(f"Updating version to {new_version} in project files...")

            # Update pyproject.toml
            pyproject_file = self.project_root / "pyproject.toml"
            if pyproject_file.exists():
                content = pyproject_file.read_text()
                # Update version line
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith('version = "'):
                        lines[i] = f'version = "{new_version}"'
                        break
                pyproject_file.write_text('\n'.join(lines))

            # Update __init__.py if it exists
            init_file = self.project_root / "src" / "__init__.py"
            if init_file.exists():
                content = init_file.read_text()
                # Update __version__ if present
                if '__version__' in content:
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if line.strip().startswith('__version__'):
                            lines[i] = f'__version__ = "{new_version}"'
                            break
                    init_file.write_text('\n'.join(lines))

            # Update deployment config files
            for config_file in ["deployment/build_config.json", "deployment/deploy_config.json"]:
                config_path = self.project_root / config_file
                if config_path.exists():
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                    config["version"] = new_version
                    config["build_date"] = datetime.now().isoformat()
                    with open(config_path, 'w') as f:
                        json.dump(config, f, indent=2)

            print("✓ Version updated in all files")

        except Exception as e:
            print(f"✗ Version update error: {e}")

    def generate_release_notes(self, version: str, changes: List[str] = None) -> str:
        """Generate release notes."""
        try:
            print(f"Generating release notes for v{version}...")

            # Collect changes from various sources
            all_changes = []

            if changes:
                all_changes.extend(changes)
            else:
                # Parse git commits for changes
                git_changes = self._get_git_changes()
                all_changes.extend(git_changes)

                # Parse changelog for existing entries
                changelog_changes = self._parse_changelog()
                all_changes.extend(changelog_changes)

            # Categorize changes
            release_info = self._categorize_changes(all_changes)

            # Generate release notes
            notes = self._format_release_notes(version, release_info)

            # Save release notes
            notes_file = self.project_root / "dist" / f"release_notes_v{version}.md"
            notes_file.write_text(notes)

            print(f"✓ Release notes generated: {notes_file}")
            return notes

        except Exception as e:
            print(f"✗ Release notes generation error: {e}")
            return f"# Release v{version}\n\nNew features and improvements."

    def _get_git_changes(self) -> List[str]:
        """Get changes from git commits."""
        changes = []
        try:
            # Get commits since last tag
            result = subprocess.run([
                "git", "log", "--oneline", "--since='1 month ago'"
            ], cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        # Extract commit message
                        commit_msg = line.split(' ', 1)[1] if ' ' in line else line
                        changes.append(commit_msg)

        except Exception:
            pass

        return changes

    def _parse_changelog(self) -> List[str]:
        """Parse existing changelog for changes."""
        changes = []
        try:
            changelog_file = self.project_root / self.config["changelog_file"]
            if changelog_file.exists():
                with open(changelog_file, 'r') as f:
                    content = f.read()

                # Look for unreleased section
                lines = content.split('\n')
                in_unreleased = False

                for line in lines:
                    if line.startswith("## [Unreleased]"):
                        in_unreleased = True
                        continue
                    elif line.startswith("## [") and in_unreleased:
                        break
                    elif in_unreleased and line.startswith("- "):
                        changes.append(line[2:])  # Remove "- " prefix

        except Exception:
            pass

        return changes

    def _categorize_changes(self, changes: List[str]) -> ReleaseInfo:
        """Categorize changes into features, bug fixes, etc."""
        features = []
        bug_fixes = []
        breaking_changes = []
        other_changes = []

        for change in changes:
            change_lower = change.lower()

            if any(keyword in change_lower for keyword in ["break", "breaking", "major"]):
                breaking_changes.append(change)
            elif any(keyword in change_lower for keyword in ["feat", "feature", "add", "new"]):
                features.append(change)
            elif any(keyword in change_lower for keyword in ["fix", "bug", "error", "issue"]):
                bug_fixes.append(change)
            else:
                other_changes.append(change)

        return ReleaseInfo(
            version=self.config["current_version"],
            release_type=VersionType.PATCH,  # Default
            changes=other_changes,
            breaking_changes=breaking_changes,
            features=features,
            bug_fixes=bug_fixes,
            release_date=datetime.now().strftime("%Y-%m-%d")
        )

    def _format_release_notes(self, version: str, release_info: ReleaseInfo) -> str:
        """Format release notes."""
        notes = f"""# Privatus-chat v{version} Release Notes

**Release Date:** {release_info.release_date}

## Overview
New release of Privatus-chat with enhanced features and improvements.

"""

        if release_info.features:
            notes += "## 🚀 New Features\n"
            for feature in release_info.features:
                notes += f"- {feature}\n"
            notes += "\n"

        if release_info.bug_fixes:
            notes += "## 🐛 Bug Fixes\n"
            for fix in release_info.bug_fixes:
                notes += f"- {fix}\n"
            notes += "\n"

        if release_info.breaking_changes:
            notes += "## ⚠️ Breaking Changes\n"
            for change in release_info.breaking_changes:
                notes += f"- {change}\n"
            notes += "\n"

        if release_info.changes:
            notes += "## 📋 Other Changes\n"
            for change in release_info.changes:
                notes += f"- {change}\n"
            notes += "\n"

        notes += """## Installation
See the installation guides for your platform:
- [Windows Installation Guide](docs/user/installation-guide-windows.md)
- [macOS Installation Guide](docs/user/installation-guide-macos.md)
- [Linux Installation Guide](docs/user/installation-guide-linux.md)

## Support
For support and questions:
- [User Guide](docs/user/user-guide.md)
- [FAQ](docs/user/faq.md)
- [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)

---
*Privatus-chat - Secure Anonymous Communication*
"""

        return notes

    def update_changelog(self, version: str, release_notes: str):
        """Update changelog with new release."""
        try:
            print(f"Updating changelog for v{version}...")

            changelog_file = self.project_root / self.config["changelog_file"]

            # Format changelog entry
            today = datetime.now().strftime("%Y-%m-%d")

            changelog_entry = f"""## [{version}] - {today}

{release_notes.split('## Overview')[1].split('## Installation')[0].strip()}

"""

            # Read existing changelog
            if changelog_file.exists():
                with open(changelog_file, 'r') as f:
                    existing_content = f.read()
            else:
                existing_content = "# Changelog\n\nAll notable changes to this project will be documented in this file.\n\n"

            # Insert new entry after header
            header_end = existing_content.find("\n## [")
            if header_end == -1:
                # No version entries yet
                updated_content = existing_content + changelog_entry
            else:
                # Insert after first header
                updated_content = existing_content[:header_end] + changelog_entry + existing_content[header_end:]

            # Write updated changelog
            with open(changelog_file, 'w') as f:
                f.write(updated_content)

            print(f"✓ Changelog updated: {changelog_file}")

        except Exception as e:
            print(f"✗ Changelog update error: {e}")

    def create_git_tag(self, version: str, message: str = None):
        """Create git tag for release."""
        try:
            print(f"Creating git tag for v{version}...")

            if not message:
                message = f"Release v{version}"

            # Create annotated tag
            cmd = [
                "git", "tag", "-a", f"v{version}",
                "-m", message
            ]

            result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✓ Git tag v{version} created")

                # Push tag if configured
                if self.config["push_changes"]:
                    push_cmd = ["git", "push", "origin", f"v{version}"]
                    push_result = subprocess.run(push_cmd, cwd=self.project_root, capture_output=True, text=True)

                    if push_result.returncode == 0:
                        print(f"✓ Git tag v{version} pushed to origin")
                    else:
                        print(f"⚠️ Failed to push tag: {push_result.stderr}")

                return True
            else:
                print(f"✗ Git tag creation failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"✗ Git tag creation error: {e}")
            return False

    def run_pre_release_checks(self) -> bool:
        """Run pre-release checks."""
        try:
            print("Running pre-release checks...")

            checks_passed = True

            # Check if tests pass
            if self.config["require_tests"]:
                print("Running tests...")
                test_result = subprocess.run([
                    sys.executable, "-m", "pytest", "tests/", "--tb=short", "-q"
                ], cwd=self.project_root, capture_output=True, text=True)

                if test_result.returncode != 0:
                    print("✗ Tests failed")
                    checks_passed = False
                else:
                    print("✓ All tests passed")

            # Check if build works
            print("Testing build...")
            build_result = subprocess.run([
                sys.executable, "deployment/build.py", "--manifest-only"
            ], cwd=self.project_root, capture_output=True, text=True)

            if build_result.returncode != 0:
                print("✗ Build failed")
                checks_passed = False
            else:
                print("✓ Build successful")

            # Check git status
            git_status = subprocess.run([
                "git", "status", "--porcelain"
            ], cwd=self.project_root, capture_output=True, text=True)

            if git_status.stdout.strip():
                print("⚠️ Working directory has uncommitted changes")
            else:
                print("✓ Working directory is clean")

            return checks_passed

        except Exception as e:
            print(f"✗ Pre-release checks error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="Release Management for Privatus-chat")
    parser.add_argument("--version-type", choices=["major", "minor", "patch"],
                        default="patch", help="Type of version bump")
    parser.add_argument("--version", help="Specific version number")
    parser.add_argument("--pre-release", action="store_true",
                        help="Mark as pre-release")
    parser.add_argument("--generate-notes", action="store_true",
                        help="Generate release notes")
    parser.add_argument("--update-changelog", action="store_true",
                        help="Update changelog")
    parser.add_argument("--create-tag", action="store_true",
                        help="Create git tag")
    parser.add_argument("--full-release", action="store_true",
                        help="Perform full release process")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done")

    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    release_manager = ReleaseManager(project_root)

    if args.dry_run:
        print("🔍 DRY RUN MODE")
        print(f"Current version: {release_manager.config['current_version']}")
        print(f"Version type: {args.version_type}")
        print(f"Pre-release: {args.pre_release}")
        return

    # Determine new version
    if args.version:
        new_version = args.version
        release_manager.config["current_version"] = new_version
    else:
        new_version = release_manager.bump_version(VersionType(args.version_type), args.pre_release)

    # Full release process
    if args.full_release:
        print(f"🚀 Starting full release process for v{new_version}...")

        # Run pre-release checks
        if not release_manager.run_pre_release_checks():
            print("✗ Pre-release checks failed")
            sys.exit(1)

        # Update version in files
        release_manager.update_version_files(new_version)

        # Generate release notes
        release_notes = release_manager.generate_release_notes(new_version)

        # Update changelog
        release_manager.update_changelog(new_version, release_notes)

        # Create git tag
        if release_manager.config["create_git_tag"]:
            if not release_manager.create_git_tag(new_version, f"Release v{new_version}"):
                print("✗ Git tag creation failed")
                sys.exit(1)

        print(f"\n🎉 Full release process completed for v{new_version}!")

    # Individual steps
    else:
        if args.version_type or args.version:
            release_manager.update_version_files(new_version)

        if args.generate_notes:
            release_notes = release_manager.generate_release_notes(new_version)
            print("Release notes generated. Check dist/ directory.")

        if args.update_changelog:
            release_notes = release_manager.generate_release_notes(new_version)
            release_manager.update_changelog(new_version, release_notes)

        if args.create_tag:
            if not release_manager.create_git_tag(new_version):
                sys.exit(1)

if __name__ == "__main__":
    main()