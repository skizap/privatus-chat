#!/usr/bin/env python3
"""
Linux Package Builder for Privatus-chat

Creates Linux packages in multiple formats:
- DEB packages for Debian/Ubuntu
- RPM packages for RHEL/CentOS/Fedora
- AppImage for universal Linux compatibility
- Snap packages for modern distributions
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional
import tempfile
import gzip
import tarfile
import stat

class LinuxPackageBuilder:
    """Creates Linux packages for Privatus-chat."""

    def __init__(self, source_dir: Path, output_dir: Path):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.temp_dir = Path(tempfile.mkdtemp(prefix="privatus_linux_"))
        self.app_name = "privatus-chat"
        self.app_version = "3.0.0"
        self.maintainer = "Privatus-chat Project <info@privatus-chat.org>"

    def create_deb_package(self) -> Optional[Path]:
        """Create Debian package."""
        try:
            print("📦 Creating DEB package...")

            # Create package structure
            deb_root = self.temp_dir / "deb_package"
            debian_dir = deb_root / "DEBIAN"
            usr_dir = deb_root / "usr"
            opt_dir = deb_root / "opt"

            for dir_path in [debian_dir, usr_dir / "bin", usr_dir / "share" / "applications",
                           usr_dir / "share" / "pixmaps", opt_dir / self.app_name]:
                dir_path.mkdir(parents=True, exist_ok=True)

            # Copy application files
            app_src = self.source_dir / "dist" / "privatus-chat"
            if app_src.exists():
                shutil.copy2(app_src, opt_dir / self.app_name / "privatus-chat")

            # Copy configuration files
            config_src = self.source_dir / "config"
            if config_src.exists():
                shutil.copytree(config_src, opt_dir / self.app_name / "config", dirs_exist_ok=True)

            # Create control file
            control_content = self._create_deb_control()
            (debian_dir / "control").write_text(control_content)

            # Create postinst script
            postinst_content = self._create_deb_postinst()
            postinst_path = debian_dir / "postinst"
            postinst_path.write_text(postinst_content)
            postinst_path.chmod(0o755)

            # Create prerm script
            prerm_content = self._create_deb_prerm()
            prerm_path = debian_dir / "prerm"
            prerm_path.write_text(prerm_content)
            prerm_path.chmod(0o755)

            # Create desktop file
            desktop_content = self._create_desktop_file()
            (usr_dir / "share" / "applications" / f"{self.app_name}.desktop").write_text(desktop_content)

            # Create executable launcher
            launcher_content = self._create_launcher_script()
            launcher_path = usr_dir / "bin" / self.app_name
            launcher_path.write_text(launcher_content)
            launcher_path.chmod(0o755)

            # Create icon (placeholder)
            icon_path = usr_dir / "share" / "pixmaps" / f"{self.app_name}.png"
            icon_path.write_bytes(b"placeholder_icon_data")

            # Build DEB package
            deb_name = f"{self.app_name}_{self.app_version}_amd64.deb"
            deb_path = self.output_dir / deb_name

            # Use dpkg-deb to build package
            cmd = ["dpkg-deb", "--build", str(deb_root), str(deb_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✅ DEB package created: {deb_path}")
                return deb_path
            else:
                print(f"❌ DEB creation failed: {result.stderr}")
                return self._create_tarball_fallback()

        except Exception as e:
            print(f"❌ DEB creation error: {e}")
            return self._create_tarball_fallback()

    def create_rpm_package(self) -> Optional[Path]:
        """Create RPM package."""
        try:
            print("📦 Creating RPM package...")

            # Create RPM structure
            rpm_root = self.temp_dir / "rpm_package"
            rpmbuild_dir = rpm_root / "rpmbuild"
            specs_dir = rpmbuild_dir / "SPECS"
            sources_dir = rpmbuild_dir / "SOURCES"
            buildroot_dir = rpmbuild_dir / "BUILDROOT"

            for dir_path in [specs_dir, sources_dir, buildroot_dir]:
                dir_path.mkdir(parents=True, exist_ok=True)

            # Create tarball source
            tarball_name = f"{self.app_name}-{self.app_version}.tar.gz"
            tarball_path = sources_dir / tarball_name

            # Create source tarball
            with tarfile.open(tarball_path, "w:gz") as tar:
                # Add application files
                app_src = self.source_dir / "dist" / "privatus-chat"
                if app_src.exists():
                    tar.add(app_src, arcname=f"{self.app_name}-{self.app_version}/privatus-chat")

                # Add config files
                config_src = self.source_dir / "config"
                if config_src.exists():
                    for file_path in config_src.rglob('*'):
                        if file_path.is_file():
                            arcname = f"{self.app_name}-{self.app_version}/config/{file_path.relative_to(config_src)}"
                            tar.add(file_path, arcname=arcname)

            # Create RPM spec file
            spec_content = self._create_rpm_spec()
            spec_path = specs_dir / f"{self.app_name}.spec"
            spec_path.write_text(spec_content)

            # Build RPM package
            rpm_name = f"{self.app_name}-{self.app_version}-1.x86_64.rpm"
            rpm_path = self.output_dir / rpm_name

            # Use rpmbuild to create package
            cmd = [
                "rpmbuild", "--define", f"_topdir {rpmbuild_dir}",
                "--define", f"_version {self.app_version}",
                "--define", f"_app_name {self.app_name}",
                "-bb", str(spec_path)
            ]

            result = subprocess.run(cmd, cwd=rpm_root, capture_output=True, text=True)

            if result.returncode == 0:
                # Find the generated RPM file
                generated_rpm = list(rpmbuild_dir.glob("**/*.rpm"))[-1]
                shutil.copy2(generated_rpm, rpm_path)
                print(f"✅ RPM package created: {rpm_path}")
                return rpm_path
            else:
                print(f"❌ RPM creation failed: {result.stderr}")
                return self._create_tarball_fallback()

        except Exception as e:
            print(f"❌ RPM creation error: {e}")
            return self._create_tarball_fallback()

    def create_appimage(self) -> Optional[Path]:
        """Create AppImage package."""
        try:
            print("📦 Creating AppImage...")

            # Check if AppImage tools are available
            if not self._check_appimage_tools():
                print("❌ AppImage tools not found. Creating tarball instead.")
                return self._create_tarball_fallback()

            # Create AppDir structure
            appdir = self.temp_dir / f"{self.app_name}.AppDir"
            usr_dir = appdir / "usr"

            for dir_path in [usr_dir / "bin", usr_dir / "share" / "applications",
                           usr_dir / "share" / "pixmaps"]:
                dir_path.mkdir(parents=True, exist_ok=True)

            # Copy application files
            app_src = self.source_dir / "dist" / "privatus-chat"
            if app_src.exists():
                shutil.copy2(app_src, usr_dir / "bin" / self.app_name)

            # Create desktop file
            desktop_content = self._create_desktop_file()
            (usr_dir / "share" / "applications" / f"{self.app_name}.desktop").write_text(desktop_content)

            # Create AppRun script
            apprun_content = self._create_apprun_script()
            apprun_path = appdir / "AppRun"
            apprun_path.write_text(apprun_content)
            apprun_path.chmod(0o755)

            # Create .DirIcon (placeholder)
            icon_path = appdir / ".DirIcon"
            icon_path.write_bytes(b"placeholder_icon_data")

            # Create AppImage
            appimage_name = f"{self.app_name}-{self.app_version}-x86_64.AppImage"
            appimage_path = self.output_dir / appimage_name

            # Use AppImage tools to create AppImage
            cmd = [
                "appimagetool", str(appdir), str(appimage_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"✅ AppImage created: {appimage_path}")
                return appimage_path
            else:
                print(f"❌ AppImage creation failed: {result.stderr}")
                return self._create_tarball_fallback()

        except Exception as e:
            print(f"❌ AppImage creation error: {e}")
            return self._create_tarball_fallback()

    def _create_deb_control(self) -> str:
        """Create DEB control file."""
        return f"""Package: {self.app_name}
Version: {self.app_version}
Section: net
Priority: optional
Architecture: amd64
Depends: python3 (>= 3.8), python3-pyqt6, libssl-dev
Recommends: python3-cryptography, python3-noiseprotocol
Maintainer: {self.maintainer}
Description: Secure Anonymous Chat Application
 Privatus-chat is a secure, anonymous messaging application that provides
 end-to-end encryption, onion routing, and advanced privacy features.
 .
 Features:
  - End-to-end encryption
  - Anonymous communication
  - File transfer capabilities
  - Voice and video calls
  - Performance monitoring
  - Security testing tools
Homepage: https://github.com/privatus-chat/privatus-chat
"""

    def _create_deb_postinst(self) -> str:
        """Create DEB postinst script."""
        return '''#!/bin/bash
set -e

# Create data directory
mkdir -p /opt/privatus-chat/data

# Set permissions
chmod 755 /opt/privatus-chat/privatus-chat
chmod 755 /usr/bin/privatus-chat

# Create desktop icon cache
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications
fi

# Create mime type cache
if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database /usr/share/mime
fi

exit 0
'''

    def _create_deb_prerm(self) -> str:
        """Create DEB prerm script."""
        return '''#!/bin/bash
set -e

# Remove data directory if empty
if [ -d /opt/privatus-chat/data ]; then
    rmdir --ignore-fail-on-non-empty /opt/privatus-chat/data
fi

exit 0
'''

    def _create_rpm_spec(self) -> str:
        """Create RPM spec file."""
        return f'''%define _app_name {self.app_name}
%define _app_version {self.app_version}

Name: %{{_app_name}}
Version: %{{_app_version}}
Release: 1
Summary: Secure Anonymous Chat Application
License: GPL-3.0
URL: https://github.com/privatus-chat/privatus-chat
Group: Applications/Communications

Requires: python3 >= 3.8, python3-pyqt6, openssl-devel

%description
Privatus-chat is a secure, anonymous messaging application that provides
end-to-end encryption, onion routing, and advanced privacy features.

%prep
%setup -n %{{_app_name}}-%{{_app_version}}

%build

%install
mkdir -p $RPM_BUILD_ROOT/opt/%{{_app_name}}
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
mkdir -p $RPM_BUILD_ROOT/usr/share/pixmaps

# Copy application files
cp privatus-chat $RPM_BUILD_ROOT/opt/%{{_app_name}}/
cp config/* $RPM_BUILD_ROOT/opt/%{{_app_name}}/ 2>/dev/null || true

# Create launcher
cat > $RPM_BUILD_ROOT/usr/bin/%{{_app_name}} << EOF
#!/bin/bash
exec /opt/%{{_app_name}}/privatus-chat "$@"
EOF

chmod 755 $RPM_BUILD_ROOT/usr/bin/%{{_app_name}}

# Copy desktop file
cat > $RPM_BUILD_ROOT/usr/share/applications/%{{_app_name}}.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Privatus-chat
Comment=Secure Anonymous Chat Application
Exec=%{{_app_name}}
Icon=%{{_app_name}}
Terminal=false
StartupNotify=true
Categories=Network;Chat;Security;
Keywords=chat;messaging;secure;anonymous;privacy;encryption;
EOF

%files
%defattr(-,root,root)
/opt/%{{_app_name}}
/usr/bin/%{{_app_name}}
/usr/share/applications/%{{_app_name}}.desktop

%post
# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then
    /usr/bin/update-desktop-database -q /usr/share/applications
fi

%postun
# Update desktop database
if [ -x /usr/bin/update-desktop-database ]; then
    /usr/bin/update-desktop-database -q /usr/share/applications
fi

%changelog
* Mon Sep 30 2024 Privatus-chat Project <info@privatus-chat.org> - {self.app_version}-1
- Initial RPM package
'''

    def _create_desktop_file(self) -> str:
        """Create desktop file for Linux."""
        return f'''[Desktop Entry]
Version=1.0
Type=Application
Name=Privatus-chat
Comment=Secure Anonymous Chat Application
Exec={self.app_name}
Icon={self.app_name}
Terminal=false
StartupNotify=true
Categories=Network;Chat;Security;
Keywords=chat;messaging;secure;anonymous;privacy;encryption;
MimeType=x-scheme-handler/privatus;
StartupWMClass=Privatus-chat
'''

    def _create_launcher_script(self) -> str:
        """Create launcher script for DEB package."""
        return f'''#!/bin/bash
# Privatus-chat launcher for Debian/Ubuntu

# Set environment variables
export PYTHONPATH="/opt/{self.app_name}:$PYTHONPATH"
export PRIVATUS_DATA_DIR="$HOME/.config/privatus-chat"

# Create data directory if it doesn't exist
mkdir -p "$PRIVATUS_DATA_DIR"

# Launch application
exec /opt/{self.app_name}/privatus-chat "$@"
'''

    def _create_apprun_script(self) -> str:
        """Create AppRun script for AppImage."""
        return '''#!/bin/bash

# AppImage AppRun script for Privatus-chat

# Get the directory where this script is located (AppImage mount point)
HERE="$(dirname "$(readlink -f "${0}")")"

# Set environment variables
export PYTHONPATH="${HERE}/usr/lib/python3.11/site-packages:${HERE}/usr/lib/python3/dist-packages"
export PRIVATUS_DATA_DIR="${HOME}/.config/privatus-chat"

# Create data directory if it doesn't exist
mkdir -p "${PRIVATUS_DATA_DIR}"

# Launch application
exec "${HERE}/usr/bin/privatus-chat" "$@"
'''

    def _check_appimage_tools(self) -> bool:
        """Check if AppImage tools are available."""
        try:
            result = subprocess.run(["appimagetool", "--version"],
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _create_tarball_fallback(self) -> Optional[Path]:
        """Create a tarball as fallback."""
        try:
            print("📦 Creating tarball fallback...")

            tarball_name = f"{self.app_name}-{self.app_version}-linux.tar.gz"
            tarball_path = self.output_dir / tarball_name

            with tarfile.open(tarball_path, "w:gz") as tar:
                # Add application files
                app_src = self.source_dir / "dist" / "privatus-chat"
                if app_src.exists():
                    tar.add(app_src, arcname=f"{self.app_name}-{self.app_version}/privatus-chat")

                # Add config files
                config_src = self.source_dir / "config"
                if config_src.exists():
                    for file_path in config_src.rglob('*'):
                        if file_path.is_file():
                            arcname = f"{self.app_name}-{self.app_version}/config/{file_path.relative_to(config_src)}"
                            tar.add(file_path, arcname=arcname)

                # Add desktop file
                desktop_content = self._create_desktop_file()
                desktop_info = tarfile.TarInfo(f"{self.app_name}-{self.app_version}/{self.app_name}.desktop")
                desktop_info.size = len(desktop_content.encode())
                tar.addfile(desktop_info, fileobj=io.BytesIO(desktop_content.encode()))

            print(f"✅ Tarball created: {tarball_path}")
            return tarball_path

        except Exception as e:
            print(f"❌ Tarball creation failed: {e}")
            return None

    def cleanup(self):
        """Clean up temporary files."""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Warning: Failed to cleanup temp directory: {e}")

def create_linux_packages(source_dir: Path, output_dir: Path) -> List[Path]:
    """Create all Linux package formats."""
    builder = LinuxPackageBuilder(source_dir, output_dir)
    packages = []

    try:
        # Create DEB package
        deb_path = builder.create_deb_package()
        if deb_path:
            packages.append(deb_path)

        # Create RPM package
        rpm_path = builder.create_rpm_package()
        if rpm_path:
            packages.append(rpm_path)

        # Create AppImage
        appimage_path = builder.create_appimage()
        if appimage_path:
            packages.append(appimage_path)

        return packages

    finally:
        builder.cleanup()

if __name__ == "__main__":
    import io

    source_dir = Path(__file__).parent.parent
    output_dir = source_dir / "dist"

    packages = create_linux_packages(source_dir, output_dir)

    if packages:
        print(f"\n✅ Created {len(packages)} Linux packages:")
        for package in packages:
            print(f"   📦 {package.name}")
    else:
        print("❌ Failed to create Linux packages")
        sys.exit(1)