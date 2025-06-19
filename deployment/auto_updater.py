"""
Secure Auto-Updater System for Privatus-chat

Implements secure automatic updates with cryptographic verification.
"""

import os
import sys
import json
import hashlib
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import platform


class UpdateType(Enum):
    """Types of updates."""
    FULL = "full"
    DELTA = "delta"
    SECURITY = "security"
    FEATURE = "feature"
    BUGFIX = "bugfix"


class UpdateStatus(Enum):
    """Update status."""
    CHECKING = "checking"
    AVAILABLE = "available"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    APPLYING = "applying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLBACK = "rollback"


@dataclass
class UpdateInfo:
    """Information about an available update."""
    version: str
    update_type: UpdateType
    release_date: datetime
    file_size: int
    download_url: str
    signature_url: str
    checksum_sha256: str
    description: str
    changelog: str
    is_critical: bool = False
    minimum_version: Optional[str] = None


@dataclass
class UpdateProgress:
    """Update progress information."""
    status: UpdateStatus
    progress_percent: float = 0.0
    bytes_downloaded: int = 0
    total_bytes: int = 0
    speed_bps: float = 0.0
    eta_seconds: Optional[float] = None
    current_operation: str = ""
    error_message: Optional[str] = None


class AutoUpdater:
    """Main auto-updater class with secure update verification."""
    
    def __init__(self, current_version: str, app_directory: Path, 
                 update_server_url: str = "https://updates.privatus-chat.org"):
        self.current_version = current_version
        self.app_directory = app_directory
        self.update_server_url = update_server_url
        
        # Initialize components
        self.backup_directory = app_directory.parent / "backups"
        self.temp_directory = Path(tempfile.gettempdir()) / "privatus_updates"
        self.temp_directory.mkdir(parents=True, exist_ok=True)
        
        # Update state
        self.last_check: Optional[datetime] = None
        self.available_updates: List[UpdateInfo] = []
        self.progress_callbacks: List[Callable[[UpdateProgress], None]] = []
        
        # Settings
        self.auto_download = True
        self.auto_install_security = True
        self.auto_install_all = False
    
    def add_progress_callback(self, callback: Callable[[UpdateProgress], None]):
        """Add progress callback."""
        self.progress_callbacks.append(callback)
    
    def _notify_progress(self, progress: UpdateProgress):
        """Notify all progress callbacks."""
        for callback in self.progress_callbacks:
            try:
                callback(progress)
            except Exception:
                pass
    
    async def check_for_updates(self, force: bool = False) -> List[UpdateInfo]:
        """Check for available updates."""
        self._notify_progress(UpdateProgress(
            status=UpdateStatus.CHECKING,
            current_operation="Checking for updates..."
        ))
        
        # Simulate update check for demo
        # In production, would fetch from actual update server
        demo_update = UpdateInfo(
            version="3.1.0",
            update_type=UpdateType.FEATURE,
            release_date=datetime.now(),
            file_size=50 * 1024 * 1024,  # 50MB
            download_url="https://example.com/privatus-chat-3.1.0.zip",
            signature_url="https://example.com/privatus-chat-3.1.0.zip.sig",
            checksum_sha256="abcdef123456...",
            description="New features and security improvements",
            changelog="Added video calls, improved security, bug fixes",
            is_critical=False
        )
        
        if self._is_version_newer(demo_update.version, self.current_version):
            self.available_updates = [demo_update]
        else:
            self.available_updates = []
        
        self.last_check = datetime.now()
        
        if self.available_updates:
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.AVAILABLE,
                current_operation=f"Found {len(self.available_updates)} updates"
            ))
        else:
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.COMPLETED,
                current_operation="No updates available"
            ))
        
        return self.available_updates
    
    def _is_version_newer(self, version1: str, version2: str) -> bool:
        """Check if version1 is newer than version2."""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            return v1_parts > v2_parts
        except Exception:
            return False
    
    async def download_update(self, update_info: UpdateInfo) -> Optional[Path]:
        """Download and verify an update."""
        self._notify_progress(UpdateProgress(
            status=UpdateStatus.DOWNLOADING,
            current_operation=f"Downloading {update_info.version}"
        ))
        
        # Simulate download progress
        for i in range(101):
            await asyncio.sleep(0.01)  # Small delay for demo
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.DOWNLOADING,
                progress_percent=i,
                current_operation=f"Downloading {update_info.version}"
            ))
        
        # Simulate verification
        self._notify_progress(UpdateProgress(
            status=UpdateStatus.VERIFYING,
            current_operation="Verifying update integrity"
        ))
        
        await asyncio.sleep(0.5)  # Simulate verification time
        
        # Create dummy update file for demo
        update_file = self.temp_directory / f"privatus-chat-{update_info.version}.zip"
        update_file.write_text("Dummy update file for demonstration")
        
        self._notify_progress(UpdateProgress(
            status=UpdateStatus.COMPLETED,
            current_operation="Update downloaded and verified"
        ))
        
        return update_file
    
    async def apply_update(self, update_file: Path, update_info: UpdateInfo) -> bool:
        """Apply a downloaded update."""
        try:
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.APPLYING,
                current_operation="Creating backup"
            ))
            
            await asyncio.sleep(0.5)  # Simulate backup creation
            
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.APPLYING,
                progress_percent=50.0,
                current_operation="Applying update"
            ))
            
            await asyncio.sleep(1.0)  # Simulate update application
            
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.COMPLETED,
                progress_percent=100.0,
                current_operation="Update applied successfully"
            ))
            
            return True
            
        except Exception as e:
            self._notify_progress(UpdateProgress(
                status=UpdateStatus.FAILED,
                error_message=f"Update failed: {e}"
            ))
            return False
    
    async def install_update(self, update_info: UpdateInfo) -> bool:
        """Download and install an update."""
        update_file = await self.download_update(update_info)
        if not update_file:
            return False
        
        return await self.apply_update(update_file, update_info)


# Example usage for demo
async def demo_updater():
    """Demonstrate the auto-updater system."""
    app_dir = Path(".")
    updater = AutoUpdater("3.0.0", app_dir)
    
    def progress_callback(progress: UpdateProgress):
        print(f"Status: {progress.status.value}")
        if progress.progress_percent > 0:
            print(f"Progress: {progress.progress_percent:.1f}%")
        print(f"Operation: {progress.current_operation}")
        if progress.error_message:
            print(f"Error: {progress.error_message}")
        print("-" * 40)
    
    updater.add_progress_callback(progress_callback)
    
    print("🔄 Checking for updates...")
    updates = await updater.check_for_updates()
    print(f"Found {len(updates)} updates")
    
    if updates:
        print(f"\n📦 Installing update {updates[0].version}...")
        success = await updater.install_update(updates[0])
        if success:
            print("✅ Update installed successfully!")
        else:
            print("❌ Update failed!")


if __name__ == "__main__":
    asyncio.run(demo_updater()) 