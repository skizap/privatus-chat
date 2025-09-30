"""
Privacy Dashboard for Privatus-chat

Provides real-time visualization of privacy and anonymity status,
including onion routing circuits, traffic analysis metrics, and identity management.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QFrame, QGroupBox, QSlider, QComboBox, QCheckBox, QPushButton,
    QGridLayout, QListWidget, QListWidgetItem, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QPainter, QPen, QBrush, QColor
from typing import Dict, List, Any
from datetime import datetime
import math


class CircuitVisualization(QWidget):
    """Widget for visualizing onion routing circuits."""
    
    def __init__(self):
        super().__init__()
        self.circuits = []
        self.setMinimumHeight(150)
        self.setMinimumWidth(300)
        
    def update_circuits(self, circuit_data: List[Dict[str, Any]]):
        """Update circuit visualization data."""
        self.circuits = circuit_data
        self.update()
        
    def paintEvent(self, event):
        """Paint the circuit visualization."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.circuits:
            # Draw "No Circuits" message
            painter.setPen(QPen(QColor("#999999")))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 
                           "No active circuits\nClick 'Build Circuit' to start")
            return
        
        # Draw circuits
        circuit_height = min(40, self.height() // max(len(self.circuits), 1))
        y_offset = 10
        
        for i, circuit in enumerate(self.circuits):
            self._draw_circuit(painter, circuit, y_offset, circuit_height)
            y_offset += circuit_height + 10
            
    def _draw_circuit(self, painter: QPainter, circuit: Dict[str, Any], y: int, height: int):
        """Draw a single circuit."""
        # Circuit background
        status = circuit.get("status", "building")
        if status == "established":
            color = QColor("#4caf50")  # Green
            bg_color = QColor("#e8f5e8")
        elif status == "building":
            color = QColor("#ff9800")  # Orange
            bg_color = QColor("#fff3e0")
        else:
            color = QColor("#f44336")  # Red
            bg_color = QColor("#ffebee")

        # Draw background with better styling
        painter.setBrush(QBrush(bg_color))
        painter.setPen(QPen(color, 2))
        painter.drawRoundedRect(10, y, self.width() - 20, height, 5, 5)

        # Draw hops with improved visualization
        hops = circuit.get("hops", [])
        if hops:
            hop_width = (self.width() - 60) // len(hops)
            for i, hop in enumerate(hops):
                x = 30 + i * hop_width

                # Hop node with better styling
                node_color = color if status == "established" else color.lighter(130)
                painter.setBrush(QBrush(node_color))
                painter.setPen(QPen(color.darker(150), 2))
                painter.drawEllipse(x, y + height//4, height//2, height//2)

                # Add hop type label
                hop_type = hop.get("type", "Unknown")
                painter.setPen(QPen(QColor("#333333")))
                painter.drawText(x - 10, y + height + 15, f"{hop_type}")

                # Connection line to next hop with animation effect
                if i < len(hops) - 1:
                    line_color = color if status == "established" else color.lighter(140)
                    painter.setPen(QPen(line_color, 3))
                    painter.drawLine(x + height//2, y + height//2,
                                   x + hop_width, y + height//2)

                    # Add connection status indicator
                    if status == "established":
                        painter.setBrush(QBrush(QColor("#4caf50")))
                        painter.drawEllipse(x + hop_width - 5, y + height//2 - 3, 6, 6)


class TrafficMetrics(QGroupBox):
    """Widget displaying traffic analysis resistance metrics."""
    
    def __init__(self):
        super().__init__("Traffic Analysis Resistance")
        self.setup_ui()
        
    def setup_ui(self):
        """Setup traffic metrics UI."""
        layout = QGridLayout()
        
        # Message Padding
        layout.addWidget(QLabel("Message Padding:"), 0, 0)
        self.padding_status = QLabel("✅ Active")
        self.padding_status.setStyleSheet("color: green; font-weight: bold;")
        layout.addWidget(self.padding_status, 0, 1)
        
        self.padding_efficiency = QProgressBar()
        self.padding_efficiency.setValue(85)
        self.padding_efficiency.setFormat("85% efficiency")
        layout.addWidget(self.padding_efficiency, 0, 2)
        
        # Timing Obfuscation
        layout.addWidget(QLabel("Timing Obfuscation:"), 1, 0)
        self.timing_status = QLabel("✅ Active")
        self.timing_status.setStyleSheet("color: green; font-weight: bold;")
        layout.addWidget(self.timing_status, 1, 1)
        
        self.timing_delay = QLabel("0.5-2.0s delay")
        layout.addWidget(self.timing_delay, 1, 2)
        
        # Cover Traffic
        layout.addWidget(QLabel("Cover Traffic:"), 2, 0)
        self.cover_status = QLabel("⚠️ Disabled")
        self.cover_status.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(self.cover_status, 2, 1)
        
        self.cover_rate = QLabel("0 msg/min")
        layout.addWidget(self.cover_rate, 2, 2)
        
        # Overall Protection Score
        layout.addWidget(QLabel("Protection Score:"), 3, 0)
        self.protection_score = QProgressBar()
        self.protection_score.setValue(75)
        self.protection_score.setFormat("75/100")
        layout.addWidget(self.protection_score, 3, 1, 1, 2)
        
        self.setLayout(layout)
        
    def update_metrics(self, metrics: Dict[str, Any]):
        """Update traffic analysis metrics."""
        # Update protection score
        score = metrics.get("protection_score", 0)
        self.protection_score.setValue(int(score))
        self.protection_score.setFormat(f"{score:.0f}/100")


class IdentityReputationWidget(QGroupBox):
    """Widget for displaying identity reputation and trust network."""

    def __init__(self):
        super().__init__("Identity Reputation & Trust")
        self.setup_ui()

    def setup_ui(self):
        """Setup identity reputation UI."""
        layout = QVBoxLayout()

        # Current identity info
        identity_layout = QHBoxLayout()
        identity_layout.addWidget(QLabel("Current Identity:"))
        self.identity_label = QLabel("Anonymous_User_42")
        self.identity_label.setStyleSheet("font-weight: bold; color: #4caf50;")
        identity_layout.addWidget(self.identity_label)
        identity_layout.addStretch()
        layout.addLayout(identity_layout)

        # Reputation score
        rep_layout = QHBoxLayout()
        rep_layout.addWidget(QLabel("Reputation Score:"))
        self.reputation_score = QProgressBar()
        self.reputation_score.setValue(85)
        self.reputation_score.setFormat("85/100 (Trusted)")
        self.reputation_score.setStyleSheet("""
            QProgressBar {
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4caf50;
            }
        """)
        rep_layout.addWidget(self.reputation_score)
        layout.addLayout(rep_layout)

        # Trust network
        trust_group = QGroupBox("Trust Network")
        trust_layout = QVBoxLayout()

        self.trust_list = QListWidget()
        self.trust_list.setMaximumHeight(100)
        # Add sample trusted identities
        self.trust_list.addItem("✅ Trusted_User_A (Score: 92)")
        self.trust_list.addItem("✅ Trusted_User_B (Score: 87)")
        self.trust_list.addItem("⚠️  Moderate_User_C (Score: 65)")

        trust_layout.addWidget(self.trust_list)

        # Trust management buttons
        button_layout = QHBoxLayout()
        self.add_trust_btn = QPushButton("Add Trust")
        self.add_trust_btn.setMaximumWidth(80)
        self.remove_trust_btn = QPushButton("Remove Trust")
        self.remove_trust_btn.setMaximumWidth(90)
        self.block_identity_btn = QPushButton("Block Identity")
        self.block_identity_btn.setMaximumWidth(100)

        button_layout.addWidget(self.add_trust_btn)
        button_layout.addWidget(self.remove_trust_btn)
        button_layout.addWidget(self.block_identity_btn)
        trust_layout.addLayout(button_layout)

        trust_group.setLayout(trust_layout)
        layout.addWidget(trust_group)

        # Blocked identities
        blocked_group = QGroupBox("Blocked Identities")
        blocked_layout = QVBoxLayout()

        self.blocked_list = QListWidget()
        self.blocked_list.setMaximumHeight(60)
        self.blocked_list.addItem("🚫 Malicious_User_X")
        blocked_layout.addWidget(self.blocked_list)

        blocked_group.setLayout(blocked_layout)
        layout.addWidget(blocked_group)

        self.setLayout(layout)

    def update_reputation(self, score: float, trust_network: List[Dict[str, Any]]):
        """Update reputation display."""
        self.reputation_score.setValue(int(score))
        if score >= 80:
            status = "Trusted"
            color = "#4caf50"
        elif score >= 60:
            status = "Moderate"
            color = "#ff9800"
        else:
            status = "Low Trust"
            color = "#f44336"

        self.reputation_score.setFormat(f"{score:.0f}/100 ({status})")
        self.reputation_score.setStyleSheet(f"""
            QProgressBar {{
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)

        # Update trust list
        self.trust_list.clear()
        for identity in trust_network[:5]:  # Show top 5
            trust_icon = "✅" if identity.get('score', 0) >= 70 else "⚠️"
            item = QListWidgetItem(f"{trust_icon} {identity.get('name', 'Unknown')} (Score: {identity.get('score', 0)})")
            self.trust_list.addItem(item)


class AdvancedPrivacyDashboard(QGroupBox):
    """Advanced privacy dashboard with detailed metrics."""

    def __init__(self):
        super().__init__("Advanced Privacy Metrics")
        self.setup_ui()

    def setup_ui(self):
        """Setup advanced privacy metrics UI."""
        layout = QVBoxLayout()

        # Create tab widget for different metric categories
        self.tab_widget = QTabWidget()

        # Anonymity tab
        anonymity_tab = QWidget()
        anonymity_layout = QVBoxLayout()

        # Multi-hop circuit info
        circuit_info = QGroupBox("Circuit Information")
        circuit_layout = QGridLayout()

        circuit_layout.addWidget(QLabel("Circuit Length:"), 0, 0)
        self.circuit_length_label = QLabel("3 hops")
        circuit_layout.addWidget(self.circuit_length_label, 0, 1)

        circuit_layout.addWidget(QLabel("Circuit Age:"), 1, 0)
        self.circuit_age_label = QLabel("2.5 minutes")
        circuit_layout.addWidget(self.circuit_age_label, 1, 1)

        circuit_layout.addWidget(QLabel("Relay Diversity:"), 2, 0)
        self.relay_diversity = QProgressBar()
        self.relay_diversity.setValue(85)
        self.relay_diversity.setFormat("85% diverse")
        circuit_layout.addWidget(self.relay_diversity, 2, 1)

        circuit_info.setLayout(circuit_layout)
        anonymity_layout.addWidget(circuit_info)

        # Traffic analysis countermeasures
        traffic_info = QGroupBox("Traffic Analysis Protection")
        traffic_layout = QGridLayout()

        traffic_layout.addWidget(QLabel("Burst Disruption:"), 0, 0)
        self.burst_disruption_status = QLabel("✅ Active")
        self.burst_disruption_status.setStyleSheet("color: green;")
        traffic_layout.addWidget(self.burst_disruption_status, 0, 1)

        traffic_layout.addWidget(QLabel("Adaptive Patterns:"), 1, 0)
        self.adaptive_patterns_status = QLabel("✅ Enabled")
        self.adaptive_patterns_status.setStyleSheet("color: green;")
        traffic_layout.addWidget(self.adaptive_patterns_status, 1, 1)

        traffic_layout.addWidget(QLabel("Timing Obfuscation:"), 2, 0)
        self.timing_obfuscation = QProgressBar()
        self.timing_obfuscation.setValue(92)
        self.timing_obfuscation.setFormat("92% effective")
        traffic_layout.addWidget(self.timing_obfuscation, 2, 1)

        traffic_info.setLayout(traffic_layout)
        anonymity_layout.addWidget(traffic_info)

        anonymity_tab.setLayout(anonymity_layout)
        self.tab_widget.addTab(anonymity_tab, "Anonymity")

        # Group Security tab
        group_tab = QWidget()
        group_layout = QVBoxLayout()

        # Group key management
        key_info = QGroupBox("Group Key Management")
        key_layout = QGridLayout()

        key_layout.addWidget(QLabel("Current Key Version:"), 0, 0)
        self.key_version_label = QLabel("v2.1")
        key_layout.addWidget(self.key_version_label, 0, 1)

        key_layout.addWidget(QLabel("Key Rotation Interval:"), 1, 0)
        self.key_rotation_label = QLabel("24 hours")
        key_layout.addWidget(self.key_rotation_label, 1, 1)

        key_layout.addWidget(QLabel("Forward Secrecy:"), 2, 0)
        self.forward_secrecy_status = QLabel("✅ Active")
        self.forward_secrecy_status.setStyleSheet("color: green;")
        key_layout.addWidget(self.forward_secrecy_status, 2, 1)

        key_info.setLayout(key_layout)
        group_layout.addWidget(key_info)

        # Member authentication
        auth_info = QGroupBox("Member Authentication")
        auth_layout = QGridLayout()

        auth_layout.addWidget(QLabel("Signature Verification:"), 0, 0)
        self.signature_verification = QLabel("✅ HMAC-SHA256")
        self.signature_verification.setStyleSheet("color: green;")
        auth_layout.addWidget(self.signature_verification, 0, 1)

        auth_layout.addWidget(QLabel("Key Freshness Check:"), 1, 0)
        self.key_freshness = QLabel("✅ Enabled")
        self.key_freshness.setStyleSheet("color: green;")
        auth_layout.addWidget(self.key_freshness, 1, 1)

        auth_info.setLayout(auth_layout)
        group_layout.addWidget(auth_info)

        group_tab.setLayout(group_layout)
        self.tab_widget.addTab(group_tab, "Group Security")

        # File Transfer tab
        file_tab = QWidget()
        file_layout = QVBoxLayout()

        # Transfer reliability
        transfer_info = QGroupBox("File Transfer Reliability")
        transfer_layout = QGridLayout()

        transfer_layout.addWidget(QLabel("Resumable Downloads:"), 0, 0)
        self.resumable_downloads = QLabel("✅ Supported")
        self.resumable_downloads.setStyleSheet("color: green;")
        transfer_layout.addWidget(self.resumable_downloads, 0, 1)

        transfer_layout.addWidget(QLabel("Chunk Integrity:"), 1, 0)
        self.chunk_integrity = QLabel("✅ SHA-256 verified")
        self.chunk_integrity.setStyleSheet("color: green;")
        transfer_layout.addWidget(self.chunk_integrity, 1, 1)

        transfer_layout.addWidget(QLabel("Retry Mechanism:"), 2, 0)
        self.retry_mechanism = QLabel("✅ Exponential backoff")
        self.retry_mechanism.setStyleSheet("color: green;")
        transfer_layout.addWidget(self.retry_mechanism, 2, 1)

        transfer_info.setLayout(transfer_layout)
        file_layout.addWidget(transfer_info)

        file_tab.setLayout(file_layout)
        self.tab_widget.addTab(file_tab, "File Transfer")

        layout.addWidget(self.tab_widget)
        self.setLayout(layout)


class PrivacyDashboard(QWidget):
    """Comprehensive privacy dashboard with advanced features."""

    privacy_level_changed = pyqtSignal(str)  # privacy_level
    setting_changed = pyqtSignal(str, bool)  # setting_name, enabled

    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        """Setup privacy dashboard UI with tabbed interface."""
        layout = QVBoxLayout()

        # Header with privacy level
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Privacy Level:"))

        self.privacy_slider = QSlider(Qt.Orientation.Horizontal)
        self.privacy_slider.setRange(0, 3)
        self.privacy_slider.setValue(2)  # Standard
        self.privacy_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.privacy_slider.setTickInterval(1)
        self.privacy_slider.valueChanged.connect(self._on_privacy_level_changed)
        header_layout.addWidget(self.privacy_slider)

        self.privacy_label = QLabel("High Privacy")
        self.privacy_label.setStyleSheet("font-weight: bold; color: #4caf50;")
        header_layout.addWidget(self.privacy_label)

        layout.addLayout(header_layout)

        # Create tab widget for different dashboard sections
        self.tab_widget = QTabWidget()

        # Overview tab (original functionality)
        overview_tab = QWidget()
        overview_layout = QVBoxLayout()

        # Circuit visualization
        circuit_group = QGroupBox("Onion Routing Circuits")
        circuit_layout = QVBoxLayout()

        self.circuit_viz = CircuitVisualization()
        circuit_layout.addWidget(self.circuit_viz)

        circuit_controls = QHBoxLayout()
        self.build_circuit_btn = QPushButton("Build Circuit")
        self.build_circuit_btn.clicked.connect(self._build_circuit)
        circuit_controls.addWidget(self.build_circuit_btn)

        circuit_controls.addStretch()

        self.circuit_info = QLabel("Active Circuits: 0")
        circuit_controls.addWidget(self.circuit_info)

        circuit_layout.addLayout(circuit_controls)
        circuit_group.setLayout(circuit_layout)
        overview_layout.addWidget(circuit_group)

        # Traffic analysis metrics
        self.traffic_metrics = TrafficMetrics()
        overview_layout.addWidget(self.traffic_metrics)

        # Quick settings
        settings_group = QGroupBox("Quick Settings")
        settings_layout = QGridLayout()

        self.onion_routing_cb = QCheckBox("Onion Routing")
        self.onion_routing_cb.setChecked(True)
        self.onion_routing_cb.toggled.connect(lambda x: self.setting_changed.emit("onion_routing", x))
        settings_layout.addWidget(self.onion_routing_cb, 0, 0)

        self.traffic_obfuscation_cb = QCheckBox("Traffic Obfuscation")
        self.traffic_obfuscation_cb.setChecked(True)
        self.traffic_obfuscation_cb.toggled.connect(lambda x: self.setting_changed.emit("traffic_obfuscation", x))
        settings_layout.addWidget(self.traffic_obfuscation_cb, 0, 1)

        self.cover_traffic_cb = QCheckBox("Cover Traffic")
        self.cover_traffic_cb.setChecked(False)
        self.cover_traffic_cb.toggled.connect(lambda x: self.setting_changed.emit("cover_traffic", x))
        settings_layout.addWidget(self.cover_traffic_cb, 1, 0)

        self.metadata_protection_cb = QCheckBox("Metadata Protection")
        self.metadata_protection_cb.setChecked(True)
        self.metadata_protection_cb.toggled.connect(lambda x: self.setting_changed.emit("metadata_protection", x))
        settings_layout.addWidget(self.metadata_protection_cb, 1, 1)

        settings_group.setLayout(settings_layout)
        overview_layout.addWidget(settings_group)

        overview_tab.setLayout(overview_layout)
        self.tab_widget.addTab(overview_tab, "Overview")

        # Identity & Reputation tab
        identity_tab = QWidget()
        identity_layout = QVBoxLayout()

        self.identity_reputation_widget = IdentityReputationWidget()
        identity_layout.addWidget(self.identity_reputation_widget)

        identity_tab.setLayout(identity_layout)
        self.tab_widget.addTab(identity_tab, "Identity")

        # Advanced Metrics tab
        self.advanced_dashboard = AdvancedPrivacyDashboard()
        self.tab_widget.addTab(self.advanced_dashboard, "Advanced")

        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
        
    def setup_timer(self):
        """Setup update timer for real-time data."""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_data)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def _on_privacy_level_changed(self, value: int):
        """Handle privacy level change."""
        levels = ["Minimal", "Standard", "High", "Maximum"]
        level = levels[value]
        self.privacy_label.setText(f"{level} Privacy")
        
        # Update label color based on level
        colors = ["#f44336", "#ff9800", "#4caf50", "#2196f3"]
        self.privacy_label.setStyleSheet(f"font-weight: bold; color: {colors[value]};")
        
        self.privacy_level_changed.emit(level)
        
    def _build_circuit(self):
        """Trigger circuit building."""
        # Create more realistic circuit data
        import random
        circuit_id = random.randint(1000, 9999)

        # Generate realistic hop data
        locations = ["Germany", "Netherlands", "Sweden", "Canada", "Switzerland", "France", "Japan", "USA"]
        hop_types = ["Entry", "Middle", "Exit"]

        hops = []
        for i, hop_type in enumerate(hop_types):
            hops.append({
                "type": hop_type,
                "location": random.choice(locations),
                "latency": random.randint(50, 200),
                "bandwidth": random.randint(10, 100)
            })

        circuit_data = {
            "id": circuit_id,
            "status": "building",
            "hops": hops,
            "created_at": datetime.now().timestamp()
        }

        # Simulate building process with progress updates
        self._simulate_circuit_building(circuit_data)
        
    def _simulate_circuit_building(self, circuit_data):
        """Simulate the circuit building process with progress updates."""
        # Add to circuits list immediately
        self.circuit_viz.circuits.append(circuit_data)
        self.circuit_viz.update()

        # Simulate building progress over time
        def build_step(step):
            if step <= 3:  # 3 hops to build
                # Update hop status
                if step <= len(circuit_data["hops"]):
                    circuit_data["hops"][step-1]["status"] = "building"

                # Update circuit status
                if step == 3:
                    circuit_data["status"] = "established"
                    circuit_data["latency"] = 120 + (hash(str(circuit_data["id"])) % 200)

                self.circuit_viz.update()
                QTimer.singleShot(800, lambda: build_step(step + 1))
            else:
                # Building complete
                self._update_circuit_info()

        # Start building process
        build_step(1)

    def _circuit_established(self, circuit_data):
        """Mark circuit as established."""
        circuit_data["status"] = "established"
        circuit_data["latency"] = 120 + (hash(str(circuit_data["id"])) % 200)
        self.circuit_viz.circuits.append(circuit_data)
        self.circuit_viz.update()
        self._update_circuit_info()
        
    def _update_circuit_info(self):
        """Update circuit information display."""
        active_circuits = len([c for c in self.circuit_viz.circuits if c.get("status") == "established"])
        self.circuit_info.setText(f"Active Circuits: {active_circuits}")
        
    def _update_data(self):
        """Update dashboard with real-time data."""
        # Simulate metrics updates
        import random
        
        metrics = {
            "protection_score": random.uniform(70, 95) if self.onion_routing_cb.isChecked() else random.uniform(40, 65)
        }
        
        self.traffic_metrics.update_metrics(metrics)
