import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QLineEdit, QComboBox, QCheckBox, QPushButton, 
                            QLabel, QProgressBar, QTextEdit, QSpinBox,
                            QFormLayout, QScrollArea, QSizePolicy, QFrame)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont, QIcon

class ScanConfigPanel(QWidget):
    start_scan_requested = pyqtSignal(dict)
    stop_scan_requested = pyqtSignal()
    
    def __init__(self, config_manager):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self.scan_active = False
        
        self._setup_ui()
        self._load_scan_profiles()
        self._connect_signals()
    
    def _setup_ui(self):
        # Create main scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # Create scrollable content widget
        content_widget = QWidget()
        content_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        
        # Main layout with proper margins and spacing
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Target Configuration Group
        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("QGroupBox::title { font-weight: bold; }")
        target_layout = QFormLayout()
        target_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        target_layout.setLabelAlignment(Qt.AlignLeft)
        
        # Target input with proper sizing
        target_label = QLabel("Target Hosts:")
        target_label.setMinimumWidth(120)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.1 or 192.168.1.0/24")
        self.target_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.target_input.setMinimumHeight(30)
        self.target_input.setToolTip("Enter target IP addresses, ranges (192.168.1.1-50), or CIDR notation (192.168.1.0/24)")
        target_layout.addRow(target_label, self.target_input)
        
        # Quick target buttons
        quick_targets_widget = QWidget()
        quick_targets_layout = QHBoxLayout(quick_targets_widget)
        quick_targets_layout.setContentsMargins(0, 0, 0, 0)
        
        self.localhost_btn = QPushButton("Localhost")
        self.localhost_btn.setMinimumHeight(30)
        self.localhost_btn.setToolTip("Scan localhost (127.0.0.1)")
        
        self.lan_btn = QPushButton("Local Network")
        self.lan_btn.setMinimumHeight(30)
        self.lan_btn.setToolTip("Scan local network (192.168.1.0/24)")
        
        quick_targets_layout.addWidget(self.localhost_btn)
        quick_targets_layout.addWidget(self.lan_btn)
        # Remove addStretch() to eliminate empty space on the right
        
        target_layout.addRow(QLabel("Quick Select:"), quick_targets_widget)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Scan Configuration Group
        scan_group = QGroupBox("Scan Configuration")
        scan_group.setStyleSheet("QGroupBox::title { font-weight: bold; }")
        scan_layout = QFormLayout()
        scan_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        scan_layout.setLabelAlignment(Qt.AlignLeft)
        
        # Scan profile
        profile_label = QLabel("Scan Profile:")
        profile_label.setMinimumWidth(120)
        self.profile_combo = QComboBox()
        self.profile_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.profile_combo.setMinimumHeight(30)
        self.profile_combo.setToolTip("Select a predefined scan configuration profile")
        scan_layout.addRow(profile_label, self.profile_combo)
        
        # Port specification
        ports_label = QLabel("Ports:")
        ports_label.setMinimumWidth(120)
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("22,80,443 or 1-1000")
        self.ports_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.ports_input.setMinimumHeight(30)
        self.ports_input.setToolTip("Specify ports to scan: single (80), list (22,80,443), or range (1-1000)")
        scan_layout.addRow(ports_label, self.ports_input)
        
        # Timing template
        timing_label = QLabel("Scan Speed:")
        timing_label.setMinimumWidth(120)
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(['T1 (Slow)', 'T2 (Polite)', 'T3 (Normal)', 'T4 (Fast)', 'T5 (Insane)'])
        self.timing_combo.setCurrentText('T3 (Normal)')
        self.timing_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.timing_combo.setMinimumHeight(30)
        self.timing_combo.setToolTip("Select scan timing: Slow (stealthy) to Insane (very fast but detectable)")
        scan_layout.addRow(timing_label, self.timing_combo)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        # Advanced Options Group
        advanced_group = QGroupBox("Advanced Options")
        advanced_group.setStyleSheet("QGroupBox::title { font-weight: bold; }")
        advanced_layout = QVBoxLayout()
        advanced_layout.setSpacing(8)
        
        # Scan techniques section
        techniques_frame = QFrame()
        techniques_frame.setFrameStyle(QFrame.StyledPanel)
        techniques_layout = QVBoxLayout(techniques_frame)
        techniques_layout.setContentsMargins(10, 10, 10, 10)
        
        techniques_title = QLabel("Scan Techniques:")
        techniques_title.setStyleSheet("font-weight: bold; color: #333;")
        techniques_layout.addWidget(techniques_title)
        
        # Checkboxes for scan options with better spacing
        self.ping_scan_cb = QCheckBox("Ping before scan")
        self.ping_scan_cb.setChecked(True)
        self.ping_scan_cb.setToolTip("Send ping packets to discover live hosts before scanning")
        techniques_layout.addWidget(self.ping_scan_cb)
        
        self.service_detection_cb = QCheckBox("Service version detection")
        self.service_detection_cb.setToolTip("Detect versions of running services on open ports")
        techniques_layout.addWidget(self.service_detection_cb)
        
        self.os_detection_cb = QCheckBox("Operating system detection")
        self.os_detection_cb.setToolTip("Attempt to identify the target's operating system")
        techniques_layout.addWidget(self.os_detection_cb)
        
        self.script_scan_cb = QCheckBox("Script scanning (NSE)")
        self.script_scan_cb.setToolTip("Run Nmap Scripting Engine scripts for vulnerability detection")
        techniques_layout.addWidget(self.script_scan_cb)
        
        self.udp_scan_cb = QCheckBox("UDP scan")
        self.udp_scan_cb.setToolTip("Scan UDP ports (slower but detects UDP services)")
        techniques_layout.addWidget(self.udp_scan_cb)
        
        self.stealth_scan_cb = QCheckBox("Stealth scan (SYN)")
        self.stealth_scan_cb.setToolTip("Use SYN scan technique for stealthy port scanning")
        techniques_layout.addWidget(self.stealth_scan_cb)
        
        advanced_layout.addWidget(techniques_frame)
        
        # Performance settings section
        performance_frame = QFrame()
        performance_frame.setFrameStyle(QFrame.StyledPanel)
        performance_layout = QFormLayout(performance_frame)
        performance_layout.setContentsMargins(10, 10, 10, 10)
        performance_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        performance_title = QLabel("Performance Settings:")
        performance_title.setStyleSheet("font-weight: bold; color: #333;")
        performance_layout.addRow(performance_title)
        
        # Threads
        threads_label = QLabel("Max Threads:")
        threads_label.setMinimumWidth(100)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(50)
        self.threads_spin.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.threads_spin.setMinimumHeight(25)
        self.threads_spin.setToolTip("Maximum number of parallel threads (higher = faster but more aggressive)")
        performance_layout.addRow(threads_label, self.threads_spin)
        
        # Timeout
        timeout_label = QLabel("Timeout (s):")
        timeout_label.setMinimumWidth(100)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.timeout_spin.setMinimumHeight(25)
        self.timeout_spin.setToolTip("Timeout in seconds for each connection attempt")
        performance_layout.addRow(timeout_label, self.timeout_spin)
        
        advanced_layout.addWidget(performance_frame)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Control Buttons Section
        controls_group = QGroupBox("Scan Control")
        controls_group.setStyleSheet("QGroupBox::title { font-weight: bold; }")
        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(10)
        
        # Button container with proper sizing
        button_container = QWidget()
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.start_button = QPushButton("Start Scan")
        self.start_button.setProperty("primary", True)
        self.start_button.setMinimumHeight(45)
        self.start_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                color: #333;
                font-weight: bold;
                border: 1px solid #ccc;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:disabled {
                background-color: #f8f8f8;
                color: #999;
            }
        """)
        self.start_button.setToolTip("Start the network scan with current configuration")
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setMinimumHeight(45)
        self.stop_button.setEnabled(False)
        self.stop_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                color: #333;
                font-weight: bold;
                border: 1px solid #ccc;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:disabled {
                background-color: #f8f8f8;
                color: #999;
            }
        """)
        self.stop_button.setToolTip("Stop the currently running scan")
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        controls_layout.addWidget(button_container)
        
        # Progress bar with better styling
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(20)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ccc;
                text-align: center;
                color: #333;
                font-weight: bold;
                background-color: #f8f8f8;
            }
            QProgressBar::chunk {
                background-color: #ddd;
            }
        """)
        controls_layout.addWidget(self.progress_bar)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Status section
        status_group = QGroupBox("Status & Messages")
        status_group.setStyleSheet("QGroupBox::title { font-weight: bold; }")
        status_layout = QVBoxLayout()
        
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(120)
        self.status_text.setMinimumHeight(80)
        self.status_text.setReadOnly(True)
        self.status_text.setPlaceholderText("Scan status and messages will appear here...")
        self.status_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.status_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                border: 1px solid #ccc;
                padding: 8px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                color: #333;
            }
        """)
        status_layout.addWidget(self.status_text)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        # Set content widget and scroll area
        content_widget.setLayout(layout)
        scroll_area.setWidget(content_widget)
        
        # Main layout for the panel
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll_area)
        
        self.setLayout(main_layout)
    
    def _load_scan_profiles(self):
        profiles = self.config_manager.get_scan_profiles()
        self.profile_combo.clear()
        
        for profile_name in profiles.keys():
            self.profile_combo.addItem(profile_name)
        
        # Load default profile
        if profiles:
            self._load_profile_settings(list(profiles.keys())[0])
    
    def _connect_signals(self):
        self.start_button.clicked.connect(self._start_scan)
        self.stop_button.clicked.connect(self._stop_scan)
        
        self.profile_combo.currentTextChanged.connect(self._load_profile_settings)
        
        self.localhost_btn.clicked.connect(lambda: self.target_input.setText("127.0.0.1"))
        self.lan_btn.clicked.connect(lambda: self.target_input.setText("192.168.1.0/24"))
    
    def _load_profile_settings(self, profile_name):
        if not profile_name:
            return
        
        profile = self.config_manager.get_scan_profile(profile_name)
        if not profile:
            return
        
        # Update UI elements based on profile
        self.ports_input.setText(profile.get('ports', ''))
        
        timing = profile.get('timing', 'T3')
        timing_text = f"{timing} ({'Slow' if timing == 'T1' else 'Polite' if timing == 'T2' else 'Normal' if timing == 'T3' else 'Fast' if timing == 'T4' else 'Insane'})"
        for i in range(self.timing_combo.count()):
            if self.timing_combo.itemText(i).startswith(timing):
                self.timing_combo.setCurrentIndex(i)
                break
        
        self.ping_scan_cb.setChecked(profile.get('ping_scan', True))
        self.service_detection_cb.setChecked(profile.get('service_detection', False))
        self.os_detection_cb.setChecked(profile.get('os_detection', False))
        self.script_scan_cb.setChecked(profile.get('script_scan', False))
        self.udp_scan_cb.setChecked(profile.get('udp_scan', False))
        self.stealth_scan_cb.setChecked(profile.get('stealth_scan', False))
        
        self.logger.debug(f"Loaded scan profile: {profile_name}")
    
    def _start_scan(self):
        if self.scan_active:
            return
        
        # Validate input
        targets = self.target_input.text().strip()
        if not targets:
            self._add_status_message("ERROR: Please specify target hosts")
            return
        
        # Build scan configuration
        config = {
            'targets': targets,
            'profile': self.profile_combo.currentText(),
            'ports': self.ports_input.text().strip(),
            'timing': self.timing_combo.currentText()[:2],  # Extract T1, T2, etc.
            'ping_scan': self.ping_scan_cb.isChecked(),
            'service_detection': self.service_detection_cb.isChecked(),
            'os_detection': self.os_detection_cb.isChecked(),
            'script_scan': self.script_scan_cb.isChecked(),
            'udp_scan': self.udp_scan_cb.isChecked(),
            'stealth_scan': self.stealth_scan_cb.isChecked(),
            'max_threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value()
        }
        
        self._add_status_message(f"Starting scan of {targets}...")
        self.start_scan_requested.emit(config)
    
    def _stop_scan(self):
        if not self.scan_active:
            return
        
        self._add_status_message("Stopping scan...")
        self.stop_scan_requested.emit()
    
    def set_scan_active(self, active):
        self.scan_active = active
        self.start_button.setEnabled(not active)
        self.stop_button.setEnabled(active)
        self.progress_bar.setVisible(active)
        
        # Disable configuration during scan
        self.target_input.setEnabled(not active)
        self.profile_combo.setEnabled(not active)
        self.ports_input.setEnabled(not active)
        self.timing_combo.setEnabled(not active)
        
        if not active:
            self.progress_bar.setValue(0)
            self._add_status_message("Scan completed or stopped")
    
    def clear_configuration(self):
        self.target_input.clear()
        self.ports_input.clear()
        self.status_text.clear()
        
        # Reset to default profile
        if self.profile_combo.count() > 0:
            self.profile_combo.setCurrentIndex(0)
            self._load_profile_settings(self.profile_combo.currentText())
    
    def load_configuration(self, config):
        self.target_input.setText(config.get('targets', ''))
        self.ports_input.setText(config.get('ports', ''))
        
        # Find matching profile or set custom
        profile_name = config.get('scan_type', 'Custom')
        for i in range(self.profile_combo.count()):
            if self.profile_combo.itemText(i).lower() == profile_name.lower():
                self.profile_combo.setCurrentIndex(i)
                break
        
        # Update checkboxes
        self.ping_scan_cb.setChecked(config.get('ping_scan', True))
        self.service_detection_cb.setChecked(config.get('service_detection', False))
        self.os_detection_cb.setChecked(config.get('os_detection', False))
        self.script_scan_cb.setChecked(config.get('script_scan', False))
        self.udp_scan_cb.setChecked(config.get('udp_scan', False))
        self.stealth_scan_cb.setChecked(config.get('stealth_scan', False))
        
        # Update timing
        timing = config.get('timing', 'T3')
        for i in range(self.timing_combo.count()):
            if self.timing_combo.itemText(i).startswith(timing):
                self.timing_combo.setCurrentIndex(i)
                break
    
    def _add_status_message(self, message):
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        self.status_text.append(formatted_message)
        
        # Auto-scroll to bottom
        scrollbar = self.status_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
        # Limit text length to prevent memory issues
        if self.status_text.document().lineCount() > 100:
            cursor = self.status_text.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, 20)  # Select first 20 lines
            cursor.removeSelectedText()
    
    def update_progress(self, current, total):
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
            self._add_status_message(f"Progress: {current}/{total} ({progress}%)")
    
    def get_current_config(self):
        return {
            'targets': self.target_input.text().strip(),
            'profile': self.profile_combo.currentText(),
            'ports': self.ports_input.text().strip(),
            'timing': self.timing_combo.currentText()[:2],
            'ping_scan': self.ping_scan_cb.isChecked(),
            'service_detection': self.service_detection_cb.isChecked(),
            'os_detection': self.os_detection_cb.isChecked(),
            'script_scan': self.script_scan_cb.isChecked(),
            'udp_scan': self.udp_scan_cb.isChecked(),
            'stealth_scan': self.stealth_scan_cb.isChecked(),
            'max_threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value()
        }