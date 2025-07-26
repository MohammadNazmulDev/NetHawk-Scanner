import os
import sys
import logging
import uuid
from datetime import datetime
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QSplitter, QMenuBar, QMenu, QAction, QStatusBar,
                            QApplication, QMessageBox, QProgressBar, QLabel,
                            QSizePolicy)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont

from .scan_config_panel import ScanConfigPanel
from .results_panel import ResultsPanel
from database.database_manager import DatabaseManager
from scanner.nmap_scanner import NmapScanManager
from scanner.vulnerability_detector import VulnerabilityDetector
from reports.report_generator import ReportGenerator
from utils.logger import get_audit_logger

class MainWindow(QMainWindow):
    scan_completed = pyqtSignal(str, dict)
    
    def __init__(self, config_manager):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.audit_logger = get_audit_logger()
        self.config_manager = config_manager
        
        # Initialize core components
        self.db_manager = DatabaseManager()
        self.scan_manager = NmapScanManager(self.db_manager)
        self.vuln_detector = VulnerabilityDetector(self.db_manager)
        self.report_generator = ReportGenerator(self.db_manager)
        
        self.current_session_id = None
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self._update_scan_status)
        
        self._setup_ui()
        self._load_theme()
        self._connect_signals()
        self._restore_window_geometry()
        
        self.audit_logger.info("NetHawk Scanner application started")
        self.logger.info("Main window initialized successfully")
    
    def _setup_ui(self):
        self.setWindowTitle("NetHawk Scanner v1.0")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 900)
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Create splitter for panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Create panels
        self.scan_config_panel = ScanConfigPanel(self.config_manager)
        self.results_panel = ResultsPanel(self.db_manager)
        
        # Set panel sizes with better constraints
        self.scan_config_panel.setMinimumWidth(380)
        self.scan_config_panel.setMaximumWidth(480)
        self.scan_config_panel.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        
        # Add panels to splitter
        splitter.addWidget(self.scan_config_panel)
        splitter.addWidget(self.results_panel)
        
        # Set splitter proportions (left panel: 420px, right panel: remainder)
        splitter.setSizes([420, 1000])
        splitter.setHandleWidth(1)
        
        # Create main layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)
        main_widget.setLayout(layout)
        
        # Create status bar
        self._create_status_bar()
        
        self.logger.debug("UI setup completed")
    
    def _create_menu_bar(self):
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu('File')
        
        new_scan_action = QAction('New Scan', self)
        new_scan_action.setShortcut('Ctrl+N')
        new_scan_action.triggered.connect(self._new_scan)
        file_menu.addAction(new_scan_action)
        
        file_menu.addSeparator()
        
        save_results_action = QAction('Save Results', self)
        save_results_action.setShortcut('Ctrl+S')
        save_results_action.triggered.connect(self._save_results)
        file_menu.addAction(save_results_action)
        
        load_previous_action = QAction('Load Previous', self)
        load_previous_action.setShortcut('Ctrl+O')
        load_previous_action.triggered.connect(self._load_previous)
        file_menu.addAction(load_previous_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools Menu
        tools_menu = menubar.addMenu('Tools')
        
        ping_sweep_action = QAction('Ping Sweep', self)
        ping_sweep_action.triggered.connect(self._ping_sweep)
        tools_menu.addAction(ping_sweep_action)
        
        port_scanner_action = QAction('Port Scanner', self)
        port_scanner_action.triggered.connect(self._port_scanner)
        tools_menu.addAction(port_scanner_action)
        
        vuln_check_action = QAction('Vulnerability Check', self)
        vuln_check_action.triggered.connect(self._vulnerability_check)
        tools_menu.addAction(vuln_check_action)
        
        # Help Menu
        help_menu = menubar.addMenu('Help')
        
        documentation_action = QAction('Documentation', self)
        documentation_action.triggered.connect(self._show_documentation)
        help_menu.addAction(documentation_action)
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status message
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Progress bar (initially hidden)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Current time
        self.time_label = QLabel()
        self.status_bar.addPermanentWidget(self.time_label)
        
        # Update time every second
        self.time_timer = QTimer()
        self.time_timer.timeout.connect(self._update_time)
        self.time_timer.start(1000)
        self._update_time()
    
    def _load_theme(self):
        theme_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'assets', 'themes', 'dark_theme.qss'
        )
        
        if os.path.exists(theme_path):
            try:
                with open(theme_path, 'r') as f:
                    self.setStyleSheet(f.read())
                self.logger.debug("Dark theme loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load theme: {e}")
        else:
            self.logger.warning("Theme file not found, using default styling")
    
    def _connect_signals(self):
        # Connect scan config panel signals
        self.scan_config_panel.start_scan_requested.connect(self._start_scan)
        self.scan_config_panel.stop_scan_requested.connect(self._stop_scan)
        
        # Connect results panel signals
        self.results_panel.export_requested.connect(self._export_data)
        self.results_panel.generate_report_requested.connect(self._generate_report)
        
        # Connect internal signals
        self.scan_completed.connect(self._on_scan_completed)
    
    def _restore_window_geometry(self):
        geometry = self.config_manager.get_window_geometry()
        self.resize(geometry['width'], geometry['height'])
        
        if geometry['maximized']:
            self.showMaximized()
    
    def _save_window_geometry(self):
        self.config_manager.save_window_geometry(
            self.width(),
            self.height(),
            self.isMaximized()
        )
    
    def _update_time(self):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.setText(current_time)
    
    def _new_scan(self):
        self.scan_config_panel.clear_configuration()
        self.results_panel.clear_results()
        self.status_label.setText("Ready for new scan")
        self.audit_logger.info("New scan initiated by user")
    
    def _save_results(self):
        if self.current_session_id:
            self.results_panel.export_results()
        else:
            QMessageBox.information(self, "No Results", "No scan results to save.")
    
    def _load_previous(self):
        self.results_panel.load_previous_scan()
    
    def _ping_sweep(self):
        config = {
            'scan_type': 'ping_sweep',
            'ping_scan': True,
            'service_detection': False,
            'os_detection': False,
            'script_scan': False,
            'ports': '',
            'timing': 'T4'
        }
        self.scan_config_panel.load_configuration(config)
        self.audit_logger.info("Ping sweep tool activated")
    
    def _port_scanner(self):
        config = {
            'scan_type': 'port_scan',
            'ping_scan': True,
            'service_detection': True,
            'os_detection': False,
            'script_scan': False,
            'ports': '1-1000',
            'timing': 'T3'
        }
        self.scan_config_panel.load_configuration(config)
        self.audit_logger.info("Port scanner tool activated")
    
    def _vulnerability_check(self):
        if self.current_session_id:
            self._run_vulnerability_detection()
        else:
            QMessageBox.information(
                self, 
                "No Scan Data", 
                "Please run a scan first before checking for vulnerabilities."
            )
    
    def _show_documentation(self):
        QMessageBox.information(
            self,
            "Documentation",
            "NetHawk Scanner v1.0\n\n"
            "Professional network vulnerability assessment tool.\n\n"
            "Features:\n"
            "- Network discovery and port scanning\n"
            "- Service enumeration and OS detection\n"
            "- Vulnerability detection with CVE database\n"
            "- Professional PDF report generation\n"
            "- Export capabilities (CSV, JSON, XML)\n\n"
            "For detailed documentation, visit the Help menu."
        )
    
    def _show_about(self):
        QMessageBox.about(
            self,
            "About NetHawk Scanner",
            "NetHawk Scanner v1.0\n\n"
            "Enterprise-grade network vulnerability assessment tool\n"
            "Built for security professionals and penetration testers\n\n"
            "Copyright 2024 NetHawk Security\n"
            "Licensed for authorized security testing only\n\n"
            "WARNING: Use only on networks you own or have explicit permission to test."
        )
    
    def _start_scan(self, scan_config):
        try:
            # Validate configuration
            if not scan_config.get('targets'):
                QMessageBox.warning(self, "Invalid Configuration", "Please specify target hosts.")
                return
            
            # Security confirmation for external targets
            if self._requires_security_confirmation(scan_config['targets']):
                reply = QMessageBox.question(
                    self,
                    "Security Confirmation",
                    "You are about to scan external targets. "
                    "Ensure you have proper authorization.\n\n"
                    "Continue with scan?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply != QMessageBox.Yes:
                    return
            
            # Generate session ID
            self.current_session_id = str(uuid.uuid4())
            
            # Start scan
            scan_name = f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            success = self.scan_manager.start_scan(
                self.current_session_id,
                scan_name,
                scan_config['targets'],
                scan_config,
                self._on_scan_progress
            )
            
            if success:
                self._update_scan_ui_state(True)
                self.status_label.setText("Scan in progress...")
                self.scan_timer.start(1000)  # Update every second
                
                self.audit_logger.info(
                    f"Scan started - Session: {self.current_session_id}, "
                    f"Targets: {scan_config['targets']}, "
                    f"Profile: {scan_config.get('profile', 'Custom')}"
                )
            else:
                QMessageBox.critical(self, "Scan Failed", "Failed to start scan. Check logs for details.")
        
        except Exception as e:
            self.logger.error(f"Error starting scan: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
    
    def _stop_scan(self):
        if self.current_session_id and self.scan_manager.is_scan_active(self.current_session_id):
            reply = QMessageBox.question(
                self,
                "Stop Scan",
                "Are you sure you want to stop the current scan?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.scan_manager.cancel_scan(self.current_session_id)
                self._update_scan_ui_state(False)
                self.status_label.setText("Scan stopped by user")
                self.scan_timer.stop()
                
                self.audit_logger.info(f"Scan stopped by user - Session: {self.current_session_id}")
    
    def _requires_security_confirmation(self, targets):
        # Check if targets include external/public IP addresses
        import ipaddress
        
        for target in targets.split(','):
            target = target.strip()
            
            try:
                # Skip hostnames for now
                if not target.replace('.', '').replace('/', '').replace('-', '').isdigit():
                    continue
                
                # Parse CIDR notation
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    sample_ip = next(network.hosts())
                else:
                    sample_ip = ipaddress.ip_address(target.split('-')[0])
                
                # Check if it's a private network
                if not sample_ip.is_private:
                    return True
                
            except Exception:
                # If we can't parse it, be safe and ask for confirmation
                return True
        
        return False
    
    def _update_scan_ui_state(self, scanning):
        self.scan_config_panel.set_scan_active(scanning)
        self.progress_bar.setVisible(scanning)
        
        if not scanning:
            self.progress_bar.setValue(0)
    
    def _on_scan_progress(self, session_id, current, total):
        if session_id == self.current_session_id:
            if total > 0:
                progress = int((current / total) * 100)
                self.progress_bar.setValue(progress)
                self.status_label.setText(f"Scanning... {current}/{total} targets ({progress}%)")
    
    def _update_scan_status(self):
        if self.current_session_id:
            # Update results panel with latest data
            self.results_panel.refresh_session_data(self.current_session_id)
            
            # Check if scan is still active
            if not self.scan_manager.is_scan_active(self.current_session_id):
                self._update_scan_ui_state(False)
                self.scan_timer.stop()
                
                # Automatically run vulnerability detection
                self._run_vulnerability_detection()
    
    def _on_scan_completed(self, session_id, summary):
        if session_id == self.current_session_id:
            self.status_label.setText(
                f"Scan completed - {summary.get('hosts_up', 0)} hosts up, "
                f"{summary.get('total_ports', 0)} ports scanned"
            )
            
            self.audit_logger.info(
                f"Scan completed - Session: {session_id}, "
                f"Hosts up: {summary.get('hosts_up', 0)}, "
                f"Total ports: {summary.get('total_ports', 0)}, "
                f"Duration: {summary.get('elapsed_time', 0):.1f}s"
            )
    
    def _run_vulnerability_detection(self):
        if not self.current_session_id:
            return
        
        try:
            self.status_label.setText("Running vulnerability detection...")
            QApplication.processEvents()  # Update UI
            
            # Run vulnerability detection
            vuln_results = self.vuln_detector.detect_vulnerabilities(self.current_session_id)
            
            # Update results panel
            self.results_panel.refresh_session_data(self.current_session_id)
            
            # Update status
            total_vulns = vuln_results.get('total_vulnerabilities', 0)
            if total_vulns > 0:
                critical = vuln_results.get('critical', 0)
                high = vuln_results.get('high', 0)
                self.status_label.setText(
                    f"Vulnerability scan completed - {total_vulns} vulnerabilities found "
                    f"({critical} critical, {high} high)"
                )
            else:
                self.status_label.setText("Vulnerability scan completed - No vulnerabilities found")
            
            self.audit_logger.info(
                f"Vulnerability detection completed - Session: {self.current_session_id}, "
                f"Total vulnerabilities: {total_vulns}"
            )
        
        except Exception as e:
            self.logger.error(f"Error during vulnerability detection: {e}")
            self.status_label.setText("Vulnerability detection failed")
    
    def _export_data(self, format_type):
        if not self.current_session_id:
            QMessageBox.information(self, "No Data", "No scan data to export.")
            return
        
        try:
            self.results_panel.export_session_data(self.current_session_id, format_type)
            self.audit_logger.info(f"Data exported - Session: {self.current_session_id}, Format: {format_type}")
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed to export data: {str(e)}")
    
    def _generate_report(self):
        if not self.current_session_id:
            QMessageBox.information(self, "No Data", "No scan data for report generation.")
            return
        
        try:
            self.status_label.setText("Generating report...")
            QApplication.processEvents()
            
            report_path = self.report_generator.generate_pdf_report(self.current_session_id)
            
            if report_path:
                self.status_label.setText(f"Report generated: {os.path.basename(report_path)}")
                
                # Ask user if they want to open the report
                reply = QMessageBox.question(
                    self,
                    "Report Generated",
                    f"Report saved to:\n{report_path}\n\nOpen report now?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )
                
                if reply == QMessageBox.Yes:
                    os.system(f'xdg-open "{report_path}"')
                
                self.audit_logger.info(f"PDF report generated - Session: {self.current_session_id}, Path: {report_path}")
            else:
                self.status_label.setText("Report generation failed")
                QMessageBox.critical(self, "Report Error", "Failed to generate report.")
        
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            self.status_label.setText("Report generation failed")
            QMessageBox.critical(self, "Report Error", f"Failed to generate report: {str(e)}")
    
    def closeEvent(self, event):
        try:
            # Stop any active scans
            active_scans = self.scan_manager.get_active_scans()
            if active_scans:
                reply = QMessageBox.question(
                    self,
                    "Active Scans",
                    "There are active scans running. Stop all scans and exit?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply != QMessageBox.Yes:
                    event.ignore()
                    return
                
                # Stop all active scans
                for session_id in active_scans:
                    self.scan_manager.cancel_scan(session_id)
            
            # Save window geometry
            self._save_window_geometry()
            
            # Log application closure
            self.audit_logger.info("NetHawk Scanner application closed")
            
            event.accept()
            
        except Exception as e:
            self.logger.error(f"Error during application closure: {e}")
            event.accept()  # Close anyway to prevent hanging