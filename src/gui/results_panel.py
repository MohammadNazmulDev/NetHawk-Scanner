import os
import logging
from datetime import datetime
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                            QTableWidgetItem, QPushButton, QLabel, QComboBox,
                            QLineEdit, QHeaderView, QTabWidget, QTextEdit,
                            QMessageBox, QFileDialog, QSplitter, QGroupBox)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class ResultsPanel(QWidget):
    export_requested = pyqtSignal(str)
    generate_report_requested = pyqtSignal()
    
    def __init__(self, database_manager):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.db_manager = database_manager
        self.current_session_id = None
        
        self._setup_ui()
        self._connect_signals()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._auto_refresh)
        self.refresh_timer.start(2000)  # Refresh every 2 seconds during active scans
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Summary statistics bar
        summary_layout = QHBoxLayout()
        
        self.stats_label = QLabel("Hosts: 0 | Open Ports: 0 | Vulnerabilities: 0")
        summary_layout.addWidget(self.stats_label)
        
        summary_layout.addStretch()
        
        self.generate_report_btn = QPushButton("Generate Report")
        summary_layout.addWidget(self.generate_report_btn)
        
        layout.addLayout(summary_layout)
        
        # Create tab widget for different result views
        self.tab_widget = QTabWidget()
        
        # Hosts tab
        self.hosts_tab = self._create_hosts_tab()
        self.tab_widget.addTab(self.hosts_tab, "Hosts")
        
        # Ports tab
        self.ports_tab = self._create_ports_tab()
        self.tab_widget.addTab(self.ports_tab, "Ports")
        
        # Vulnerabilities tab
        self.vulnerabilities_tab = self._create_vulnerabilities_tab()
        self.tab_widget.addTab(self.vulnerabilities_tab, "Vulnerabilities")
        
        # History tab
        self.history_tab = self._create_history_tab()
        self.tab_widget.addTab(self.history_tab, "History")
        
        layout.addWidget(self.tab_widget)
        
        # Filter and export controls
        controls_layout = QHBoxLayout()
        
        # Filter controls
        controls_layout.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Search results...")
        self.filter_input.setMaximumWidth(200)
        controls_layout.addWidget(self.filter_input)
        
        self.filter_column_combo = QComboBox()
        self.filter_column_combo.addItems(["All", "Host", "Port", "Service", "Vulnerability"])
        self.filter_column_combo.setMaximumWidth(100)
        controls_layout.addWidget(self.filter_column_combo)
        
        controls_layout.addStretch()
        
        # Export controls
        controls_layout.addWidget(QLabel("Export:"))
        
        # Create export button container with proper spacing
        export_container = QWidget()
        export_layout = QHBoxLayout(export_container)
        export_layout.setContentsMargins(0, 0, 0, 0)
        export_layout.setSpacing(8)
        
        self.export_csv_btn = QPushButton("CSV")
        self.export_csv_btn.setMinimumWidth(70)
        self.export_csv_btn.setMaximumWidth(70)
        export_layout.addWidget(self.export_csv_btn)
        
        self.export_json_btn = QPushButton("JSON")
        self.export_json_btn.setMinimumWidth(70)
        self.export_json_btn.setMaximumWidth(70)
        export_layout.addWidget(self.export_json_btn)
        
        self.export_xml_btn = QPushButton("XML")
        self.export_xml_btn.setMinimumWidth(70)
        self.export_xml_btn.setMaximumWidth(70)
        export_layout.addWidget(self.export_xml_btn)
        
        controls_layout.addWidget(export_container)
        
        layout.addLayout(controls_layout)
        
        self.setLayout(layout)
    
    def _create_hosts_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Hosts table
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(7)
        self.hosts_table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "OS", "Status", "Ports", "Vulnerabilities", "Response Time"
        ])
        
        # Set column widths according to spec
        header = self.hosts_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # IP
        header.setSectionResizeMode(1, QHeaderView.Stretch)           # Hostname
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # OS
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Ports
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Vulnerabilities
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Response Time
        
        self.hosts_table.setAlternatingRowColors(True)
        self.hosts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hosts_table.setSortingEnabled(True)
        
        layout.addWidget(self.hosts_table)
        widget.setLayout(layout)
        
        return widget
    
    def _create_ports_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Ports table
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(6)
        self.ports_table.setHorizontalHeaderLabels([
            "Host", "Port", "State", "Service", "Version", "Protocol"
        ])
        
        # Set column widths
        header = self.ports_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Host
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Port
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # State
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Service
        header.setSectionResizeMode(4, QHeaderView.Stretch)           # Version
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Protocol
        
        self.ports_table.setAlternatingRowColors(True)
        self.ports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ports_table.setSortingEnabled(True)
        
        layout.addWidget(self.ports_table)
        widget.setLayout(layout)
        
        return widget
    
    def _create_vulnerabilities_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Vulnerability counts
        vuln_summary_layout = QHBoxLayout()
        self.critical_label = QLabel("Critical: 0")
        self.high_label = QLabel("High: 0")
        self.medium_label = QLabel("Medium: 0")
        self.low_label = QLabel("Low: 0")
        
        vuln_summary_layout.addWidget(self.critical_label)
        vuln_summary_layout.addWidget(self.high_label)
        vuln_summary_layout.addWidget(self.medium_label)
        vuln_summary_layout.addWidget(self.low_label)
        vuln_summary_layout.addStretch()
        
        layout.addLayout(vuln_summary_layout)
        
        # Vulnerabilities table
        self.vulnerabilities_table = QTableWidget()
        self.vulnerabilities_table.setColumnCount(6)
        self.vulnerabilities_table.setHorizontalHeaderLabels([
            "Host", "Vulnerability", "Severity", "CVSS", "CVE ID", "Port"
        ])
        
        # Set column widths
        header = self.vulnerabilities_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Host
        header.setSectionResizeMode(1, QHeaderView.Stretch)           # Vulnerability
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # CVSS
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # CVE ID
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Port
        
        self.vulnerabilities_table.setAlternatingRowColors(True)
        self.vulnerabilities_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vulnerabilities_table.setSortingEnabled(True)
        
        layout.addWidget(self.vulnerabilities_table)
        
        widget.setLayout(layout)
        return widget
    
    def _create_history_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Date", "Scan Name", "Targets", "Status", "Hosts", "Vulnerabilities"
        ])
        
        # Set column widths
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Date
        header.setSectionResizeMode(1, QHeaderView.Stretch)           # Scan Name
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Targets
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Hosts
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Vulnerabilities
        
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setSortingEnabled(True)
        
        layout.addWidget(self.history_table)
        
        # Load history button
        history_controls = QHBoxLayout()
        history_controls.addStretch()
        
        self.load_scan_btn = QPushButton("Load Selected Scan")
        history_controls.addWidget(self.load_scan_btn)
        
        self.delete_scan_btn = QPushButton("Delete Selected Scan")
        history_controls.addWidget(self.delete_scan_btn)
        
        layout.addLayout(history_controls)
        
        widget.setLayout(layout)
        return widget
    
    def _connect_signals(self):
        # Button signals
        self.generate_report_btn.clicked.connect(lambda: self.generate_report_requested.emit())
        self.export_csv_btn.clicked.connect(lambda: self.export_requested.emit('csv'))
        self.export_json_btn.clicked.connect(lambda: self.export_requested.emit('json'))
        self.export_xml_btn.clicked.connect(lambda: self.export_requested.emit('xml'))
        
        # History controls
        self.load_scan_btn.clicked.connect(self._load_selected_scan)
        self.delete_scan_btn.clicked.connect(self._delete_selected_scan)
        
        # Filter
        self.filter_input.textChanged.connect(self._apply_filter)
        self.filter_column_combo.currentTextChanged.connect(self._apply_filter)
        
        # Table selection changes
        self.vulnerabilities_table.itemSelectionChanged.connect(self._on_vulnerability_selected)
    
    def refresh_session_data(self, session_id):
        self.current_session_id = session_id
        
        if not session_id:
            self.clear_results()
            return
        
        self._refresh_hosts_data()
        self._refresh_ports_data()
        self._refresh_vulnerabilities_data()
        self._update_summary_statistics()
    
    def _refresh_hosts_data(self):
        if not self.current_session_id:
            return
        
        hosts = self.db_manager.get_session_hosts(self.current_session_id)
        
        self.hosts_table.setRowCount(len(hosts))
        
        for row, host in enumerate(hosts):
            self.hosts_table.setItem(row, 0, QTableWidgetItem(host['ip_address']))
            self.hosts_table.setItem(row, 1, QTableWidgetItem(host.get('hostname', '')))
            self.hosts_table.setItem(row, 2, QTableWidgetItem(host.get('os_name', 'Unknown')))
            self.hosts_table.setItem(row, 3, QTableWidgetItem(host['status'].title()))
            self.hosts_table.setItem(row, 4, QTableWidgetItem(str(host.get('port_count', 0))))
            self.hosts_table.setItem(row, 5, QTableWidgetItem(str(host.get('vulnerability_count', 0))))
            
            response_time = host.get('response_time')
            response_str = f"{response_time:.2f}ms" if response_time else "N/A"
            self.hosts_table.setItem(row, 6, QTableWidgetItem(response_str))
    
    def _refresh_ports_data(self):
        if not self.current_session_id:
            return
        
        hosts = self.db_manager.get_session_hosts(self.current_session_id)
        all_ports = []
        
        for host in hosts:
            ports = self.db_manager.get_host_ports(host['id'])
            for port in ports:
                port['host_ip'] = host['ip_address']
                all_ports.append(port)
        
        self.ports_table.setRowCount(len(all_ports))
        
        for row, port in enumerate(all_ports):
            self.ports_table.setItem(row, 0, QTableWidgetItem(port['host_ip']))
            self.ports_table.setItem(row, 1, QTableWidgetItem(str(port['port_number'])))
            self.ports_table.setItem(row, 2, QTableWidgetItem(port['state'].title()))
            self.ports_table.setItem(row, 3, QTableWidgetItem(port.get('service_name', 'Unknown')))
            self.ports_table.setItem(row, 4, QTableWidgetItem(port.get('service_version', '')))
            self.ports_table.setItem(row, 5, QTableWidgetItem(port['protocol'].upper()))
    
    def _refresh_vulnerabilities_data(self):
        if not self.current_session_id:
            return
        
        hosts = self.db_manager.get_session_hosts(self.current_session_id)
        all_vulnerabilities = []
        vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for host in hosts:
            vulnerabilities = self.db_manager.get_host_vulnerabilities(host['id'])
            for vuln in vulnerabilities:
                vuln['host_ip'] = host['ip_address']
                all_vulnerabilities.append(vuln)
                
                # Count by severity
                severity = vuln.get('severity', 'low').lower()
                if severity in vuln_counts:
                    vuln_counts[severity] += 1
        
        # Update vulnerability counts
        self.critical_label.setText(f"Critical: {vuln_counts['critical']}")
        self.high_label.setText(f"High: {vuln_counts['high']}")
        self.medium_label.setText(f"Medium: {vuln_counts['medium']}")
        self.low_label.setText(f"Low: {vuln_counts['low']}")
        
        # Update table
        self.vulnerabilities_table.setRowCount(len(all_vulnerabilities))
        
        for row, vuln in enumerate(all_vulnerabilities):
            self.vulnerabilities_table.setItem(row, 0, QTableWidgetItem(vuln['host_ip']))
            self.vulnerabilities_table.setItem(row, 1, QTableWidgetItem(vuln.get('title', 'Unknown')))
            self.vulnerabilities_table.setItem(row, 2, QTableWidgetItem(vuln.get('severity', 'Low')))
            
            cvss_score = vuln.get('cvss_score', 0.0)
            cvss_str = f"{cvss_score:.1f}" if cvss_score > 0 else "N/A"
            self.vulnerabilities_table.setItem(row, 3, QTableWidgetItem(cvss_str))
            
            self.vulnerabilities_table.setItem(row, 4, QTableWidgetItem(vuln.get('cve_id', 'N/A')))
            self.vulnerabilities_table.setItem(row, 5, QTableWidgetItem(str(vuln.get('port_id', 'N/A'))))
    
    def _update_summary_statistics(self):
        if not self.current_session_id:
            self.stats_label.setText("Hosts: 0 | Open Ports: 0 | Vulnerabilities: 0")
            return
        
        session_data = self.db_manager.get_scan_session_details(self.current_session_id)
        if not session_data:
            return
        
        hosts_count = session_data.get('total_hosts', 0)
        ports_count = session_data.get('total_ports', 0)
        vulns_count = session_data.get('vulnerabilities', 0)
        
        self.stats_label.setText(f"Hosts: {hosts_count} | Open Ports: {ports_count} | Vulnerabilities: {vulns_count}")
    
    def _auto_refresh(self):
        if self.current_session_id:
            self.refresh_session_data(self.current_session_id)
    
    def load_previous_scan(self):
        self._refresh_history_data()
        self.tab_widget.setCurrentWidget(self.history_tab)
    
    def _refresh_history_data(self):
        sessions = self.db_manager.get_scan_sessions(50)  # Get last 50 sessions
        
        self.history_table.setRowCount(len(sessions))
        
        for row, session in enumerate(sessions):
            start_time = session.get('start_time', '')
            if start_time:
                try:
                    dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                    date_str = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    date_str = start_time
            else:
                date_str = 'Unknown'
            
            self.history_table.setItem(row, 0, QTableWidgetItem(date_str))
            self.history_table.setItem(row, 1, QTableWidgetItem(session.get('name', '')))
            self.history_table.setItem(row, 2, QTableWidgetItem(session.get('targets', '')))
            self.history_table.setItem(row, 3, QTableWidgetItem(session.get('status', '').title()))
            self.history_table.setItem(row, 4, QTableWidgetItem(str(session.get('total_hosts', 0))))
            self.history_table.setItem(row, 5, QTableWidgetItem(str(session.get('vulnerabilities', 0))))
            
            # Store session ID in the first column for later retrieval
            item = self.history_table.item(row, 0)
            item.setData(Qt.UserRole, session['session_id'])
    
    def _load_selected_scan(self):
        current_row = self.history_table.currentRow()
        if current_row < 0:
            QMessageBox.information(self, "No Selection", "Please select a scan to load.")
            return
        
        item = self.history_table.item(current_row, 0)
        session_id = item.data(Qt.UserRole)
        
        if session_id:
            self.refresh_session_data(session_id)
            self.tab_widget.setCurrentIndex(0)  # Switch to hosts tab
            QMessageBox.information(self, "Scan Loaded", f"Loaded scan data for session {session_id[:8]}...")
    
    def _delete_selected_scan(self):
        current_row = self.history_table.currentRow()
        if current_row < 0:
            QMessageBox.information(self, "No Selection", "Please select a scan to delete.")
            return
        
        item = self.history_table.item(current_row, 0)
        session_id = item.data(Qt.UserRole)
        scan_name = self.history_table.item(current_row, 1).text()
        
        reply = QMessageBox.question(
            self,
            "Delete Scan",
            f"Are you sure you want to delete scan '{scan_name}'?\n\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success = self.db_manager.delete_scan_session(session_id)
            if success:
                self._refresh_history_data()
                QMessageBox.information(self, "Scan Deleted", "Scan has been deleted successfully.")
            else:
                QMessageBox.critical(self, "Delete Failed", "Failed to delete scan. Check logs for details.")
    
    def _apply_filter(self):
        filter_text = self.filter_input.text().lower()
        filter_column = self.filter_column_combo.currentText()
        
        # Apply filter to current tab's table
        current_widget = self.tab_widget.currentWidget()
        
        if current_widget == self.hosts_tab:
            self._filter_table(self.hosts_table, filter_text, filter_column)
        elif current_widget == self.ports_tab:
            self._filter_table(self.ports_table, filter_text, filter_column)
        elif current_widget == self.vulnerabilities_tab:
            self._filter_table(self.vulnerabilities_table, filter_text, filter_column)
        elif current_widget == self.history_tab:
            self._filter_table(self.history_table, filter_text, filter_column)
    
    def _filter_table(self, table, filter_text, filter_column):
        if not filter_text:
            # Show all rows
            for row in range(table.rowCount()):
                table.setRowHidden(row, False)
            return
        
        for row in range(table.rowCount()):
            should_hide = True
            
            if filter_column == "All":
                # Search in all columns
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    if item and filter_text in item.text().lower():
                        should_hide = False
                        break
            else:
                # Search in specific column
                column_map = {
                    "Host": 0,
                    "Port": 1,
                    "Service": 3,
                    "Vulnerability": 1
                }
                
                col_index = column_map.get(filter_column, 0)
                if col_index < table.columnCount():
                    item = table.item(row, col_index)
                    if item and filter_text in item.text().lower():
                        should_hide = False
            
            table.setRowHidden(row, should_hide)
    
    def _on_vulnerability_selected(self):
        current_row = self.vulnerabilities_table.currentRow()
        if current_row < 0:
            return
        
        try:
            # Get vulnerability details from the selected row
            host_ip = self.vulnerabilities_table.item(current_row, 0).text()
            vuln_title = self.vulnerabilities_table.item(current_row, 1).text()
            severity = self.vulnerabilities_table.item(current_row, 2).text()
            cvss_score = self.vulnerabilities_table.item(current_row, 3).text()
            cve_id = self.vulnerabilities_table.item(current_row, 4).text()
            port = self.vulnerabilities_table.item(current_row, 5).text()
            
            # Find the actual vulnerability data from database
            hosts = self.db_manager.get_session_hosts(self.current_session_id)
            vuln_data = None
            
            for host in hosts:
                if host['ip_address'] == host_ip:
                    vulnerabilities = self.db_manager.get_host_vulnerabilities(host['id'])
                    for vuln in vulnerabilities:
                        if vuln.get('title', '') == vuln_title:
                            vuln_data = vuln
                            break
                    break
            
            if vuln_data:
                self._show_vulnerability_details_dialog(vuln_data, host_ip, port)
        except Exception as e:
            self.logger.error(f"Error showing vulnerability details: {e}")
    
    def _show_vulnerability_details_dialog(self, vuln_data, host_ip, port):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QScrollArea
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QFont
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Vulnerability Details - {vuln_data.get('title', 'Unknown')}")
        dialog.setModal(True)
        dialog.resize(700, 500)
        
        layout = QVBoxLayout()
        
        # Create scroll area for content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        
        # Title section
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(14)
        
        title_label = QLabel(vuln_data.get('title', 'Unknown Vulnerability'))
        title_label.setFont(title_font)
        title_label.setWordWrap(True)
        content_layout.addWidget(title_label)
        
        # Basic information section
        info_layout = QVBoxLayout()
        
        # Host and port info
        host_info = QLabel(f"<b>Host:</b> {host_ip} | <b>Port:</b> {port}")
        host_info.setTextFormat(Qt.RichText)
        info_layout.addWidget(host_info)
        
        # CVE ID
        cve_id = vuln_data.get('cve_id', 'N/A')
        if cve_id and cve_id != 'N/A':
            cve_label = QLabel(f"<b>CVE ID:</b> <a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}'>{cve_id}</a>")
            cve_label.setTextFormat(Qt.RichText)
            cve_label.setOpenExternalLinks(True)
        else:
            cve_label = QLabel(f"<b>CVE ID:</b> {cve_id}")
            cve_label.setTextFormat(Qt.RichText)
        info_layout.addWidget(cve_label)
        
        # Severity and CVSS
        severity = vuln_data.get('severity', 'Unknown')
        cvss_score = vuln_data.get('cvss_score', 0.0)
        
        severity_color = {
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#28a745'
        }.get(severity, '#6c757d')
        
        severity_label = QLabel(f"<b>Severity:</b> <span style='color: {severity_color}; font-weight: bold;'>{severity}</span> | <b>CVSS Score:</b> {cvss_score:.1f}/10.0")
        severity_label.setTextFormat(Qt.RichText)
        info_layout.addWidget(severity_label)
        
        content_layout.addLayout(info_layout)
        
        # Description section
        if vuln_data.get('description'):
            desc_label = QLabel("<b>Description:</b>")
            desc_label.setFont(QFont("", 10, QFont.Bold))
            content_layout.addWidget(desc_label)
            
            desc_text = QTextEdit()
            desc_text.setPlainText(vuln_data['description'])
            desc_text.setReadOnly(True)
            desc_text.setMaximumHeight(120)
            content_layout.addWidget(desc_text)
        
        # Solution section
        if vuln_data.get('solution'):
            solution_label = QLabel("<b>Recommended Solution:</b>")
            solution_label.setFont(QFont("", 10, QFont.Bold))
            content_layout.addWidget(solution_label)
            
            solution_text = QTextEdit()
            solution_text.setPlainText(vuln_data['solution'])
            solution_text.setReadOnly(True)
            solution_text.setMaximumHeight(100)
            content_layout.addWidget(solution_text)
        
        # CVSS Vector
        if vuln_data.get('cvss_vector'):
            cvss_label = QLabel(f"<b>CVSS Vector:</b> {vuln_data['cvss_vector']}")
            cvss_label.setTextFormat(Qt.RichText)
            cvss_label.setWordWrap(True)
            content_layout.addWidget(cvss_label)
        
        # References section
        try:
            references = vuln_data.get('vuln_references', '[]')
            if isinstance(references, str):
                import json
                references = json.loads(references)
            
            if references and len(references) > 0:
                ref_label = QLabel("<b>References:</b>")
                ref_label.setFont(QFont("", 10, QFont.Bold))
                content_layout.addWidget(ref_label)
                
                for ref in references[:5]:  # Limit to 5 references
                    if ref.startswith('http'):
                        ref_link = QLabel(f"• <a href='{ref}'>{ref}</a>")
                        ref_link.setTextFormat(Qt.RichText)
                        ref_link.setOpenExternalLinks(True)
                    else:
                        ref_link = QLabel(f"• {ref}")
                    ref_link.setWordWrap(True)
                    content_layout.addWidget(ref_link)
        except Exception as e:
            self.logger.debug(f"Error parsing references: {e}")
        
        # Detection timestamp
        if vuln_data.get('detected_at'):
            detected_label = QLabel(f"<b>Detected:</b> {vuln_data['detected_at']}")
            detected_label.setTextFormat(Qt.RichText)
            content_layout.addWidget(detected_label)
        
        # Set scroll area content
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)
        
        # Button section
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        close_button.setMinimumWidth(100)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        
        # Show dialog
        dialog.exec_()
    
    def clear_results(self):
        self.current_session_id = None
        
        self.hosts_table.setRowCount(0)
        self.ports_table.setRowCount(0)
        self.vulnerabilities_table.setRowCount(0)
        
        self.stats_label.setText("Hosts: 0 | Open Ports: 0 | Vulnerabilities: 0")
        
        self.critical_label.setText("Critical: 0")
        self.high_label.setText("High: 0")
        self.medium_label.setText("Medium: 0")
        self.low_label.setText("Low: 0")
    
    def export_results(self):
        if not self.current_session_id:
            QMessageBox.information(self, "No Data", "No scan data to export.")
            return
        
        # Open file dialog
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results",
            f"nethawk_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "CSV Files (*.csv);;JSON Files (*.json);;XML Files (*.xml)"
        )
        
        if file_path:
            format_type = 'csv'
            if file_path.endswith('.json'):
                format_type = 'json'
            elif file_path.endswith('.xml'):
                format_type = 'xml'
            
            self.export_requested.emit(format_type)
    
    def export_session_data(self, session_id, format_type):
        if format_type == 'csv':
            self._export_csv(session_id)
        elif format_type == 'json':
            self._export_json(session_id)
        elif format_type == 'xml':
            self._export_xml(session_id)
    
    def _export_csv(self, session_id):
        try:
            import csv
            
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export to CSV",
                f"nethawk_export_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "CSV Files (*.csv)"
            )
            
            if not file_path:
                return
            
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write headers
                writer.writerow(['Host IP', 'Hostname', 'Port', 'Protocol', 'Service', 'Version', 
                               'Vulnerability', 'Severity', 'CVSS Score', 'CVE ID'])
                
                # Get data
                hosts = self.db_manager.get_session_hosts(session_id)
                
                for host in hosts:
                    ports = self.db_manager.get_host_ports(host['id'])
                    vulns = self.db_manager.get_host_vulnerabilities(host['id'])
                    
                    # Write port data
                    for port in ports:
                        writer.writerow([
                            host['ip_address'],
                            host.get('hostname', ''),
                            port['port_number'],
                            port['protocol'],
                            port.get('service_name', ''),
                            port.get('service_version', ''),
                            '', '', '', ''  # Empty vuln fields
                        ])
                    
                    # Write vulnerability data
                    for vuln in vulns:
                        writer.writerow([
                            host['ip_address'],
                            host.get('hostname', ''),
                            '', '', '', '',  # Empty port fields
                            vuln.get('title', ''),
                            vuln.get('severity', ''),
                            vuln.get('cvss_score', ''),
                            vuln.get('cve_id', '')
                        ])
            
            QMessageBox.information(self, "Export Complete", f"Data exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export CSV: {str(e)}")
    
    def _export_json(self, session_id):
        try:
            import json
            
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export to JSON",
                f"nethawk_export_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json)"
            )
            
            if not file_path:
                return
            
            # Build export data structure
            export_data = {
                'session_id': session_id,
                'export_time': datetime.now().isoformat(),
                'hosts': []
            }
            
            hosts = self.db_manager.get_session_hosts(session_id)
            
            for host in hosts:
                host_data = {
                    'ip_address': host['ip_address'],
                    'hostname': host.get('hostname'),
                    'os_name': host.get('os_name'),
                    'status': host['status'],
                    'ports': [],
                    'vulnerabilities': []
                }
                
                # Add ports
                ports = self.db_manager.get_host_ports(host['id'])
                for port in ports:
                    host_data['ports'].append({
                        'port': port['port_number'],
                        'protocol': port['protocol'],
                        'state': port['state'],
                        'service': port.get('service_name'),
                        'version': port.get('service_version')
                    })
                
                # Add vulnerabilities
                vulns = self.db_manager.get_host_vulnerabilities(host['id'])
                for vuln in vulns:
                    host_data['vulnerabilities'].append({
                        'title': vuln.get('title'),
                        'severity': vuln.get('severity'),
                        'cvss_score': vuln.get('cvss_score'),
                        'cve_id': vuln.get('cve_id'),
                        'description': vuln.get('description')
                    })
                
                export_data['hosts'].append(host_data)
            
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, default=str)
            
            QMessageBox.information(self, "Export Complete", f"Data exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"JSON export failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export JSON: {str(e)}")
    
    def _export_xml(self, session_id):
        try:
            import xml.etree.ElementTree as ET
            
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export to XML",
                f"nethawk_export_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml",
                "XML Files (*.xml)"
            )
            
            if not file_path:
                return
            
            # Build XML structure
            root = ET.Element('nethawk_scan')
            root.set('session_id', session_id)
            root.set('export_time', datetime.now().isoformat())
            
            hosts = self.db_manager.get_session_hosts(session_id)
            
            for host in hosts:
                host_elem = ET.SubElement(root, 'host')
                host_elem.set('ip', host['ip_address'])
                host_elem.set('status', host['status'])
                
                if host.get('hostname'):
                    host_elem.set('hostname', host['hostname'])
                if host.get('os_name'):
                    host_elem.set('os', host['os_name'])
                
                # Add ports
                ports = self.db_manager.get_host_ports(host['id'])
                if ports:
                    ports_elem = ET.SubElement(host_elem, 'ports')
                    for port in ports:
                        port_elem = ET.SubElement(ports_elem, 'port')
                        port_elem.set('number', str(port['port_number']))
                        port_elem.set('protocol', port['protocol'])
                        port_elem.set('state', port['state'])
                        if port.get('service_name'):
                            port_elem.set('service', port['service_name'])
                        if port.get('service_version'):
                            port_elem.set('version', port['service_version'])
                
                # Add vulnerabilities
                vulns = self.db_manager.get_host_vulnerabilities(host['id'])
                if vulns:
                    vulns_elem = ET.SubElement(host_elem, 'vulnerabilities')
                    for vuln in vulns:
                        vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
                        vuln_elem.set('severity', vuln.get('severity', ''))
                        if vuln.get('cve_id'):
                            vuln_elem.set('cve_id', vuln['cve_id'])
                        if vuln.get('cvss_score'):
                            vuln_elem.set('cvss_score', str(vuln['cvss_score']))
                        
                        title_elem = ET.SubElement(vuln_elem, 'title')
                        title_elem.text = vuln.get('title', '')
                        
                        if vuln.get('description'):
                            desc_elem = ET.SubElement(vuln_elem, 'description')
                            desc_elem.text = vuln['description']
            
            # Write XML file
            tree = ET.ElementTree(root)
            tree.write(file_path, encoding='utf-8', xml_declaration=True)
            
            QMessageBox.information(self, "Export Complete", f"Data exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"XML export failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export XML: {str(e)}")