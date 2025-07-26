import nmap
import logging
import time
import json
import re
from typing import Dict, List, Optional, Callable, Any
from PyQt5.QtCore import QThread, pyqtSignal
import xml.etree.ElementTree as ET

class NmapScanner(QThread):
    scan_started = pyqtSignal(str)  # session_id
    host_discovered = pyqtSignal(str, dict)  # session_id, host_data
    port_discovered = pyqtSignal(str, str, dict)  # session_id, host_ip, port_data
    scan_progress = pyqtSignal(str, int, int)  # session_id, current, total
    scan_completed = pyqtSignal(str, dict)  # session_id, summary
    scan_error = pyqtSignal(str, str)  # session_id, error_message
    
    def __init__(self, session_id: str, targets: str, scan_options: Dict, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.session_id = session_id
        self.targets = targets
        self.scan_options = scan_options
        self.nm = nmap.PortScanner()
        self.is_cancelled = False
        self.scan_summary = {
            'total_hosts': 0,
            'hosts_up': 0,
            'hosts_down': 0,
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'start_time': None,
            'end_time': None,
            'elapsed_time': 0
        }
        
    def cancel_scan(self):
        self.is_cancelled = True
        self.logger.info(f"Scan cancellation requested for session: {self.session_id}")
    
    def run(self):
        try:
            self.scan_summary['start_time'] = time.time()
            self.scan_started.emit(self.session_id)
            
            self.logger.info(f"Starting nmap scan for session: {self.session_id}")
            self.logger.info(f"Targets: {self.targets}")
            self.logger.info(f"Options: {self.scan_options}")
            
            # Build nmap command arguments
            nmap_args = self._build_nmap_arguments()
            self.logger.debug(f"Nmap arguments: {nmap_args}")
            
            # Perform the scan
            self._execute_scan(nmap_args)
            
            if not self.is_cancelled:
                self.scan_summary['end_time'] = time.time()
                self.scan_summary['elapsed_time'] = self.scan_summary['end_time'] - self.scan_summary['start_time']
                self.scan_completed.emit(self.session_id, self.scan_summary)
                self.logger.info(f"Scan completed for session: {self.session_id}")
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.logger.error(f"Error in scan session {self.session_id}: {error_msg}")
            self.scan_error.emit(self.session_id, error_msg)
    
    def _build_nmap_arguments(self) -> str:
        args = []
        
        # Port specification
        if self.scan_options.get('ports'):
            ports = self.scan_options['ports']
            if ports.startswith('top-ports:'):
                top_count = ports.split(':')[1]
                args.append(f'--top-ports {top_count}')
            else:
                args.append(f'-p {ports}')
        
        # Timing template
        timing = self.scan_options.get('timing', 'T3')
        args.append(f'-{timing}')
        
        # Scan type options
        if self.scan_options.get('stealth_scan', False):
            args.append('-sS')  # SYN stealth scan
        elif self.scan_options.get('udp_scan', False):
            args.append('-sU')  # UDP scan
        else:
            args.append('-sT')  # TCP connect scan
        
        # Host discovery
        if not self.scan_options.get('ping_scan', True):
            args.append('-Pn')  # Skip ping
        
        # Service and OS detection
        if self.scan_options.get('service_detection', False):
            args.append('-sV')
        
        if self.scan_options.get('os_detection', False):
            args.append('-O')
        
        # Script scanning
        if self.scan_options.get('script_scan', False):
            args.append('-sC')  # Default scripts
        
        # Additional options
        if self.scan_options.get('aggressive', False):
            args.append('-A')  # Aggressive scan
        
        if self.scan_options.get('verbose', False):
            args.append('-v')
        
        # Packet fragmentation for evasion
        if self.scan_options.get('fragment_packets', False):
            args.append('-f')
        
        # Randomize host order
        if self.scan_options.get('randomize_hosts', False):
            args.append('--randomize-hosts')
        
        # Source port specification
        source_port = self.scan_options.get('source_port', 0)
        if source_port > 0:
            args.append(f'--source-port {source_port}')
        
        # Set timeout
        timeout = self.scan_options.get('timeout', 30)
        args.append(f'--host-timeout {timeout}s')
        
        # Always request XML output for parsing
        args.append('-oX -')
        
        # Resolve hostnames
        if not self.scan_options.get('resolve_hostnames', True):
            args.append('-n')
        
        return ' '.join(args)
    
    def _execute_scan(self, nmap_args: str):
        try:
            # Pre-process targets to estimate total work
            target_list = self._expand_targets(self.targets)
            total_targets = len(target_list)
            self.scan_summary['total_hosts'] = total_targets
            
            current_target = 0
            
            # If we have a small number of targets, scan them individually for better progress tracking
            if total_targets <= 100:
                for target in target_list:
                    if self.is_cancelled:
                        break
                    
                    current_target += 1
                    self.scan_progress.emit(self.session_id, current_target, total_targets)
                    
                    try:
                        result = self.nm.scan(target, arguments=nmap_args)
                        self._process_scan_result(result)
                    except Exception as e:
                        self.logger.warning(f"Failed to scan target {target}: {e}")
                        continue
            else:
                # For large scans, use nmap's batch processing
                try:
                    result = self.nm.scan(self.targets, arguments=nmap_args)
                    self._process_scan_result(result)
                except Exception as e:
                    self.logger.error(f"Batch scan failed: {e}")
                    raise
        
        except Exception as e:
            self.logger.error(f"Error executing scan: {e}")
            raise
    
    def _expand_targets(self, targets: str) -> List[str]:
        import ipaddress
        target_list = []
        
        for target in targets.split(','):
            target = target.strip()
            
            try:
                # Try to parse as IP network (CIDR)
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    target_list.extend([str(ip) for ip in network.hosts()])
                # Try to parse as IP range (e.g., 192.168.1.1-10)
                elif '-' in target and not target.replace('-', '').replace('.', '').isalpha():
                    parts = target.split('-')
                    if len(parts) == 2:
                        start_ip = parts[0].strip()
                        end_part = parts[1].strip()
                        
                        # Handle format like 192.168.1.1-10
                        if '.' not in end_part:
                            ip_parts = start_ip.split('.')
                            if len(ip_parts) == 4:
                                start_last = int(ip_parts[3])
                                end_last = int(end_part)
                                for i in range(start_last, end_last + 1):
                                    ip_parts[3] = str(i)
                                    target_list.append('.'.join(ip_parts))
                        else:
                            # Handle format like 192.168.1.1-192.168.1.10
                            start_ip_obj = ipaddress.ip_address(start_ip)
                            end_ip_obj = ipaddress.ip_address(end_part)
                            current = start_ip_obj
                            while current <= end_ip_obj:
                                target_list.append(str(current))
                                current += 1
                else:
                    # Single IP or hostname
                    target_list.append(target)
            
            except Exception as e:
                self.logger.warning(f"Could not parse target '{target}': {e}")
                target_list.append(target)  # Add as-is and let nmap handle it
        
        return target_list
    
    def _process_scan_result(self, scan_result: Dict):
        if 'scan' not in scan_result:
            return
        
        for host_ip, host_data in scan_result['scan'].items():
            if self.is_cancelled:
                break
            
            # Process host information
            host_info = self._extract_host_info(host_ip, host_data)
            self.host_discovered.emit(self.session_id, host_info)
            
            # Update summary
            if host_info['status'] == 'up':
                self.scan_summary['hosts_up'] += 1
            else:
                self.scan_summary['hosts_down'] += 1
            
            # Process ports if host is up
            if host_info['status'] == 'up' and 'tcp' in host_data:
                for port_num, port_data in host_data['tcp'].items():
                    if self.is_cancelled:
                        break
                    
                    port_info = self._extract_port_info(port_num, port_data, 'tcp')
                    self.port_discovered.emit(self.session_id, host_ip, port_info)
                    
                    # Update port summary
                    self.scan_summary['total_ports'] += 1
                    if port_info['state'] == 'open':
                        self.scan_summary['open_ports'] += 1
                    elif port_info['state'] == 'closed':
                        self.scan_summary['closed_ports'] += 1
                    elif port_info['state'] == 'filtered':
                        self.scan_summary['filtered_ports'] += 1
            
            # Process UDP ports if scanned
            if host_info['status'] == 'up' and 'udp' in host_data:
                for port_num, port_data in host_data['udp'].items():
                    if self.is_cancelled:
                        break
                    
                    port_info = self._extract_port_info(port_num, port_data, 'udp')
                    self.port_discovered.emit(self.session_id, host_ip, port_info)
                    
                    self.scan_summary['total_ports'] += 1
                    if port_info['state'] == 'open':
                        self.scan_summary['open_ports'] += 1
                    elif port_info['state'] == 'closed':
                        self.scan_summary['closed_ports'] += 1
                    elif port_info['state'] == 'filtered':
                        self.scan_summary['filtered_ports'] += 1
    
    def _extract_host_info(self, host_ip: str, host_data: Dict) -> Dict:
        host_info = {
            'ip_address': host_ip,
            'hostname': None,
            'mac_address': None,
            'os_name': None,
            'os_version': None,
            'os_accuracy': 0,
            'status': host_data.get('status', {}).get('state', 'unknown'),
            'response_time': None
        }
        
        # Extract hostname
        hostnames = host_data.get('hostnames', [])
        if hostnames and len(hostnames) > 0:
            host_info['hostname'] = hostnames[0].get('name', '')
        
        # Extract MAC address
        addresses = host_data.get('addresses', {})
        if 'mac' in addresses:
            host_info['mac_address'] = addresses['mac']
        
        # Extract OS information
        if 'osmatch' in host_data:
            os_matches = host_data['osmatch']
            if os_matches and len(os_matches) > 0:
                best_match = os_matches[0]
                host_info['os_name'] = best_match.get('name', '')
                host_info['os_accuracy'] = int(best_match.get('accuracy', 0))
                
                # Try to extract version from OS name
                os_name = host_info['os_name']
                version_match = re.search(r'(\d+\.?\d*\.?\d*)', os_name)
                if version_match:
                    host_info['os_version'] = version_match.group(1)
        
        # Extract response time from uptime or other sources
        uptime = host_data.get('uptime', {})
        if 'lastboot' in uptime:
            host_info['response_time'] = 0.0  # Dummy value, real response time from ping
        
        return host_info
    
    def _extract_port_info(self, port_num: int, port_data: Dict, protocol: str) -> Dict:
        port_info = {
            'port_number': port_num,
            'protocol': protocol,
            'state': port_data.get('state', 'unknown'),
            'service_name': port_data.get('name', ''),
            'service_version': port_data.get('version', ''),
            'service_product': port_data.get('product', ''),
            'service_extra_info': port_data.get('extrainfo', ''),
            'tunnel': port_data.get('tunnel', ''),
            'method': port_data.get('method', ''),
            'confidence': int(port_data.get('conf', 0))
        }
        
        # Create service fingerprint
        service_parts = []
        if port_info['service_product']:
            service_parts.append(port_info['service_product'])
        if port_info['service_version']:
            service_parts.append(port_info['service_version'])
        if port_info['service_extra_info']:
            service_parts.append(port_info['service_extra_info'])
        
        port_info['service_fingerprint'] = ' '.join(service_parts)
        
        return port_info

class NmapScanManager:
    def __init__(self, database_manager):
        self.logger = logging.getLogger(__name__)
        self.db_manager = database_manager
        self.active_scans = {}
    
    def start_scan(self, session_id: str, name: str, targets: str, scan_options: Dict, 
                   progress_callback: Optional[Callable] = None) -> bool:
        try:
            if session_id in self.active_scans:
                self.logger.warning(f"Scan session {session_id} is already active")
                return False
            
            # Create database entry
            if not self.db_manager.create_scan_session(session_id, name, targets, 
                                                     scan_options.get('profile', 'Custom'), scan_options):
                return False
            
            # Create and start scanner thread
            scanner = NmapScanner(session_id, targets, scan_options)
            
            # Connect signals
            scanner.scan_started.connect(self._on_scan_started)
            scanner.host_discovered.connect(self._on_host_discovered)
            scanner.port_discovered.connect(self._on_port_discovered)
            scanner.scan_progress.connect(self._on_scan_progress)
            scanner.scan_completed.connect(self._on_scan_completed)
            scanner.scan_error.connect(self._on_scan_error)
            
            if progress_callback:
                scanner.scan_progress.connect(progress_callback)
            
            self.active_scans[session_id] = scanner
            scanner.start()
            
            self.logger.info(f"Started scan session: {session_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start scan: {e}")
            return False
    
    def cancel_scan(self, session_id: str) -> bool:
        if session_id in self.active_scans:
            scanner = self.active_scans[session_id]
            scanner.cancel_scan()
            scanner.wait(5000)  # Wait up to 5 seconds for clean shutdown
            
            if scanner.isRunning():
                scanner.terminate()
                scanner.wait(2000)
            
            del self.active_scans[session_id]
            
            # Update database
            self.db_manager.update_scan_session(session_id, status='cancelled', end_time=time.time())
            
            self.logger.info(f"Cancelled scan session: {session_id}")
            return True
        
        return False
    
    def get_active_scans(self) -> List[str]:
        return list(self.active_scans.keys())
    
    def is_scan_active(self, session_id: str) -> bool:
        return session_id in self.active_scans
    
    def _on_scan_started(self, session_id: str):
        self.logger.info(f"Scan started: {session_id}")
        self.db_manager.log_scan_event(session_id, 'scan_started')
    
    def _on_host_discovered(self, session_id: str, host_data: Dict):
        self.logger.debug(f"Host discovered in {session_id}: {host_data['ip_address']}")
        
        # Add host to database
        host_id = self.db_manager.add_host(session_id, **host_data)
        if host_id:
            host_data['id'] = host_id
            self.db_manager.log_scan_event(session_id, 'host_discovered', 
                                         {'ip': host_data['ip_address'], 'status': host_data['status']})
    
    def _on_port_discovered(self, session_id: str, host_ip: str, port_data: Dict):
        self.logger.debug(f"Port discovered in {session_id}: {host_ip}:{port_data['port_number']}")
        
        # Find host ID
        hosts = self.db_manager.get_session_hosts(session_id)
        host_id = None
        for host in hosts:
            if host['ip_address'] == host_ip:
                host_id = host['id']
                break
        
        if host_id:
            port_id = self.db_manager.add_port(host_id, **port_data)
            if port_id:
                self.db_manager.log_scan_event(session_id, 'port_discovered', 
                                             {'host': host_ip, 'port': port_data['port_number'], 
                                              'state': port_data['state']})
    
    def _on_scan_progress(self, session_id: str, current: int, total: int):
        self.logger.debug(f"Scan progress {session_id}: {current}/{total}")
    
    def _on_scan_completed(self, session_id: str, summary: Dict):
        self.logger.info(f"Scan completed: {session_id}")
        
        # Update database with final statistics
        self.db_manager.update_scan_session(
            session_id,
            status='completed',
            end_time=summary['end_time'],
            total_hosts=summary['hosts_up'] + summary['hosts_down'],
            total_ports=summary['total_ports']
        )
        
        self.db_manager.log_scan_event(session_id, 'scan_completed', summary)
        
        # Clean up
        if session_id in self.active_scans:
            del self.active_scans[session_id]
    
    def _on_scan_error(self, session_id: str, error_message: str):
        self.logger.error(f"Scan error in {session_id}: {error_message}")
        
        self.db_manager.update_scan_session(session_id, status='error', end_time=time.time())
        self.db_manager.log_scan_event(session_id, 'scan_error', {'error': error_message})
        
        # Clean up
        if session_id in self.active_scans:
            del self.active_scans[session_id]