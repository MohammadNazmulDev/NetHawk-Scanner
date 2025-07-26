import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'database')
        os.makedirs(self.db_dir, exist_ok=True)
        
        self.db_path = os.path.join(self.db_dir, 'nethawk_scanner.db')
        self._initialize_database()
    
    def _initialize_database(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scan sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    status TEXT NOT NULL DEFAULT 'running',
                    total_hosts INTEGER DEFAULT 0,
                    total_ports INTEGER DEFAULT 0,
                    vulnerabilities INTEGER DEFAULT 0,
                    scan_options TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Hosts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    hostname TEXT,
                    mac_address TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    os_accuracy INTEGER,
                    status TEXT NOT NULL,
                    response_time REAL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
                )
            ''')
            
            # Ports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    service_name TEXT,
                    service_version TEXT,
                    service_product TEXT,
                    service_extra_info TEXT,
                    tunnel TEXT,
                    method TEXT,
                    confidence INTEGER,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port_id INTEGER,
                    cve_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    solution TEXT,
                    vuln_references TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Scan history for tracking and analytics
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
                )
            ''')
            
            # User preferences
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_preferences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # CVE database cache
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    vuln_references TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_session_id ON hosts (session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts (ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports (host_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_number ON ports (port_number)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id ON vulnerabilities (host_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities (cve_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_history_session ON scan_history (session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_cache_id ON cve_cache (cve_id)')
            
            conn.commit()
            self.logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def create_scan_session(self, session_id: str, name: str, targets: str, scan_type: str, scan_options: Dict = None) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_sessions (session_id, name, targets, scan_type, start_time, scan_options)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session_id, name, targets, scan_type, datetime.now(), json.dumps(scan_options) if scan_options else None))
                conn.commit()
                self.logger.info(f"Created scan session: {session_id}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to create scan session: {e}")
            return False
    
    def update_scan_session(self, session_id: str, **kwargs) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                set_clauses = []
                values = []
                
                for key, value in kwargs.items():
                    if key in ['end_time', 'status', 'total_hosts', 'total_ports', 'vulnerabilities']:
                        set_clauses.append(f"{key} = ?")
                        values.append(value)
                
                if not set_clauses:
                    return False
                
                values.append(session_id)
                query = f"UPDATE scan_sessions SET {', '.join(set_clauses)} WHERE session_id = ?"
                
                cursor.execute(query, values)
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to update scan session: {e}")
            return False
    
    def add_host(self, session_id: str, ip_address: str, hostname: str = None, status: str = 'up', **kwargs) -> Optional[int]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO hosts (session_id, ip_address, hostname, status, mac_address, 
                                     os_name, os_version, os_accuracy, response_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session_id, ip_address, hostname, status, 
                      kwargs.get('mac_address'), kwargs.get('os_name'), 
                      kwargs.get('os_version'), kwargs.get('os_accuracy'), 
                      kwargs.get('response_time')))
                
                host_id = cursor.lastrowid
                conn.commit()
                return host_id
        except Exception as e:
            self.logger.error(f"Failed to add host: {e}")
            return None
    
    def add_port(self, host_id: int, port_number: int, protocol: str, state: str, **kwargs) -> Optional[int]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO ports (host_id, port_number, protocol, state, service_name,
                                     service_version, service_product, service_extra_info,
                                     tunnel, method, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (host_id, port_number, protocol, state, kwargs.get('service_name'),
                      kwargs.get('service_version'), kwargs.get('service_product'),
                      kwargs.get('service_extra_info'), kwargs.get('tunnel'),
                      kwargs.get('method'), kwargs.get('confidence')))
                
                port_id = cursor.lastrowid
                conn.commit()
                return port_id
        except Exception as e:
            self.logger.error(f"Failed to add port: {e}")
            return None
    
    def add_vulnerability(self, host_id: int, title: str, severity: str, **kwargs) -> Optional[int]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO vulnerabilities (host_id, port_id, cve_id, title, description,
                                               severity, cvss_score, cvss_vector, solution, vuln_references)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (host_id, kwargs.get('port_id'), kwargs.get('cve_id'), title,
                      kwargs.get('description'), severity, kwargs.get('cvss_score'),
                      kwargs.get('cvss_vector'), kwargs.get('solution'),
                      json.dumps(kwargs.get('vuln_references', []))))
                
                vuln_id = cursor.lastrowid
                conn.commit()
                return vuln_id
        except Exception as e:
            self.logger.error(f"Failed to add vulnerability: {e}")
            return None
    
    def get_scan_sessions(self, limit: int = 100) -> List[Dict]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM scan_sessions 
                    ORDER BY start_time DESC 
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Failed to get scan sessions: {e}")
            return []
    
    def get_scan_session_details(self, session_id: str) -> Optional[Dict]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM scan_sessions WHERE session_id = ?', (session_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            self.logger.error(f"Failed to get scan session details: {e}")
            return None
    
    def get_session_hosts(self, session_id: str) -> List[Dict]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT h.*, COUNT(p.id) as port_count, COUNT(v.id) as vulnerability_count
                    FROM hosts h
                    LEFT JOIN ports p ON h.id = p.host_id
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                    WHERE h.session_id = ?
                    GROUP BY h.id
                    ORDER BY h.ip_address
                ''', (session_id,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Failed to get session hosts: {e}")
            return []
    
    def get_host_ports(self, host_id: int) -> List[Dict]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ports WHERE host_id = ? ORDER BY port_number', (host_id,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Failed to get host ports: {e}")
            return []
    
    def get_host_vulnerabilities(self, host_id: int) -> List[Dict]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM vulnerabilities 
                    WHERE host_id = ? 
                    ORDER BY cvss_score DESC, severity DESC
                ''', (host_id,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Failed to get host vulnerabilities: {e}")
            return []
    
    def delete_scan_session(self, session_id: str) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Delete in reverse order of dependencies
                cursor.execute('DELETE FROM scan_history WHERE session_id = ?', (session_id,))
                cursor.execute('DELETE FROM vulnerabilities WHERE host_id IN (SELECT id FROM hosts WHERE session_id = ?)', (session_id,))
                cursor.execute('DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE session_id = ?)', (session_id,))
                cursor.execute('DELETE FROM hosts WHERE session_id = ?', (session_id,))
                cursor.execute('DELETE FROM scan_sessions WHERE session_id = ?', (session_id,))
                
                conn.commit()
                self.logger.info(f"Deleted scan session: {session_id}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to delete scan session: {e}")
            return False
    
    def cache_cve_data(self, cve_id: str, data: Dict) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO cve_cache 
                    (cve_id, description, severity, cvss_score, cvss_vector, 
                     published_date, modified_date, vuln_references)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (cve_id, data.get('description'), data.get('severity'),
                      data.get('cvss_score'), data.get('cvss_vector'),
                      data.get('published_date'), data.get('modified_date'),
                      json.dumps(data.get('references', []))))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to cache CVE data: {e}")
            return False
    
    def get_cached_cve_data(self, cve_id: str) -> Optional[Dict]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM cve_cache WHERE cve_id = ?', (cve_id,))
                row = cursor.fetchone()
                if row:
                    data = dict(row)
                    if data.get('vuln_references'):
                        data['references'] = json.loads(data['vuln_references'])
                    return data
                return None
        except Exception as e:
            self.logger.error(f"Failed to get cached CVE data: {e}")
            return None
    
    def log_scan_event(self, session_id: str, event_type: str, event_data: Dict = None) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_history (session_id, event_type, event_data)
                    VALUES (?, ?, ?)
                ''', (session_id, event_type, json.dumps(event_data) if event_data else None))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to log scan event: {e}")
            return False
    
    def backup_database(self, backup_path: str) -> bool:
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            self.logger.info(f"Database backed up to: {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to backup database: {e}")
            return False
    
    def get_database_stats(self) -> Dict:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                tables = ['scan_sessions', 'hosts', 'ports', 'vulnerabilities', 'cve_cache']
                
                for table in tables:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    stats[f'{table}_count'] = cursor.fetchone()[0]
                
                # Get database file size
                stats['database_size'] = os.path.getsize(self.db_path)
                
                return stats
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {e}")
            return {}