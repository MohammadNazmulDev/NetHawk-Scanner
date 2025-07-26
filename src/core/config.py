import json
import os
import logging
from PyQt5.QtCore import QSettings
from typing import Dict, Any, List

class ConfigManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'config')
        os.makedirs(self.config_dir, exist_ok=True)
        
        self.settings = QSettings("NetHawk", "Scanner")
        self.scan_profiles_file = os.path.join(self.config_dir, 'scan_profiles.json')
        self.app_config_file = os.path.join(self.config_dir, 'app_config.json')
        
        self._load_default_config()
        self._load_scan_profiles()
    
    def _load_default_config(self):
        self.default_config = {
            'window': {
                'width': 1200,
                'height': 800,
                'maximized': False
            },
            'scanning': {
                'max_threads': 50,
                'timeout': 30,
                'max_retries': 3,
                'timing_template': 'T3',
                'ping_before_scan': True,
                'resolve_hostnames': True
            },
            'reports': {
                'default_format': 'pdf',
                'include_raw_data': False,
                'auto_open': True
            },
            'security': {
                'require_confirmation': True,
                'audit_all_scans': True,
                'encrypt_reports': False
            },
            'network': {
                'source_port': 0,
                'fragment_packets': False,
                'randomize_hosts': False,
                'decoy_scan': False
            }
        }
        
        if os.path.exists(self.app_config_file):
            try:
                with open(self.app_config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self._merge_config(self.default_config, loaded_config)
            except Exception as e:
                self.logger.error(f"Failed to load app config: {e}")
    
    def _load_scan_profiles(self):
        self.scan_profiles = {
            'Quick Scan': {
                'ports': '22,80,443,3389',
                'timing': 'T4',
                'ping_scan': True,
                'service_detection': False,
                'os_detection': False,
                'script_scan': False,
                'udp_scan': False,
                'stealth_scan': False
            },
            'Comprehensive Scan': {
                'ports': '1-65535',
                'timing': 'T3',
                'ping_scan': True,
                'service_detection': True,
                'os_detection': True,
                'script_scan': True,
                'udp_scan': True,
                'stealth_scan': False
            },
            'Stealth Scan': {
                'ports': '22,80,443,21,25,53,110,995,993,143,993',
                'timing': 'T1',
                'ping_scan': False,
                'service_detection': True,
                'os_detection': False,
                'script_scan': False,
                'udp_scan': False,
                'stealth_scan': True
            },
            'Web Ports': {
                'ports': '80,443,8080,8443,8000,8888,9000,3000,5000',
                'timing': 'T3',
                'ping_scan': True,
                'service_detection': True,
                'os_detection': False,
                'script_scan': True,
                'udp_scan': False,
                'stealth_scan': False
            },
            'Top 1000 Ports': {
                'ports': 'top-ports:1000',
                'timing': 'T3',
                'ping_scan': True,
                'service_detection': True,
                'os_detection': True,
                'script_scan': False,
                'udp_scan': False,
                'stealth_scan': False
            }
        }
        
        if os.path.exists(self.scan_profiles_file):
            try:
                with open(self.scan_profiles_file, 'r') as f:
                    loaded_profiles = json.load(f)
                    self.scan_profiles.update(loaded_profiles)
            except Exception as e:
                self.logger.error(f"Failed to load scan profiles: {e}")
    
    def _merge_config(self, default_dict, loaded_dict):
        for key, value in loaded_dict.items():
            if key in default_dict and isinstance(default_dict[key], dict) and isinstance(value, dict):
                self._merge_config(default_dict[key], value)
            else:
                default_dict[key] = value
    
    def get_config(self, section: str = None, key: str = None, default=None):
        if section is None:
            return self.default_config
        
        if section in self.default_config:
            if key is None:
                return self.default_config[section]
            return self.default_config[section].get(key, default)
        
        return default
    
    def set_config(self, section: str, key: str = None, value: Any = None):
        if key is None:
            if isinstance(section, dict):
                self.default_config.update(section)
            return
        
        if section not in self.default_config:
            self.default_config[section] = {}
        
        self.default_config[section][key] = value
        self.save_config()
    
    def save_config(self):
        try:
            with open(self.app_config_file, 'w') as f:
                json.dump(self.default_config, f, indent=2)
            self.logger.debug("Configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def get_scan_profiles(self) -> Dict[str, Dict]:
        return self.scan_profiles
    
    def get_scan_profile(self, name: str) -> Dict:
        return self.scan_profiles.get(name, {})
    
    def save_scan_profile(self, name: str, profile: Dict):
        self.scan_profiles[name] = profile
        try:
            with open(self.scan_profiles_file, 'w') as f:
                json.dump(self.scan_profiles, f, indent=2)
            self.logger.debug(f"Scan profile '{name}' saved successfully")
        except Exception as e:
            self.logger.error(f"Failed to save scan profile '{name}': {e}")
    
    def delete_scan_profile(self, name: str):
        if name in self.scan_profiles:
            del self.scan_profiles[name]
            self.save_scan_profiles()
    
    def save_scan_profiles(self):
        try:
            with open(self.scan_profiles_file, 'w') as f:
                json.dump(self.scan_profiles, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save scan profiles: {e}")
    
    def get_window_geometry(self):
        return {
            'width': self.settings.value('window/width', self.default_config['window']['width'], type=int),
            'height': self.settings.value('window/height', self.default_config['window']['height'], type=int),
            'maximized': self.settings.value('window/maximized', self.default_config['window']['maximized'], type=bool)
        }
    
    def save_window_geometry(self, width: int, height: int, maximized: bool):
        self.settings.setValue('window/width', width)
        self.settings.setValue('window/height', height)
        self.settings.setValue('window/maximized', maximized)