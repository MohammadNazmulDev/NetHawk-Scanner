#!/usr/bin/env python3

import sys
import os
import unittest
import tempfile
import shutil
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from database.database_manager import DatabaseManager
from core.config import ConfigManager
from scanner.vulnerability_detector import VulnerabilityDetector
from reports.report_generator import ReportGenerator

class TestNetHawkScanner(unittest.TestCase):
    
    def setUp(self):
        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp()
        
        # Temporarily change data directory for testing
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Initialize components
        self.config_manager = ConfigManager()
        self.db_manager = DatabaseManager()
        self.vuln_detector = VulnerabilityDetector(self.db_manager)
        self.report_generator = ReportGenerator(self.db_manager)
    
    def tearDown(self):
        # Restore original directory and clean up
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)
    
    def test_database_initialization(self):
        """Test database initialization and basic operations"""
        print("Testing database initialization...")
        
        # Test database creation
        self.assertTrue(os.path.exists(self.db_manager.db_path))
        
        # Test scan session creation
        session_id = "test_session_001"
        success = self.db_manager.create_scan_session(
            session_id, 
            "Test Scan", 
            "127.0.0.1", 
            "Test",
            {"test": "options"}
        )
        self.assertTrue(success)
        
        # Test session retrieval
        session_data = self.db_manager.get_scan_session_details(session_id)
        self.assertIsNotNone(session_data)
        self.assertEqual(session_data['session_id'], session_id)
        
        print("✓ Database tests passed")
    
    def test_configuration_management(self):
        """Test configuration management"""
        print("Testing configuration management...")
        
        # Test default configuration
        config = self.config_manager.get_config()
        self.assertIsInstance(config, dict)
        
        # Test scan profiles
        profiles = self.config_manager.get_scan_profiles()
        self.assertIsInstance(profiles, dict)
        self.assertGreater(len(profiles), 0)
        
        # Test specific profile
        quick_scan = self.config_manager.get_scan_profile("Quick Scan")
        self.assertIsInstance(quick_scan, dict)
        self.assertIn('ports', quick_scan)
        
        print("✓ Configuration tests passed")
    
    def test_vulnerability_detection_patterns(self):
        """Test vulnerability detection patterns"""
        print("Testing vulnerability detection...")
        
        # Test pattern loading
        patterns = self.vuln_detector.vulnerability_patterns
        self.assertIsInstance(patterns, dict)
        
        # Test service mappings
        service_mappings = self.vuln_detector.service_vulnerabilities
        self.assertIsInstance(service_mappings, dict)
        self.assertIn(22, service_mappings)  # SSH port
        self.assertIn(80, service_mappings)  # HTTP port
        
        print("✓ Vulnerability detection tests passed")
    
    def test_report_generation_components(self):
        """Test report generation components"""
        print("Testing report generation components...")
        
        # Create test session with data
        session_id = "test_report_session"
        self.db_manager.create_scan_session(
            session_id, 
            "Test Report Scan", 
            "127.0.0.1", 
            "Test"
        )
        
        # Add test host
        host_id = self.db_manager.add_host(
            session_id, 
            "127.0.0.1", 
            "localhost", 
            "up"
        )
        self.assertIsNotNone(host_id)
        
        # Add test port
        port_id = self.db_manager.add_port(
            host_id, 
            80, 
            "tcp", 
            "open",
            service_name="http"
        )
        self.assertIsNotNone(port_id)
        
        # Add test vulnerability
        vuln_id = self.db_manager.add_vulnerability(
            host_id,
            "Test Vulnerability",
            "Medium",
            port_id=port_id,
            cvss_score=5.0
        )
        self.assertIsNotNone(vuln_id)
        
        # Test vulnerability statistics
        vuln_stats = self.report_generator._get_vulnerability_statistics(session_id)
        self.assertIsInstance(vuln_stats, dict)
        self.assertEqual(vuln_stats['total'], 1)
        self.assertEqual(vuln_stats['medium'], 1)
        
        print("✓ Report generation tests passed")
    
    def test_data_export_functionality(self):
        """Test data export functionality"""
        print("Testing data export...")
        
        # Create test session with comprehensive data
        session_id = "test_export_session"
        self.db_manager.create_scan_session(
            session_id, 
            "Export Test Scan", 
            "192.168.1.0/24", 
            "Comprehensive"
        )
        
        # Add multiple test hosts
        for i in range(1, 4):
            host_id = self.db_manager.add_host(
                session_id, 
                f"192.168.1.{i}", 
                f"host-{i}", 
                "up",
                os_name="Linux",
                os_accuracy=95
            )
            
            # Add ports for each host
            for port in [22, 80, 443]:
                port_id = self.db_manager.add_port(
                    host_id, 
                    port, 
                    "tcp", 
                    "open",
                    service_name="ssh" if port == 22 else "http" if port == 80 else "https"
                )
                
                # Add vulnerability for some ports
                if port == 22:
                    self.db_manager.add_vulnerability(
                        host_id,
                        f"SSH Vulnerability on host {i}",
                        "High",
                        port_id=port_id,
                        cvss_score=7.5,
                        cve_id="CVE-2023-TEST"
                    )
        
        # Test getting session data
        hosts = self.db_manager.get_session_hosts(session_id)
        self.assertEqual(len(hosts), 3)
        
        # Test vulnerability counting
        total_vulns = 0
        for host in hosts:
            vulns = self.db_manager.get_host_vulnerabilities(host['id'])
            total_vulns += len(vulns)
        
        self.assertEqual(total_vulns, 3)  # One vulnerability per host
        
        print("✓ Data export tests passed")
    
    def test_security_features(self):
        """Test security and validation features"""
        print("Testing security features...")
        
        # Test input validation - empty targets
        session_id = "test_security"
        result = self.db_manager.create_scan_session(session_id, "Test", "", "Test")
        # Should still create session even with empty targets (validation happens at UI level)
        self.assertTrue(result)
        
        # Test CVE caching
        test_cve_data = {
            'cve_id': 'CVE-2023-TEST',
            'description': 'Test vulnerability',
            'severity': 'High',
            'cvss_score': 7.5
        }
        
        cache_result = self.db_manager.cache_cve_data('CVE-2023-TEST', test_cve_data)
        self.assertTrue(cache_result)
        
        cached_data = self.db_manager.get_cached_cve_data('CVE-2023-TEST')
        self.assertIsNotNone(cached_data)
        self.assertEqual(cached_data['cve_id'], 'CVE-2023-TEST')
        
        print("✓ Security feature tests passed")
    
    def test_database_performance(self):
        """Test database performance with larger datasets"""
        print("Testing database performance...")
        
        session_id = "test_performance"
        self.db_manager.create_scan_session(session_id, "Performance Test", "10.0.0.0/8", "Test")
        
        # Add multiple hosts quickly
        import time
        start_time = time.time()
        
        host_ids = []
        for i in range(50):  # Test with 50 hosts
            host_id = self.db_manager.add_host(
                session_id, 
                f"10.0.0.{i}", 
                f"host-{i}", 
                "up"
            )
            host_ids.append(host_id)
        
        # Add ports for each host
        for host_id in host_ids:
            for port in [22, 80, 443, 3389, 5432]:
                self.db_manager.add_port(host_id, port, "tcp", "open")
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        self.assertLess(elapsed, 10.0, f"Database operations took too long: {elapsed:.2f}s")
        
        # Verify data integrity
        hosts = self.db_manager.get_session_hosts(session_id)
        self.assertEqual(len(hosts), 50)
        
        print(f"✓ Database performance test passed ({elapsed:.2f}s for 50 hosts, 250 ports)")
    
    def test_error_handling(self):
        """Test error handling and edge cases"""
        print("Testing error handling...")
        
        # Test invalid session access
        invalid_session_data = self.db_manager.get_scan_session_details("nonexistent_session")
        self.assertIsNone(invalid_session_data)
        
        # Test invalid host operations
        invalid_host_id = self.db_manager.add_host("nonexistent_session", "1.1.1.1", status="up")
        # Should still work as database doesn't enforce foreign key by default
        self.assertIsNotNone(invalid_host_id)
        
        # Test vulnerability detection with empty data
        vuln_results = self.vuln_detector.detect_vulnerabilities("nonexistent_session")
        self.assertIsInstance(vuln_results, dict)
        self.assertEqual(vuln_results['total_vulnerabilities'], 0)
        
        print("✓ Error handling tests passed")

def run_application_tests():
    """Run comprehensive application tests"""
    print("NetHawk Scanner - Application Testing Suite")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("ERROR: Python 3.7 or higher is required for testing")
        return False
    
    print(f"Python Version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Run unit tests
    test_suite = unittest.TestSuite()
    test_loader = unittest.TestLoader()
    
    # Add all test methods
    test_suite.addTest(test_loader.loadTestsFromTestCase(TestNetHawkScanner))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(test_suite)
    
    print("\n" + "=" * 50)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    
    if success:
        print("\n✓ ALL TESTS PASSED - NetHawk Scanner is ready for use!")
    else:
        print("\n✗ SOME TESTS FAILED - Please check the application")
    
    return success

if __name__ == "__main__":
    success = run_application_tests()
    sys.exit(0 if success else 1)