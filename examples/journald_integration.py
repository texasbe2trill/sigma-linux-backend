#!/usr/bin/env python3
"""
Journald Integration Example for Sigma Simple Backend

This example demonstrates how to integrate the Sigma Simple Backend with
systemd journald for real-time security monitoring of system logs.
"""

import sys
import os
import json
import subprocess
import signal
import time
from datetime import datetime

# Add parent directory to path to import the backend
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_simple_backend import (
    SimpleEvalBackend,
    RestrictivenessLevel,
    MockRuleCollection,
    Alert
)


class JournaldMonitor:
    """Real-time journald log monitor with Sigma rule evaluation"""
    
    def __init__(self, restrictiveness=RestrictivenessLevel.RESTRICTIVE):
        self.backend = SimpleEvalBackend(restrictiveness=restrictiveness)
        self.rule_collection = MockRuleCollection()
        self.compiled_rules = []
        self.process = None
        self.running = False
        self.alert_count = 0
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        print(f"Initialized Journald Monitor with {restrictiveness.value} restrictiveness")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.stop()
    
    def start(self, units=None, follow=True, since="now"):
        """
        Start monitoring journald logs
        
        Args:
            units: List of systemd units to monitor (None for all)
            follow: Whether to follow new log entries
            since: When to start reading from ("now", "boot", "yesterday", etc.)
        """
        
        print("Compiling Sigma rules...")
        self.compiled_rules = self.backend.compile(self.rule_collection)
        print(f"Compiled {len(self.compiled_rules)} rules")
        
        # Build journalctl command
        cmd = ["journalctl", "-o", "json"]
        
        if follow:
            cmd.append("-f")
        
        if since:
            cmd.extend(["--since", since])
        
        if units:
            for unit in units:
                cmd.extend(["-u", unit])
        
        print(f"Starting journald monitoring with command: {' '.join(cmd)}")
        print("Press Ctrl+C to stop monitoring\n")
        
        try:
            # Start the journalctl process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.running = True
            self._monitor_loop()
            
        except FileNotFoundError:
            print("Error: journalctl command not found. Make sure systemd is installed.")
        except Exception as e:
            print(f"Error starting journald monitor: {e}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        
        start_time = datetime.now()
        log_count = 0
        
        print(f"Monitoring started at {start_time}")
        print("=" * 60)
        
        try:
            while self.running and self.process:
                line = self.process.stdout.readline()
                
                if not line:
                    if self.process.poll() is not None:
                        break
                    continue
                
                log_count += 1
                
                try:
                    # Parse JSON log entry
                    log_entry = json.loads(line.strip())
                    
                    # Convert journald fields to our expected format
                    event = self._convert_journald_event(log_entry)
                    
                    # Test against Sigma rules
                    self._evaluate_event(event, log_entry)
                    
                    # Print periodic status
                    if log_count % 1000 == 0:
                        elapsed = datetime.now() - start_time
                        print(f"Processed {log_count} log entries, {self.alert_count} alerts generated (runtime: {elapsed})")
                
                except json.JSONDecodeError:
                    # Skip malformed JSON
                    continue
                except Exception as e:
                    print(f"Error processing log entry: {e}")
                    continue
        
        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user")
        
        finally:
            elapsed = datetime.now() - start_time
            print(f"\nMonitoring stopped. Processed {log_count} entries, {self.alert_count} alerts in {elapsed}")
    
    def _convert_journald_event(self, log_entry):
        """Convert journald log entry to our event format"""
        
        event = {}
        
        # Map common journald fields
        field_mappings = {
            'MESSAGE': 'MESSAGE',
            '_COMM': '_COMM',
            '_CMDLINE': '_CMDLINE',
            '_PID': '_PID',
            '_UID': '_UID',
            '_GID': '_GID',
            '_HOSTNAME': '_HOSTNAME',
            '_EXE': '_EXE',
            '_SYSTEMD_UNIT': '_SYSTEMD_UNIT',
            'SYSLOG_IDENTIFIER': 'SYSLOG_IDENTIFIER',
            'PRIORITY': 'PRIORITY',
        }
        
        # Apply field mappings
        for journald_field, event_field in field_mappings.items():
            if journald_field in log_entry:
                event[event_field] = log_entry[journald_field]
        
        # Add timestamp
        if '__REALTIME_TIMESTAMP' in log_entry:
            # Convert microseconds to datetime
            timestamp_us = int(log_entry['__REALTIME_TIMESTAMP'])
            event['@timestamp'] = datetime.fromtimestamp(timestamp_us / 1000000).isoformat()
        
        return event
    
    def _evaluate_event(self, event, original_log_entry):
        """Evaluate event against compiled Sigma rules"""
        
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                self.alert_count += 1
                self._handle_alert(alert, event, original_log_entry)
    
    def _handle_alert(self, alert: Alert, event: dict, original_log_entry: dict):
        """Handle security alerts"""
        
        print(f"\n🚨 SECURITY ALERT #{self.alert_count} 🚨")
        print(f"Time: {datetime.now().isoformat()}")
        print(f"Rule: {alert.rule_title}")
        print(f"Severity: {alert.severity}")
        print(f"Description: {alert.description}")
        
        if alert.mitre_tactics:
            print(f"MITRE Tactics: {', '.join(alert.mitre_tactics)}")
        
        if alert.mitre_techniques:
            print(f"MITRE Techniques: {', '.join(alert.mitre_techniques)}")
        
        print("Event Details:")
        print(f"  Command: {event.get('_COMM', 'N/A')}")
        print(f"  PID: {event.get('_PID', 'N/A')}")
        print(f"  Message: {event.get('MESSAGE', 'N/A')[:100]}...")
        print(f"  Host: {event.get('_HOSTNAME', 'N/A')}")
        print(f"  Unit: {event.get('_SYSTEMD_UNIT', 'N/A')}")
        
        print("-" * 60)
        
        # Here you could add additional alert handling:
        # - Send to SIEM
        # - Write to alert log file
        # - Send notifications
        # - Trigger automated responses
    
    def stop(self):
        """Stop the monitoring process"""
        self.running = False
        if self.process:
            self.process.terminate()


def monitor_specific_services():
    """Example of monitoring specific systemd services"""
    
    print("=== Monitoring Specific Services Example ===\n")
    
    # Monitor SSH, web services, and cron
    services_to_monitor = [
        "ssh.service",
        "apache2.service",
        "nginx.service",
        "cron.service",
        "systemd-logind.service"
    ]
    
    monitor = JournaldMonitor(restrictiveness=RestrictivenessLevel.BALANCED)
    
    print(f"Monitoring services: {', '.join(services_to_monitor)}")
    print("This will monitor only logs from these specific systemd units")
    
    try:
        monitor.start(units=services_to_monitor)
    except KeyboardInterrupt:
        print("\nStopping service monitoring...")


def monitor_all_logs():
    """Example of monitoring all system logs"""
    
    print("=== Monitoring All System Logs Example ===\n")
    
    monitor = JournaldMonitor(restrictiveness=RestrictivenessLevel.RESTRICTIVE)
    
    print("Monitoring ALL system logs with restrictive rule matching")
    print("This may generate many log entries - use with caution on busy systems")
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nStopping full system monitoring...")


def simulate_threats():
    """Simulate some threat activities for testing"""
    
    print("=== Simulating Threat Activities ===\n")
    print("This will simulate some suspicious commands to test detection")
    print("Note: These are harmless simulation commands")
    
    # These commands will be picked up by journald and should trigger alerts
    simulation_commands = [
        "echo 'Simulating reverse shell: bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'",
        "echo 'Simulating credential theft: cat /etc/shadow'",
        "echo 'Simulating privilege escalation: sudo -u root /bin/bash'",
    ]
    
    for cmd in simulation_commands:
        print(f"Running: {cmd}")
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            time.sleep(1)  # Give journald time to process
        except Exception as e:
            print(f"Error running simulation command: {e}")
    
    print("\nSimulation completed. Check journald monitor output for alerts.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Journald Integration Example")
    parser.add_argument("--mode", choices=["all", "services", "simulate"], 
                       default="all", help="Monitoring mode")
    parser.add_argument("--restrictiveness", 
                       choices=["permissive", "balanced", "restrictive", "ultra"],
                       default="restrictive", help="Rule restrictiveness level")
    
    args = parser.parse_args()
    
    # Map restrictiveness argument to enum
    restrictiveness_map = {
        "permissive": RestrictivenessLevel.PERMISSIVE,
        "balanced": RestrictivenessLevel.BALANCED,
        "restrictive": RestrictivenessLevel.RESTRICTIVE,
        "ultra": RestrictivenessLevel.ULTRA_RESTRICTIVE,
    }
    
    try:
        if args.mode == "simulate":
            simulate_threats()
        elif args.mode == "services":
            monitor_specific_services()
        else:
            monitor_all_logs()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc() 