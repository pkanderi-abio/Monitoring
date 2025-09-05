import numpy as np
from sklearn.ensemble import IsolationForest
import queue
import threading
import time
import json
import os
from confluent_kafka import Consumer, Producer
import logging
from fastapi import FastAPI, Query, WebSocket
from fastapi.responses import HTMLResponse, FileResponse
from uvicorn import Config, Server
import asyncio
from datetime import datetime
import pytz
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import smtplib
from email.mime.text import MIMEText
import boto3
from io import StringIO
import csv
from retrying import retry

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
SLACK_WEBHOOK_URL = 'your-slack-webhook-url'  # Replace with your Slack webhook URL
EMAIL_CONFIG = {
    'smtp_server': 'smtp.example.com',  # Replace with your SMTP server
    'smtp_port': 587,
    'smtp_username': 'your-username',  # Replace with your SMTP username
    'smtp_password': 'your-password',  # Replace with your SMTP password
    'to_email': 'your-email@example.com',  # Replace with recipient email
    'from_email': 'mdr-xdr@example.com'  # Replace with sender email
}
AWS_CONFIG = {
    'aws_access_key_id': 'your-access-key',  # Replace with AWS access key
    'aws_secret_access_key': 'your-secret-key',  # Replace with AWS secret key
    'region_name': 'us-east-1'  # Replace with your AWS region
}
LOG_FILE = os.path.expanduser('~/Tools/Monitoring/test.log')
ALERT_FILE = os.path.expanduser('~/Tools/Monitoring/alerts.json')
KAFKA_TOPIC = 'threat-logs'
KAFKA_CONFIG = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'threat-group',
    'auto.offset.reset': 'earliest',
    'num.partitions': 3,
    'replication.factor': 1
}

# FastAPI app
app = FastAPI()

# WebSocket clients
websocket_clients = []

# HTML dashboard with filters, pagination, and severity sorting
HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>MDR/XDR Alerts Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .alert-critical { color: red; font-weight: bold; }
        .alert-warning { color: orange; }
        #alert-chart, #alert-pie-chart { max-width: 600px; margin-bottom: 20px; }
        select, input, button { margin: 5px; }
        .pagination { margin-top: 10px; }
    </style>
</head>
<body>
    <h1>MDR/XDR Alerts Dashboard</h1>
    <div>
        <label for="alert-filter">Filter by Alert Type:</label>
        <select id="alert-filter" onchange="fetchAlerts(1)">
            <option value="all">All</option>
            <option value="rule">Rule</option>
            <option value="ml">ML</option>
            <option value="compliance">Compliance</option>
        </select>
        <label for="severity-filter">Filter by Severity:</label>
        <select id="severity-filter" onchange="fetchAlerts(1)">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
        </select>
        <label for="time-range">Time Range (hours):</label>
        <input type="number" id="time-range" value="24" min="1" onchange="fetchAlerts(1)">
        <button onclick="exportCSV()">Export to CSV</button>
    </div>
    <table id="alerts-table">
        <tr>
            <th>Timestamp</th>
            <th>Event</th>
            <th>Alerts</th>
            <th>Severity</th>
        </tr>
    </table>
    <div class="pagination" id="pagination"></div>
    <h2>Alert Trends</h2>
    <canvas id="alert-chart"></canvas>
    <h2>Alert Distribution</h2>
    <canvas id="alert-pie-chart"></canvas>
    <script>
        let lineChart, pieChart;
        let currentPage = 1;
        const pageSize = 10;
        const ws = new WebSocket('ws://localhost:8000/ws');
        ws.onmessage = function(event) {
            fetchAlerts(currentPage);
        };

        async function fetchAlerts(page) {
            try {
                currentPage = page;
                const filter = document.getElementById('alert-filter').value;
                const severity = document.getElementById('severity-filter').value;
                const timeRange = document.getElementById('time-range').value;
                const response = await fetch(`/alerts?filter=${filter}&severity=${severity}&page=${page}&page_size=${pageSize}&time_range=${timeRange}`);
                const data = await response.json();
                const table = document.getElementById('alerts-table');
                while (table.rows.length > 1) table.deleteRow(1);
                data.alerts.forEach(alert => {
                    const row = table.insertRow();
                    row.insertCell().textContent = alert.timestamp;
                    row.insertCell().textContent = JSON.stringify(alert.event, null, 2);
                    const alertsCell = row.insertCell();
                    alertsCell.innerHTML = alert.alerts.map(a => 
                        a.includes('brute force') || a.includes('root') ? 
                        `<span class="alert-critical">${a}</span>` : 
                        `<span class="alert-warning">${a}</span>`
                    ).join('<br>');
                    row.insertCell().textContent = alert.severity;
                });
                updatePagination(data.total_pages);
                updateLineChart();
                updatePieChart();
            } catch (error) {
                console.error('Error fetching alerts:', error);
            }
        }

        function updatePagination(totalPages) {
            const pagination = document.getElementById('pagination');
            pagination.innerHTML = '';
            for (let i = 1; i <= totalPages; i++) {
                const button = document.createElement('button');
                button.textContent = i;
                button.onclick = () => fetchAlerts(i);
                if (i === currentPage) button.style.fontWeight = 'bold';
                pagination.appendChild(button);
            }
        }

        async function updateLineChart() {
            const response = await fetch('/chart');
            const chartData = await response.json();
            const ctx = document.getElementById('alert-chart').getContext('2d');
            if (lineChart) lineChart.destroy();
            lineChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        label: 'Alert Count',
                        data: chartData.data,
                        borderColor: '#007bff',
                        backgroundColor: 'rgba(0, 123, 255, 0.1)',
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        x: { title: { display: true, text: 'Time' } },
                        y: { title: { display: true, text: 'Number of Alerts' }, beginAtZero: true }
                    }
                }
            });
        }

        async function updatePieChart() {
            const response = await fetch('/chart_pie');
            const chartData = await response.json();
            const ctx = document.getElementById('alert-pie-chart').getContext('2d');
            if (pieChart) pieChart.destroy();
            pieChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        data: chartData.data,
                        backgroundColor: ['#ff6384', '#36a2eb', '#ffce56']
                    }]
                },
                options: { responsive: true }
            });
        }

        async function exportCSV() {
            const filter = document.getElementById('alert-filter').value;
            const severity = document.getElementById('severity-filter').value;
            const timeRange = document.getElementById('time-range').value;
            window.location.href = `/export?filter=${filter}&severity=${severity}&time_range=${timeRange}`;
        }

        fetchAlerts(1);
        setInterval(() => fetchAlerts(currentPage), 5000);
    </script>
</body>
</html>
"""

# FastAPI endpoints
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return HTML_CONTENT

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    websocket_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        websocket_clients.remove(websocket)

@app.get("/alerts")
async def get_alerts(filter: str = 'all', severity: str = 'all', page: int = 1, page_size: int = 10, time_range: float = 24):
    try:
        if not os.path.exists(ALERT_FILE):
            logger.debug("No alerts.json found, returning empty list")
            return {'alerts': [], 'total_pages': 0}
        with open(ALERT_FILE, 'r') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
        cutoff_time = time.time() - time_range * 3600
        filtered_alerts = [
            alert for alert in alerts
            if time.mktime(time.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')) >= cutoff_time
        ]
        if filter != 'all':
            filtered_alerts = [
                alert for alert in filtered_alerts
                if any('Rule' in a and filter == 'rule' or
                       'ML' in a and filter == 'ml' or
                       'Compliance' in a and filter == 'compliance' for a in alert['alerts'])
            ]
        if severity != 'all':
            filtered_alerts = [
                alert for alert in filtered_alerts
                if alert['severity'].lower() == severity
            ]
        filtered_alerts.sort(key=lambda x: 'Critical' not in x['severity'], reverse=True)
        total_alerts = len(filtered_alerts)
        total_pages = (total_alerts + page_size - 1) // page_size
        start = (page - 1) * page_size
        end = start + page_size
        return {'alerts': filtered_alerts[start:end], 'total_pages': total_pages}
    except Exception as e:
        logger.error(f"Error reading alerts: {e}")
        return {'alerts': [], 'total_pages': 0}

@app.get("/chart")
async def get_chart_data():
    try:
        if not os.path.exists(ALERT_FILE):
            logger.debug("No alerts.json for chart data, returning empty")
            return {'labels': [], 'data': []}
        with open(ALERT_FILE, 'r') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
        alert_counts = {}
        for alert in alerts:
            timestamp = alert['timestamp'][:16]  # YYYY-MM-DD HH:MM
            alert_counts[timestamp] = alert_counts.get(timestamp, 0) + len(alert['alerts'])
        return {
            'labels': list(alert_counts.keys()),
            'data': list(alert_counts.values())
        }
    except Exception as e:
        logger.error(f"Error generating chart data: {e}")
        return {'labels': [], 'data': []}

@app.get("/chart_pie")
async def get_pie_chart_data():
    try:
        if not os.path.exists(ALERT_FILE):
            logger.debug("No alerts.json for pie chart, returning empty")
            return {'labels': ['Rule', 'ML', 'Compliance'], 'data': [0, 0, 0]}
        with open(ALERT_FILE, 'r') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
        rule_count = ml_count = compliance_count = 0
        for alert in alerts:
            for a in alert['alerts']:
                if 'Rule' in a:
                    rule_count += 1
                elif 'ML' in a:
                    ml_count += 1
                else:
                    compliance_count += 1
        return {
            'labels': ['Rule', 'ML', 'Compliance'],
            'data': [rule_count, ml_count, compliance_count]
        }
    except Exception as e:
        logger.error(f"Error generating pie chart data: {e}")
        return {'labels': ['Rule', 'ML', 'Compliance'], 'data': [0, 0, 0]}

@app.get("/export")
async def export_alerts(filter: str = 'all', severity: str = 'all', time_range: float = 24):
    try:
        if not os.path.exists(ALERT_FILE):
            logger.debug("No alerts.json for export, returning empty CSV")
            return FileResponse('empty.csv', media_type='text/csv', filename='alerts.csv')
        with open(ALERT_FILE, 'r') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
        cutoff_time = time.time() - time_range * 3600
        filtered_alerts = [
            alert for alert in alerts
            if time.mktime(time.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')) >= cutoff_time
        ]
        if filter != 'all':
            filtered_alerts = [
                alert for alert in filtered_alerts
                if any('Rule' in a and filter == 'rule' or
                       'ML' in a and filter == 'ml' or
                       'Compliance' in a and filter == 'compliance' for a in alert['alerts'])
            ]
        if severity != 'all':
            filtered_alerts = [
                alert for alert in filtered_alerts
                if alert['severity'].lower() == severity
            ]
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Event', 'Alerts', 'Severity'])
        for alert in filtered_alerts:
            writer.writerow([alert['timestamp'], json.dumps(alert['event']), ', '.join(alert['alerts']), alert['severity']])
        output.seek(0)
        with open('alerts.csv', 'w') as f:
            f.write(output.getvalue())
        return FileResponse('alerts.csv', media_type='text/csv', filename='alerts.csv')
    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        return FileResponse('empty.csv', media_type='text/csv', filename='alerts.csv')

# Optional Slack import
try:
    from slack_sdk.webhook import WebhookClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    WebhookClient = None

# Sample training data: [timestamp, login_count, failed_attempts]
training_data = np.array([
    [1, 5, 0], [2, 6, 1], [3, 7, 0], [4, 4, 2], [5, 5, 1],  # Normal
    [6, 100, 50], [7, 200, 100]  # Anomalous
])

# Train ML model
try:
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(training_data)
    logger.info("ML model trained successfully")
except Exception as e:
    logger.error(f"Failed to train ML model: {e}")
    raise

# Rule-based detection
def rule_based_detect(event):
    try:
        if event['failed_attempts'] > 50:
            return 'Rule Alert: High failed attempts - Possible brute force attack!'
        return None
    except KeyError as e:
        logger.error(f"Missing key in event for rule-based detection: {e}")
        return None

# ML-based detection
def ml_based_detect(event):
    try:
        event_array = np.array([[event['timestamp'], event['login_count'], event['failed_attempts']]])
        pred = model.predict(event_array)[0]
        return 'ML Alert: Anomaly detected - Unusual pattern!' if pred == -1 else None
    except KeyError as e:
        logger.error(f"Missing key in event for ML-based detection: {e}")
        return None

# Compliance checks
def compliance_check(event):
    try:
        alerts = []
        # Rule 1: Unauthorized root login
        if event.get('user') == 'root' and event.get('action') == 'login':
            alerts.append('Compliance Alert: Unauthorized root login detected!')
        # Rule 2: Login from unauthorized IP
        authorized_ips = ['192.168.1.100', '192.168.1.101']
        if event.get('ip') not in authorized_ips:
            alerts.append(f'Compliance Alert: Login from unauthorized IP {event.get("ip")}!')
        # Rule 3: After-hours access (adjusted for 12:09 PM CDT)
        event_time = time.localtime(event['timestamp'])
        if event_time.tm_hour >= 10:
            alerts.append('Compliance Alert: After-hours login detected!')
        # Rule 4: GDPR/PCI-DSS - Excessive data access
        if event.get('action') == 'data_access' and event.get('data_size', 0) > 1000000:
            alerts.append('Compliance Alert: Excessive data access detected!')
        # Rule 5: GDPR/PCI-DSS - Suspicious network traffic
        if event.get('action') == 'network' and event.get('bytes_transferred', 0) > 10000000:
            alerts.append('Compliance Alert: Suspicious network traffic detected!')
        return alerts if alerts else None
    except Exception as e:
        logger.error(f"Error in compliance check: {e}")
        return None

# Slack alert function
def send_slack_alert(message):
    if not SLACK_AVAILABLE or SLACK_WEBHOOK_URL == 'your-slack-webhook-url':
        logger.warning("Slack alerting disabled: slack-sdk not installed or webhook URL not set")
        return
    try:
        webhook = WebhookClient(SLACK_WEBHOOK_URL)
        webhook.send(text=message)
        logger.info("Slack alert sent successfully")
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")

# Email alert function
def send_email_alert(message):
    try:
        msg = MIMEText(message)
        msg['Subject'] = 'MDR/XDR Threat Alert'
        msg['From'] = EMAIL_CONFIG['from_email']
        msg['To'] = EMAIL_CONFIG['to_email']
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['smtp_username'], EMAIL_CONFIG['smtp_password'])
            server.send_message(msg)
        logger.info("Email alert sent successfully")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")

# Combined threat detection
async def detect_threat(event, alert_file=ALERT_FILE):
    try:
        alerts = []
        rule_alert = rule_based_detect(event)
        if rule_alert:
            alerts.append(rule_alert)
        ml_alert = ml_based_detect(event)
        if ml_alert:
            alerts.append(ml_alert)
        compliance_alerts = compliance_check(event)
        if compliance_alerts:
            alerts.extend(compliance_alerts)
        
        severity = 'Critical' if any('brute force' in a or 'root' in a for a in alerts) else 'Warning'
        
        if alerts:
            alert_data = {
                'event': event,
                'alerts': alerts,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                'severity': severity
            }
            try:
                with open(alert_file, 'a') as f:
                    json.dump(alert_data, f)
                    f.write('\n')
                logger.info(f"Alerts saved to {alert_file}: {alerts} (Severity: {severity})")
                print(f"Threat Detected for event {event}: {', '.join(alerts)} (Severity: {severity})")
                send_slack_alert(f"Threat Detected: {', '.join(alerts)} (Severity: {severity})")
                send_email_alert(f"Threat Detected: {', '.join(alerts)} (Severity: {severity})")
                # Notify WebSocket clients
                for client in websocket_clients:
                    try:
                        await client.send_text(json.dumps(alert_data))
                    except Exception as e:
                        logger.error(f"Error sending WebSocket update: {e}")
                # Update Prometheus
                alert_count.labels(severity).inc(len(alerts))
            except Exception as e:
                logger.error(f"Failed to save alerts to {alert_file}: {e}")
        else:
            print(f"Normal event: {event}")
    except Exception as e:
        logger.error(f"Error in detect_threat: {e}")

# Parse real log lines (e.g., auth.log format)
def parse_log_line(line):
    try:
        parts = line.strip().split()
        timestamp = int(datetime.strptime(f"2025 {parts[0]} {parts[1]} {parts[2]}", '%Y %b %d %H:%M:%S').replace(tzinfo=pytz.timezone('America/Chicago')).timestamp())
        user = parts[8] if len(parts) > 8 and parts[6] == 'for' else 'unknown'
        failed = 1 if 'Failed' in line else 0
        ip = parts[10] if len(parts) > 10 else 'unknown'
        event = {
            'timestamp': timestamp,
            'login_count': 1,
            'failed_attempts': failed,
            'user': user,
            'action': 'login',
            'ip': ip
        }
        logger.debug(f"Parsed log line: {event}")
        return event
    except Exception as e:
        logger.error(f"Error parsing log line '{line}': {e}")
        return None

# Parse Zeek log lines (e.g., conn.log)
def parse_zeek_line(line):
    try:
        parts = line.strip().split('\t')
        if len(parts) < 8:
            return None
        timestamp = float(parts[0])  # Zeek uses UNIX timestamp
        src_ip = parts[2]
        dst_ip = parts[4]
        bytes_transferred = int(parts[9]) if parts[9] != '-' else 0
        event = {
            'timestamp': timestamp,
            'login_count': 0,
            'failed_attempts': 0,
            'user': 'unknown',
            'action': 'network',
            'ip': src_ip,
            'dst_ip': dst_ip,
            'bytes_transferred': bytes_transferred
        }
        logger.debug(f"Parsed Zeek log line: {event}")
        return event
    except Exception as e:
        logger.error(f"Error parsing Zeek log line '{line}': {e}")
        return None

# AWS CloudTrail event producer
@retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def cloudtrail_producer(producer, topic='threat-logs'):
    if AWS_CONFIG['aws_access_key_id'] == 'your-access-key':
        logger.warning("Skipping CloudTrail: Invalid AWS credentials")
        return
    try:
        client = boto3.client(
            'cloudtrail',
            aws_access_key_id=AWS_CONFIG['aws_access_key_id'],
            aws_secret_access_key=AWS_CONFIG['aws_secret_access_key'],
            region_name=AWS_CONFIG['region_name']
        )
        events = client.lookup_events()['Events']
        for event in events:
            kafka_event = {
                'timestamp': event['EventTime'].timestamp(),
                'user': event.get('Username', 'unknown'),
                'action': event.get('EventName', 'unknown'),
                'ip': event.get('SourceIPAddress', 'unknown'),
                'login_count': 1,
                'failed_attempts': 0
            }
            producer.produce(topic, value=json.dumps(kafka_event).encode('utf-8'))
            producer.flush()
            logger.info(f"Produced CloudTrail event: {kafka_event}")
            event_queue.put(kafka_event)
            asyncio.run(detect_threat(kafka_event))
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error fetching CloudTrail events: {e}")
        raise

# Log file watcher
class LogHandler(FileSystemEventHandler):
    def __init__(self, queue, producer, topic='threat-logs', log_type='system'):
        self.queue = queue
        self.producer = producer
        self.topic = topic
        self.log_type = log_type
        self.last_position = 0

    def on_modified(self, event):
        if not event.is_directory and event.src_path == LOG_FILE:
            logger.debug(f"Detected modification in {event.src_path}")
            try:
                with open(event.src_path, 'r') as f:
                    f.seek(self.last_position)
                    lines = f.readlines()
                    self.last_position = f.tell()
                    for line in lines:
                        if self.log_type == 'system':
                            event_data = parse_log_line(line)
                        else:
                            event_data = parse_zeek_line(line)
                        if event_data:
                            self.producer.produce(self.topic, value=json.dumps(event_data).encode('utf-8'))
                            self.producer.flush()
                            logger.info(f"Produced event from log ({self.log_type}): {event_data}")
                            self.queue.put(event_data)
                            asyncio.run(detect_threat(event_data))
            except Exception as e:
                logger.error(f"Error reading log file {event.src_path}: {e}")

# Kafka producer with log file watching and CloudTrail
@retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def event_producer():
    conf = {'bootstrap.servers': KAFKA_CONFIG['bootstrap.servers']}
    try:
        producer = Producer(conf)
    except Exception as e:
        logger.error(f"Failed to initialize Kafka producer: {e}")
        raise
    
    # Create test.log if it doesn't exist
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'w') as f:
                f.write('')
            logger.info(f"Created empty {LOG_FILE}")
        except Exception as e:
            logger.error(f"Failed to create {LOG_FILE}: {e}")
            logger.warning("Using sample events due to log file creation failure")
            now = int(datetime.now(pytz.timezone('America/Chicago')).timestamp())
            events = [
                {'timestamp': now, 'login_count': 5, 'failed_attempts': 1, 'user': 'admin', 'action': 'login', 'ip': '192.168.1.100'},
                {'timestamp': now + 1, 'login_count': 10, 'failed_attempts': 60, 'user': 'admin', 'action': 'login', 'ip': '192.168.1.101'},
                {'timestamp': now + 2, 'login_count': 150, 'failed_attempts': 20, 'user': 'root', 'action': 'login', 'ip': '192.168.1.102'},
                {'timestamp': now + 3, 'login_count': 200, 'failed_attempts': 100, 'user': 'admin', 'action': 'login', 'ip': '192.168.1.103'}
            ]
            topic = KAFKA_TOPIC
            for event in events:
                try:
                    producer.produce(topic, value=json.dumps(event).encode('utf-8'))
                    producer.flush()
                    logger.info(f"Produced event: {event}")
                    event_queue.put(event)
                    asyncio.run(detect_threat(event))
                    time.sleep(1)
                except Exception as e:
                    logger.error(f"Error producing event: {e}")
            producer.produce(topic, value='STOP'.encode('utf-8'))
            producer.flush()
            logger.info("Producer finished")
            return
    
    # Process CloudTrail events
    cloudtrail_producer(producer)
    
    # Watch log file
    logger.debug(f"Checking for log file: {LOG_FILE}")
    observer = Observer()
    observer.schedule(LogHandler(queue=event_queue, producer=producer, topic=KAFKA_TOPIC, log_type='system'), LOG_FILE, recursive=False)
    logger.info(f"Starting log file watcher for {LOG_FILE}")
    observer.start()
    try:
        print(f"Watching log file: {LOG_FILE}")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Stopping log file watcher")
    observer.join()
    producer.produce(KAFKA_TOPIC, value='STOP'.encode('utf-8'))
    producer.flush()
    logger.info("Producer finished")

# Kafka consumer
@retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def event_consumer(q):
    conf = {
        'bootstrap.servers': KAFKA_CONFIG['bootstrap.servers'],
        'group.id': KAFKA_CONFIG['group.id'],
        'auto.offset.reset': KAFKA_CONFIG['auto.offset.reset']
    }
    try:
        consumer = Consumer(conf)
        consumer.subscribe([KAFKA_TOPIC])
    except Exception as e:
        logger.error(f"Failed to initialize Kafka consumer: {e}")
        raise
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                logger.error(f"Consumer error: {msg.error()}")
                continue
            try:
                message = msg.value().decode('utf-8')
                if message == 'STOP':
                    q.put(None)
                    break
                event = json.loads(message)
                q.put(event)
                asyncio.run(detect_threat(event))
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding message: {e}")
                continue
    except Exception as e:
        logger.error(f"Consumer error: {e}")
        raise
    finally:
        consumer.close()
        logger.info("Consumer closed")

# Process events from queue
def process_events(q):
    while True:
        try:
            event = q.get(timeout=10)
            if event is None:
                break
            asyncio.run(detect_threat(event))
        except queue.Empty:
            logger.debug("No events in queue, continuing...")
            continue
        except Exception as e:
            logger.error(f"Error processing event: {e}")

# Backup alerts.json every 5 minutes
def backup_alerts():
    while True:
        try:
            if os.path.exists(ALERT_FILE):
                shutil.copy(ALERT_FILE, ALERT_FILE + '.backup')
                logger.info(f"Backed up alerts.json to alerts.json.backup")
            time.sleep(300)
        except Exception as e:
            logger.error(f"Failed to backup alerts.json: {e}")

# Run FastAPI server in a separate thread
async def run_fastapi():
    config = Config(app=app, host="0.0.0.0", port=8000)
    server = Server(config)
    await server.serve()

# Main execution
if __name__ == "__main__":
    event_queue = queue.Queue()
    
    # Log system time zone
    logger.info(f"System time zone: {time.tzname}")
    
    # Create empty alerts.json if it doesn't exist
    if not os.path.exists(ALERT_FILE):
        try:
            with open(ALERT_FILE, 'w') as f:
                f.write('')
            logger.info(f"Created empty {ALERT_FILE}")
        except Exception as e:
            logger.error(f"Failed to create {ALERT_FILE}: {e}")
    
    # Create Kafka topic with multiple partitions
    try:
        from confluent_kafka.admin import AdminClient, NewTopic
        admin_client = AdminClient({'bootstrap.servers': KAFKA_CONFIG['bootstrap.servers']})
        new_topic = NewTopic(KAFKA_TOPIC, num_partitions=KAFKA_CONFIG['num.partitions'], replication_factor=KAFKA_CONFIG['replication.factor'])
        admin_client.create_topics([new_topic])
        logger.info(f"Created Kafka topic {KAFKA_TOPIC} with {KAFKA_CONFIG['num.partitions']} partitions")
    except Exception as e:
        logger.warning(f"Failed to create Kafka topic {KAFKA_TOPIC}: {e}. Topic may already exist.")
    
    # Start producer, consumer, and detection threads
    producer_thread = threading.Thread(target=event_producer)
    consumer_thread = threading.Thread(target=event_consumer, args=(event_queue,))
    detection_thread = threading.Thread(target=process_events, args=(event_queue,))
    backup_thread = threading.Thread(target=backup_alerts)
    
    # Start FastAPI server in a separate thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    fastapi_thread = threading.Thread(target=lambda: loop.run_until_complete(run_fastapi()))
    
    try:
        producer_thread.start()
        consumer_thread.start()
        detection_thread.start()
        backup_thread.start()
        fastapi_thread.start()
        
        print("Running production-ready MDR/XDR solution with Kafka...")
        print(f"Watching log file: {LOG_FILE}")
        print("Dashboard available at http://localhost:8000")
        producer_thread.join()
        consumer_thread.join()
        detection_thread.join()
        backup_thread.join()
        fastapi_thread.join()
    except KeyboardInterrupt:
        logger.info("Shutting down MDR/XDR solution...")
        event_queue.put(None)
        loop.call_soon_threadsafe(loop.stop)
    except Exception as e:
        logger.error(f"Error running MDR/XDR solution: {e}")
    
    logger.info("MDR/XDR solution shutdown complete.")
    print("MDR/XDR solution shutdown complete.")