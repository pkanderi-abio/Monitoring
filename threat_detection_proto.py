import numpy as np
from sklearn.ensemble import IsolationForest
import queue
import threading
import time
import json
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

# Compliance check
def compliance_check(event):
    try:
        if event.get('user') == 'root' and event.get('action') == 'login':
            return 'Compliance Alert: Unauthorized root login detected!'
        return None
    except Exception as e:
        logger.error(f"Error in compliance check: {e}")
        return None

# Combined threat detection
def detect_threat(event, alert_file='alerts.json'):
    try:
        alerts = []
        rule_alert = rule_based_detect(event)
        if rule_alert:
            alerts.append(rule_alert)
        ml_alert = ml_based_detect(event)
        if ml_alert:
            alerts.append(ml_alert)
        compliance_alert = compliance_check(event)
        if compliance_alert:
            alerts.append(compliance_alert)
        
        if alerts:
            alert_data = {
                'event': event,
                'alerts': alerts,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            try:
                with open(alert_file, 'a') as f:
                    json.dump(alert_data, f)
                    f.write('\n')
                logger.info(f"Alerts saved to {alert_file}: {alerts}")
                print(f"Threat Detected for event {event}: {', '.join(alerts)}")
            except Exception as e:
                logger.error(f"Failed to save alerts to {alert_file}: {e}")
        else:
            print(f"Normal event: {event}")
    except Exception as e:
        logger.error(f"Error in detect_threat: {e}")

# Parse log line into event dictionary
def parse_log_line(line):
    try:
        parts = line.strip().split()
        timestamp = int(time.mktime(time.strptime(parts[0] + ' ' + parts[1], '%Y-%m-%d %H:%M:%S')))
        event = {
            'timestamp': timestamp,
            'login_count': 1,  # Simplified: assume 1 login per log line
            'failed_attempts': int(parts[4].split('=')[1]),
            'user': parts[2].split('=')[1],
            'action': parts[3].split('=')[1],
            'ip': parts[5].split('=')[1]
        }
        logger.info(f"Parsed log line: {event}")
        return event
    except Exception as e:
        logger.error(f"Error parsing log line '{line}': {e}")
        return None

# Log file watcher
class LogHandler(FileSystemEventHandler):
    def __init__(self, queue):
        self.queue = queue
        self.last_position = 0

    def on_modified(self, event):
        if not event.is_directory:
            try:
                with open(event.src_path, 'r') as f:
                    f.seek(self.last_position)
                    lines = f.readlines()
                    self.last_position = f.tell()
                    for line in lines:
                        event_data = parse_log_line(line)
                        if event_data:
                            self.queue.put(event_data)
            except Exception as e:
                logger.error(f"Error reading log file {event.src_path}: {e}")

# Consumer thread for real-time processing
def event_consumer(q):
    while True:
        event = q.get()
        if event is None:
            break
        detect_threat(event)

# Run the prototype
if __name__ == "__main__":
    log_file = 'sample.log'
    alert_file = 'alerts.json'
    
    # Validate log file
    if not os.path.exists(log_file):
        logger.error(f"Log file {log_file} does not exist. Please create it.")
        print(f"Error: Create {log_file} with sample log entries.")
        exit(1)
    
    # Clear previous alerts file
    if os.path.exists(alert_file):
        try:
            os.remove(alert_file)
            logger.info(f"Cleared previous {alert_file}")
        except Exception as e:
            logger.error(f"Failed to clear {alert_file}: {e}")
    
    event_queue = queue.Queue()
    
    # Start log file watcher
    try:
        observer = Observer()
        observer.schedule(LogHandler(event_queue), log_file, recursive=False)
        observer.start()
        logger.info(f"Started watching log file: {log_file}")
    except Exception as e:
        logger.error(f"Failed to start log watcher: {e}")
        exit(1)
    
    # Start consumer thread
    consumer_thread = threading.Thread(target=event_consumer, args=(event_queue,))
    consumer_thread.start()
    
    try:
        print(f"Watching log file: {log_file}")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down prototype...")
        observer.stop()
        event_queue.put(None)
    
    observer.join()
    consumer_thread.join()
    logger.info("Prototype detection complete.")
    print("Prototype detection complete.")