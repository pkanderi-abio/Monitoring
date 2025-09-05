import pytest
# Make sure the module is in your PYTHONPATH or installed in your environment
from threat_detection_prod_kafka import rule_based_detect, ml_based_detect, compliance_check

def test_rule_based_detect():
    event = {'failed_attempts': 60}
    assert 'Rule Alert' in rule_based_detect(event)

def test_ml_based_detect():
    event = {'timestamp': time.time(), 'login_count': 200, 'failed_attempts': 100}
    assert 'ML Alert' in ml_based_detect(event)

def test_compliance_check():
    event = {'user': 'root', 'action': 'login', 'ip': '192.168.1.102'}
    assert 'Unauthorized root login' in ', '.join(compliance_check(event))