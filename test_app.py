#!/usr/bin/env python3
"""
Test script for Suricata Rule Builder
Runs basic tests to ensure the application is working correctly
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, parse_rule, build_rule, validate_rule_syntax, basic_rule_validation

def test_rule_parsing():
    """Test rule parsing functionality"""
    print("Testing rule parsing...")

    test_rule = 'alert tcp any any -> any 80 (msg:"Test Rule"; content:"test"; sid:1000001; rev:1;)'
    parsed = parse_rule(test_rule)

    assert parsed is not None, "Failed to parse valid rule"
    assert parsed['action'] == 'alert', "Incorrect action parsed"
    assert parsed['protocol'] == 'tcp', "Incorrect protocol parsed"
    assert parsed['sid'] == 1000001, "Incorrect SID parsed"
    assert parsed['msg'] == 'Test Rule', "Incorrect message parsed"

    print("✓ Rule parsing tests passed")


def test_rule_building():
    """Test rule building from form data"""
    print("Testing rule building...")

    test_data = {
        'action': 'alert',
        'protocol': 'tcp',
        'src_ip': 'any',
        'src_port': 'any',
        'direction': '->',
        'dst_ip': 'any',
        'dst_port': '80',
        'msg': 'Test Rule',
        'sid': 1000001,
        'rev': 1,
        'contents': [],
        'classtype': 'web-application-attack',
        'priority': 1
    }

    rule = build_rule(test_data)
    assert 'alert tcp any any -> any 80' in rule, "Rule header incorrect"
    assert 'msg:"Test Rule"' in rule, "Message not included"
    assert 'sid:1000001' in rule, "SID not included"
    assert 'classtype:web-application-attack' in rule, "Classtype not included"

    print("✓ Rule building tests passed")


def test_basic_validation():
    """Test basic rule validation"""
    print("Testing basic validation...")

    valid_rule = 'alert tcp any any -> any 80 (msg:"Valid Rule"; sid:1000001; rev:1;)'
    result = basic_rule_validation(valid_rule)
    assert result['valid'] == True, "Valid rule marked as invalid"

    invalid_rule = 'alert tcp any any -> any 80'  # Missing options
    result = basic_rule_validation(invalid_rule)
    assert result['valid'] == False, "Invalid rule marked as valid"

    no_sid_rule = 'alert tcp any any -> any 80 (msg:"No SID";)'
    result = basic_rule_validation(no_sid_rule)
    assert result['valid'] == False, "Rule without SID marked as valid"

    print("✓ Basic validation tests passed")


def test_api_endpoints():
    """Test Flask API endpoints"""
    print("Testing API endpoints...")

    app.config['TESTING'] = True
    client = app.test_client()

    # Test GET /api/rules
    response = client.get('/api/rules')
    assert response.status_code == 200, "GET /api/rules failed"
    data = response.get_json()
    assert 'success' in data, "Response missing success field"
    assert 'rules' in data, "Response missing rules field"

    # Test GET /api/next-sid
    response = client.get('/api/next-sid')
    assert response.status_code == 200, "GET /api/next-sid failed"
    data = response.get_json()
    assert 'next_sid' in data, "Response missing next_sid field"

    # Test GET /api/export
    response = client.get('/api/export')
    assert response.status_code == 200, "GET /api/export failed"
    data = response.get_json()
    assert 'rules' in data, "Export response missing rules field"

    print("✓ API endpoint tests passed")


def test_content_options():
    """Test content matching options"""
    print("Testing content options...")

    test_data = {
        'action': 'alert',
        'protocol': 'http',
        'src_ip': 'any',
        'src_port': 'any',
        'direction': '->',
        'dst_ip': 'any',
        'dst_port': 'any',
        'msg': 'Content Test',
        'sid': 1000002,
        'rev': 1,
        'contents': [
            {
                'value': 'malware',
                'nocase': True,
                'offset': '0',
                'depth': '100'
            }
        ]
    }

    rule = build_rule(test_data)
    assert 'content:"malware"' in rule, "Content not included"
    assert 'nocase' in rule, "Nocase modifier not included"
    assert 'offset:0' in rule, "Offset not included"
    assert 'depth:100' in rule, "Depth not included"

    print("✓ Content options tests passed")


def test_flow_options():
    """Test flow options"""
    print("Testing flow options...")

    test_data = {
        'action': 'alert',
        'protocol': 'tcp',
        'src_ip': 'any',
        'src_port': 'any',
        'direction': '->',
        'dst_ip': 'any',
        'dst_port': '80',
        'msg': 'Flow Test',
        'sid': 1000003,
        'rev': 1,
        'contents': [],
        'flow_established': True,
        'flow_to_server': True
    }

    rule = build_rule(test_data)
    assert 'flow:' in rule, "Flow option not included"
    assert 'established' in rule, "Established flow not included"
    assert 'to_server' in rule, "To_server flow not included"

    print("✓ Flow options tests passed")


def test_threshold_options():
    """Test threshold options"""
    print("Testing threshold options...")

    test_data = {
        'action': 'drop',
        'protocol': 'tcp',
        'src_ip': '$EXTERNAL_NET',
        'src_port': 'any',
        'direction': '->',
        'dst_ip': '$HOME_NET',
        'dst_port': '22',
        'msg': 'SSH Brute Force',
        'sid': 1000004,
        'rev': 1,
        'contents': [],
        'threshold_type': 'threshold',
        'threshold_track': 'by_src',
        'threshold_count': '10',
        'threshold_seconds': '60'
    }

    rule = build_rule(test_data)
    assert 'threshold:' in rule, "Threshold option not included"
    assert 'type threshold' in rule, "Threshold type not included"
    assert 'track by_src' in rule, "Threshold track not included"
    assert 'count 10' in rule, "Threshold count not included"
    assert 'seconds 60' in rule, "Threshold seconds not included"

    print("✓ Threshold options tests passed")


def run_all_tests():
    """Run all tests"""
    print("=" * 50)
    print("Suricata Rule Builder - Test Suite")
    print("=" * 50)
    print()

    try:
        test_rule_parsing()
        test_rule_building()
        test_basic_validation()
        test_content_options()
        test_flow_options()
        test_threshold_options()
        test_api_endpoints()

        print()
        print("=" * 50)
        print("✅ All tests passed successfully!")
        print("=" * 50)
        return 0

    except AssertionError as e:
        print()
        print("=" * 50)
        print(f"❌ Test failed: {e}")
        print("=" * 50)
        return 1
    except Exception as e:
        print()
        print("=" * 50)
        print(f"❌ Unexpected error: {e}")
        print("=" * 50)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
