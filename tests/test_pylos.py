import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Insert the parent directory into the path so pytest can import pylos.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pylos

def test_validate_ip():
    # Valid IPs should return the string
    assert pylos.validate_ip("192.168.1.1") == "192.168.1.1"
    # Invalid or out-of-bounds IPs should return None
    assert pylos.validate_ip("256.256.256.256") is None
    assert pylos.validate_ip("not_an_ip") is None

def test_is_whitelisted():
    whitelist = ["127.0.0.0/8", "192.168.0.0/16"]
    
    # Exact match and subnet match should pass
    assert pylos.is_whitelisted("127.0.0.1", whitelist) is True
    assert pylos.is_whitelisted("192.168.5.5", whitelist) is True
    
    # Outside the subnet should fail
    assert pylos.is_whitelisted("10.0.0.1", whitelist) is False

@patch('pylos.subprocess.run')
def test_firewall_ban_ip(mock_run):
    # Setup: Tell the mock to pretend the iptables check (-C) failed (rule doesn't exist)
    mock_run.return_value = MagicMock(returncode=1)
    
    fw = pylos.FirewallController()
    
    # Setup: Tell the mock to pretend the iptables append (-A) succeeded
    mock_run.return_value = MagicMock(returncode=0)
    
    result = fw.ban_ip("1.2.3.4")
    
    # The function should return True (success)
    assert result is True
    
    # Verify the script attempted to execute the correct system command
    mock_run.assert_called_with(
        ["/usr/sbin/iptables", "-A", "PYLOS", "-s", "1.2.3.4", "-j", "DROP"],
        stdout=pylos.subprocess.PIPE,
        stderr=pylos.subprocess.PIPE,
        text=True
    )
