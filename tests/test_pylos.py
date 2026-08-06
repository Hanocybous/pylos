import os
import sys
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
    # Dynamic Mock: If checking for a rule (-C), pretend it doesn't exist (return 1). 
    # For all other commands (-N, -I, -A), pretend they succeeded (return 0).
    def mock_subprocess(cmd, **_kwargs):
        if "-C" in cmd:
            return MagicMock(returncode=1)
        return MagicMock(returncode=0)
        
    mock_run.side_effect = mock_subprocess
    
    fw = pylos.FirewallController()
    
    # 1. Test IPv4 Routing
    result_v4 = fw.ban_ip("1.2.3.4")
    assert result_v4 is True
    mock_run.assert_any_call(
        ["/usr/sbin/iptables", "-A", "PYLOS", "-s", "1.2.3.4", "-j", "DROP"],
        stdout=pylos.subprocess.PIPE,
        stderr=pylos.subprocess.PIPE,
        text=True
    )

    # 2. Test IPv6 Routing
    result_v6 = fw.ban_ip("2001:db8::1")
    assert result_v6 is True
    mock_run.assert_any_call(
        ["/usr/sbin/ip6tables", "-A", "PYLOS", "-s", "2001:db8::1", "-j", "DROP"],
        stdout=pylos.subprocess.PIPE,
        stderr=pylos.subprocess.PIPE,
        text=True
    )