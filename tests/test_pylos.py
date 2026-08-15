import json
import time
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
        text=True, check=False
    )

    # 2. Test IPv6 Routing
    result_v6 = fw.ban_ip("2001:db8::1")
    assert result_v6 is True
    mock_run.assert_any_call(
        ["/usr/sbin/ip6tables", "-A", "PYLOS", "-s", "2001:db8::1", "-j", "DROP"],
        stdout=pylos.subprocess.PIPE,
        stderr=pylos.subprocess.PIPE,
        text=True, check=False
    )


def test_load_config(tmp_path):
    """Test that the daemon correctly parses custom JSON config files."""
    config_file = tmp_path / "config.json"
    fake_config = {
        "max_attempts": 7,
        "ban_duration_seconds": 1200,
        "whitelist": ["10.0.0.0/8"]
    }
    config_file.write_text(json.dumps(fake_config))
    
    # Patch filesystem-touching setup and CONFIG_PATH so test stays unprivileged
    with patch('pylos.ensure_environment'), patch('pylos.CONFIG_PATH', str(config_file)):
        cfg = pylos.load_config()
        
        assert cfg.get("max_attempts") == 7
        assert "10.0.0.0/8" in cfg.get("whitelist", [])

def test_sshd_log_regex():
    """Test that the regex correctly identifies attacks and extracts the IP."""
    regex = getattr(pylos, 'FAIL_REGEX', None)
    
    if regex:
        valid_log = "Failed password for invalid user admin from 203.0.113.50 port 2222 ssh2"
        invalid_log = "Accepted publickey for root from 10.0.0.5 port 2222 ssh2"
        
        match = regex.search(valid_log)
        assert match is not None
        assert match.group("ip") == "203.0.113.50"
        
        assert regex.search(invalid_log) is None

def test_default_config_progressive_keys():
    """Ensure progressive banning keys exist in the default config."""
    assert "progressive_banning" in pylos.DEFAULT_CONFIG
    assert pylos.DEFAULT_CONFIG["progressive_banning"] is True
    assert pylos.DEFAULT_CONFIG["progressive_multiplier"] == 2.0
    assert pylos.DEFAULT_CONFIG["progressive_lookback_seconds"] == 86400

def test_progressive_ban_count(tmp_path):
    """Test that the database correctly counts recent previous bans for an IP."""
    db_file = tmp_path / "pylos.db"
    
    with patch('pylos.DB_PATH', str(db_file)):
        db = pylos.DatabaseManager(db_path=str(db_file))
        now = time.time()
        
        # Add bans to the history
        db.add_ban("192.168.1.100", now - 100000, 3600)  # Outside 24h (86400s) window
        db.add_ban("192.168.1.100", now - 3600, 3600)    # Inside window
        db.add_ban("192.168.1.100", now - 1800, 3600)    # Inside window
        db.add_ban("10.0.0.5", now - 1800, 3600)         # Different IP inside window
        
        # Check lookback counts
        lookback_time = now - 86400
        count_192 = db.get_previous_ban_count("192.168.1.100", lookback_time)
        count_10 = db.get_previous_ban_count("10.0.0.5", lookback_time)
        count_clean = db.get_previous_ban_count("172.16.0.1", lookback_time)
        
        # Assertions
        assert count_192 == 2  # Only the 2 recent bans should be counted
        assert count_10 == 1
        assert count_clean == 0


