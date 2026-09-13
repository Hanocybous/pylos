import os
import time
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pylos


class DummyMonitorBanOnce:
    """Yields a series of failed-login lines for a single IP then raises SystemExit to stop the daemon."""
    def __init__(self, ip='1.2.3.4', attempts=5):
        self.ip = ip
        self.attempts = attempts
        self.count = 0

    def read_line(self, timeout=1.0):
        if self.count < self.attempts:
            self.count += 1
            return f"Failed password for invalid user admin from {self.ip} port 2222 ssh2"
        raise SystemExit("stop")

    def terminate(self):
        pass


class DummyMonitorGeoIP:
    def __init__(self, ip='8.8.8.8'):
        self.ip = ip
        self.count = 0

    def read_line(self, timeout=1.0):
        if self.count == 0:
            self.count += 1
            return f"Failed password for invalid user admin from {self.ip} port 2222 ssh2"
        raise SystemExit("stop")

    def terminate(self):
        pass


@patch('pylos.ensure_environment')
@patch('pylos.signal.signal')
@patch('pylos.os.geteuid', return_value=0, create=True)
def test_run_daemon_progressive_ban(mock_euid, mock_signal, mock_env, tmp_path):
    db_file = tmp_path / 'pylos.db'

    with patch('pylos.DB_PATH', str(db_file)):
        # Replace monitor, firewall controller, and geoip lookup
        with patch('pylos.SSHLogMonitor', return_value=DummyMonitorBanOnce(attempts=5)), patch('pylos.FirewallController._setup_chain', return_value=None):
            fw_calls = {'banned': []}

            def fake_ban(ip):
                fw_calls['banned'].append(ip)
                return True

            with patch.object(pylos.FirewallController, 'ban_ip', side_effect=fake_ban), \
                 patch.object(pylos.FirewallController, 'unban_ip', return_value=True):

                # Make progressive lookback small so earlier bans are irrelevant for this test
                with patch('pylos.load_config', return_value={**pylos.DEFAULT_CONFIG, 'max_attempts': 5, 'ban_duration_seconds': 2, 'progressive_lookback_seconds': 86400, 'geoip_blocking': False}):
                    # Ensure SIGHUP exists on Windows test environment
                    pylos.signal.SIGHUP = 1
                    # Run daemon; it will raise SystemExit from DummyMonitor and exit
                    try:
                        pylos.run_daemon()
                    except SystemExit:
                        pass

                # Assert the IP was banned
                assert '1.2.3.4' in fw_calls['banned']

                # Verify DB contains an active ban for that IP
                db = pylos.DatabaseManager(db_path=str(db_file))
                active = db.get_active_bans()
                assert any(row['ip'] == '1.2.3.4' for row in active)


@patch('pylos.ensure_environment')
@patch('pylos.signal.signal')
@patch('pylos.os.geteuid', return_value=0, create=True)
def test_run_daemon_geoip_instant_ban(mock_euid, mock_signal, mock_env, tmp_path):
    db_file = tmp_path / 'pylos_geo.db'

    with patch('pylos.DB_PATH', str(db_file)):
        with patch('pylos.SSHLogMonitor', return_value=DummyMonitorGeoIP(ip='203.0.113.50')), patch('pylos.FirewallController._setup_chain', return_value=None):
            fw_calls = {'banned': []}

            def fake_ban(ip):
                fw_calls['banned'].append(ip)
                return True

            with patch.object(pylos.FirewallController, 'ban_ip', side_effect=fake_ban):
                # Mock geolocation to return a blocked country
                with patch('pylos.get_country_code', return_value='CN'):
                    cfg = {**pylos.DEFAULT_CONFIG, 'geoip_blocking': True, 'blocked_countries': ['CN']}
                    with patch('pylos.load_config', return_value=cfg):
                        # Ensure SIGHUP exists on Windows test environment
                        pylos.signal.SIGHUP = 1
                        try:
                            pylos.run_daemon()
                        except SystemExit:
                            pass

                assert '203.0.113.50' in fw_calls['banned']

                db = pylos.DatabaseManager(db_path=str(db_file))
                bans = db.get_active_bans()
                assert any('203.0.113.50' == row['ip'] for row in bans)
                # GeoIP bans are recorded with a long duration in the code (10 years)
                assert any('GeoIP Block' in (row['reason'] or '') for row in db._get_connection().execute('SELECT reason FROM ban_history').fetchall())
