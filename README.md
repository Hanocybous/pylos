# 🛡️ Pylos

**Pylos** is a modern, lightweight, and production-grade SSH intrusion prevention daemon for Debian and Ubuntu environments. 

Written in Python, Pylos actively monitors `sshd` logs in real-time and dynamically updates `iptables` and `ip6tables` to instantly block brute-force attacks. Designed with modern server administration in mind, it features zero-downtime configuration reloads, GeoIP instant blocking, and progressive exponential bans for persistent botnets.

## Key Features

* **Dual-Stack Protection:** Native, automated firewall routing for both IPv4 and IPv6 traffic.
* **Instant GeoIP Blocking:** Drop traffic from specific countries on the *very first* failed attempt (or allow only specific countries), powered by lightning-fast local memory caching.
* **Progressive Exponential Bans:** Remembers repeat offenders. If an IP attacks again within 24 hours, its ban time doubles automatically.
* **Zero-Downtime Reloads:** Update your whitelist or config and apply it instantly via `SIGHUP` (`systemctl reload pylos`) without dropping the active log-monitoring threads.
* **Local SQLite Tracking:** Fast and persistent storage for ban history and attack analytics.
* **Native Systemd Integration:** Runs as a standard background service with auto-restart capabilities.

---

## Installation

The easiest way to install Pylos is via the pre-compiled Debian package available on the [Releases](https://github.com/Hanocybous/pylos/releases) page.

```bash
# 1. Download the latest release (update the version number as needed)
wget https://github.com/Hanocybous/pylos/releases/download/v1.4.0/pylos_1.4.0_all.deb

# 2. Install it (pulls in dependencies, then enables and starts the service)
sudo apt install ./pylos_1.4.0_all.deb
```

## Usage

```bash
pylos status                  # config summary and ban statistics
pylos list                    # active bans
sudo pylos ban 203.0.113.7 -d 600
sudo pylos unban 203.0.113.7
sudo systemctl reload pylos   # re-read the config without restarting
```

## Configuration

Config lives in `/etc/pylos/config.json` and is created with defaults on first run. See [`contrib/config.example.json`](contrib/config.example.json) for every key. Missing keys fall back to the defaults.

GeoIP blocking (on by default) sends each attacking IP to `ip-api.com` over HTTP. Set `"geoip_blocking": false` if you don't want any outbound lookups.

Ban history is stored in `/var/lib/pylos/pylos.db`.

## Development

```bash
pip install -r requirements-dev.txt
pytest
pylint -d C,R $(git ls-files '*.py')
```

Releases are built by pushing a `vX.Y.Z` tag. See [`packaging/README.md`](packaging/README.md).
