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
wget [https://github.com/Hanocybous/pylos/releases/download/v1.4.0/pylos_1.4.0_all.deb](https://github.com/Hanocybous/pylos/releases/download/v1.4.0/pylos_1.4.0_all.deb)

# 2. Install the package
sudo dpkg -i pylos_1.4.0_all.deb
sudo apt-get install -f

# 3. Enable and start the daemon
sudo systemctl enable --now pylos
