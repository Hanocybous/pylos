# Pylos: SSH Intrusion Autoblocker

Pylos is a production-grade, Python-based security daemon for Debian/Ubuntu servers. It tails `journalctl` for failed SSH authentication attempts and dynamically manages IPTables firewall rules to drop malicious IPs.

## Features
* **Zero-Dependency Core:** Uses standard Python libraries (SQLite3, IPAddress, Subprocess).
* **Database Persistence:** Active bans and historical logs survive server reboots.
* **CLI Management:** Built-in command line interface (`pylos status`, `pylos ban`, `pylos list`).
* **Subnet Whitelisting:** Protects local and internal network ranges from accidental lockouts.
* **Discord Webhooks:** Sends rich embed alerts upon ban execution.
* **Self-Pruning:** Automatically cleans old logs to prevent disk exhaustion (DoS protection).

## Installation
You can install Pylos using the pre-compiled `.deb` package from the Releases tab:
```bash
sudo apt install ./pylos_1.0-1_all.deb
```
