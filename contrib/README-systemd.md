Example config for Pylos (the systemd unit is `pylos.service` in the repo root)

Place the service unit at /etc/systemd/system/pylos.service and the config at /etc/pylos/config.json.

Installation example:

sudo cp pylos.service /etc/systemd/system/pylos.service
sudo mkdir -p /etc/pylos
sudo cp contrib/config.example.json /etc/pylos/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now pylos

Notes:
- ExecStart expects `/usr/bin/pylos`; adjust it for a manual install (e.g. `/usr/bin/python3 /path/to/pylos.py daemon`).
- For least-privilege operation consider packaging Pylos so it can run with CAP_NET_ADMIN instead of full root.

