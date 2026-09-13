Systemd unit and example config for Pylos

Place the service unit at /etc/systemd/system/pylos.service and the config at /etc/pylos/config.json.

Installation example:

sudo cp contrib/pylos.service /etc/systemd/system/pylos.service
sudo mkdir -p /etc/pylos
sudo cp contrib/config.example.json /etc/pylos/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now pylos

Notes:
- ExecStart may need to be adjusted depending on how Pylos is installed.
- For least-privilege operation consider packaging Pylos so it can run with CAP_NET_ADMIN instead of full root.

