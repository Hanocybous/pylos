Packaging scripts for Pylos

This folder contains Debian packaging helper scripts used during package install/removal:

- control
  - Debian control metadata (Package, Version, Depends, Maintainer, Description).

- postinst (post-install)
  - Idempotent installer that: creates /opt/pylos if missing, installs a /usr/bin/pylos symlink, copies the systemd unit from /opt/pylos/contrib/pylos.service to /etc/systemd/system, installs an example config at /etc/pylos/config.json if none exists, and reloads/enables the systemd unit when available.
  - Designed to be tolerant of missing systemd (non-fatal) and to not overwrite existing user config.

- prerm (pre-remove)
  - Stops and disables the service (if systemd available), reloads systemd, and removes the global symlink. All operations are best-effort to avoid failing uninstall.

Notes for maintainers:
- Ensure postinst/prerm are executable in the package (chmod +x). They run as root during package operations.
- Adjust INSTALL_DIR and paths if the package layout changes.
- Keep these scripts idempotent and avoid destructive operations on user data (do not delete /etc/pylos/config.json on remove).
