Packaging scripts for Pylos

`.github/workflows/release.yml` builds the `.deb` on every `v*.*.*` tag. Package layout:

- `/opt/pylos/pylos.py` - the program
- `/lib/systemd/system/pylos.service` - the unit (from the repo root `pylos.service`)

Scripts in this folder:

- `control` - Debian metadata. `Version` is overwritten from the git tag at build time.
- `postinst` - links `/usr/bin/pylos`, reloads systemd, enables and starts the service.
  Config is not installed here: Pylos writes `/etc/pylos/config.json` with defaults on first run and never overwrites it.
- `prerm` - stops and disables the service and removes the symlink. Best-effort; never deletes config or the database.

Keep both scripts idempotent; they run as root.
