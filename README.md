# caddy-webui

A tiny structured web UI for managing `reverse_proxy` routes in a Caddyfile.
Standard-library-only Python 3, single file (`app.py`), no dependencies to
install. Runs alongside Caddy on the same host so it can write the Caddyfile
and trigger a reload directly.

## What it can and can't edit

A site block is editable in the UI only if its body is exactly one line:
`reverse_proxy <upstream>` or `reverse_proxy <matcher> <upstream>` (matcher
being a leading `/path*` or `@name`). Anything else — multiple directives, an
options block (`transport`, `header_up`, etc.), matchers with their own
braces, comments inside the block — is shown read-only as a "custom" block
and is preserved byte-for-byte on every save. The tool never rewrites config
it doesn't fully understand.

Every save: writes to a temp file → `caddy validate --config <tmp> --adapter
caddyfile` → only on success, backs up the current Caddyfile with a
timestamp, atomically replaces it, then runs `caddy reload`. If validation
fails, nothing on disk changes and the error is shown in the UI.

## Quickstart (deploy to your own Caddy host)

Needs: Python 3.8+ and the `caddy` binary already on the box. No pip
packages required.

1. **Copy the files onto the host** running Caddy (e.g. `scp app.py
   caddy-webui.service config.json.example user@host:/tmp/`).

2. **Install the app:**

   ```
   sudo mkdir -p /opt/caddy-webui /etc/caddy-webui
   sudo cp app.py /opt/caddy-webui/app.py
   sudo cp config.json.example /etc/caddy-webui/config.json
   ```

3. **Edit `/etc/caddy-webui/config.json`** — at minimum check
   `caddyfile_path` points at your real Caddyfile, and `listen_port` is free:

   ```json
   {
     "caddyfile_path": "/etc/caddy/Caddyfile",
     "backup_dir": "/etc/caddy/caddyfile-backups",
     "listen_host": "127.0.0.1",
     "listen_port": 8080,
     "reload_cmd": ["/usr/bin/caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--force"],
     "caddy_bin": "/usr/bin/caddy"
   }
   ```

4. **Set the admin password** (this fills in `password_salt`/`password_hash`
   in the config file — pick whatever OS user will actually run the service,
   see step 6):

   ```
   sudo python3 /opt/caddy-webui/app.py set-password /etc/caddy-webui/config.json
   ```

5. **Make sure the backup dir exists and permissions line up:**

   ```
   sudo mkdir -p /etc/caddy/caddyfile-backups
   ```

6. **Install and start the systemd service.** `caddy-webui.service` runs the
   app as `User=caddy` — the same OS user Caddy's own systemd unit typically
   runs as. That's what lets it write the Caddyfile and call `caddy reload`
   with no sudo/polkit setup. Check what user *your* Caddy service actually
   runs as (`systemctl cat caddy | grep User=`) and edit the unit file to
   match if it's different, then:

   ```
   sudo cp caddy-webui.service /etc/systemd/system/caddy-webui.service
   sudo chown caddy:caddy /opt/caddy-webui/app.py /etc/caddy-webui/config.json
   sudo systemctl daemon-reload
   sudo systemctl enable --now caddy-webui
   sudo systemctl status caddy-webui
   ```

7. **Access it.** By default it only listens on `127.0.0.1:8080` on the
   host. Two easy ways to reach it:

   - **SSH tunnel** (simplest, no extra config):
     ```
     ssh -L 8080:127.0.0.1:8080 user@host
     ```
     then browse to `http://127.0.0.1:8080`.

   - **Expose it via Caddy itself**, e.g. add this block to your Caddyfile
     (adjust the address to your LAN IP or a hostname, and use `tls
     internal` if you don't have a public domain/cert for it):
     ```
     your-host-ip:8443 {
         tls internal
         reverse_proxy 127.0.0.1:8080
     }
     ```
     Note: if you use `tls internal`, give the block a real address (an IP
     or hostname) rather than a bare `:8443` — Caddy's internal CA needs an
     identifiable host to issue a certificate for, and a hostless address
     will fail the TLS handshake.

## Changing the password

```
sudo python3 /opt/caddy-webui/app.py set-password /etc/caddy-webui/config.json
sudo systemctl restart caddy-webui   # restarting clears all sessions
```

## Rollback

If a save ever produces something wrong (shouldn't happen — validation runs
first) or you just want to revert:

```
ls -lt /etc/caddy/caddyfile-backups/       # find the timestamp you want
sudo cp /etc/caddy/caddyfile-backups/Caddyfile.<timestamp> /etc/caddy/Caddyfile
sudo caddy reload --config /etc/caddy/Caddyfile --force
```

## Redeploying after an app.py change

```
scp app.py user@host:/tmp/app.py
ssh user@host 'sudo cp /tmp/app.py /opt/caddy-webui/app.py && sudo chown caddy:caddy /opt/caddy-webui/app.py && sudo systemctl restart caddy-webui'
```

## Known limitations

- Single shared password, in-memory sessions (a restart logs everyone out).
- No CSRF token — mitigated by `SameSite=Strict` on the session cookie, but
  don't expose this outside a trusted network without adding auth in front
  (e.g. a Caddy `basic_auth` layer) if you add a public route to it.
- Multi-host addresses (comma-separated) are supported as a single opaque
  address string, editable as one field.
- New routes are always appended at the end of the file, not near related
  blocks.
