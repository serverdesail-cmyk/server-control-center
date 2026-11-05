# SCC — Server Control Center

SCC is a self-hosted web workspace for securely managing an explicitly mounted part of an Arch-based Linux server. It provides authenticated file operations, Root_user-managed accounts and folder grants, live host monitoring, and a customizable responsive workspace.

## Install on Arch, CachyOS, or another Arch-based distribution

Run this single command on the server:

```sh
curl -fsSL https://raw.githubusercontent.com/serverdesail-cmyk/server-control-center/main/install-scc.sh | sudo bash
```

The installer verifies the distribution, installs missing Arch packages with `pacman` (without a partial system upgrade), enables Docker when needed, refreshes installed SCC files from a clean GitHub checkout, creates a one-time setup token when needed, rebuilds the container, and checks the health endpoint.

Re-running this command is also the repair path: it replaces stale or damaged SCC source, Git metadata, and launchers while preserving `/opt/server-control-center/.env` and persistent data. For an older installation, `/etc/server-control-center/.env` is retained when no current configuration exists, and a detected legacy management command is redirected to the repaired installation. Unrelated files in the application directory and persistent data are not removed.

Run the command from an unprivileged user account with `sudo`. SCC runs inside the container as that invoking user's numeric UID/GID, not as root. The installer does not add the user to the Docker group.

## Root_user setup

On the server, open `http://localhost:8787` and retrieve the one-time token in a terminal:

```sh
sudo scc setup-token
```

Enter that token, a username, and a password of at least 12 characters in the setup screen to create the Root_user account. Setup is single-use: the database enforces one privileged account (stored internally as `owner`). After setup, run `sudo scc setup-token` again to remove the now-unused token from the Compose environment.

Keep the owner credentials private. The setup token is not printed during installation or written to installer logs.

## Network access and ngrok

The default listener is `127.0.0.1:8787`, so the service is not directly exposed to a LAN or the public internet. For remote access, use ngrok's HTTPS endpoint:

```sh
ngrok http http://127.0.0.1:8787
```

Open the HTTPS URL displayed by ngrok. SCC still requires its own login; ngrok is only the transport.

To allow direct LAN access, edit `/opt/server-control-center/.env` and set `SCC_BIND_ADDRESS` to the server's LAN address, then apply the change. `sudo scc restart` recreates the container so updated environment and mount settings take effect:

```sh
sudo scc restart
```

Configure the host firewall before doing this. `SCC_COOKIE_SECURE=true` is the recommended setting and requires HTTPS for browser sessions. Do not turn it off on an untrusted network.

## Filesystem access boundary

By default, the only host directory mounted into the application is `/srv`. The entire host filesystem and Docker socket are not mounted. Root_user can choose an active workspace directory from the Access control page, anywhere inside this configured mount. Root_user can manage everything inside that active root without application-level grants; the container's numeric user must still have the relevant Linux filesystem permissions. USER and ADMIN accounts are constrained by grants beneath the active root. SCC does not change host ownership or mode bits.

The active root can be changed in the owner panel without restarting. Changing it remaps grants that still point inside the new root and removes grants that would no longer refer to the same physical paths. The owner can browse and apply only directories inside the configured mount.

To use a different dedicated host directory or expand the available host boundary, update `SCC_HOST_ROOT` in `/opt/server-control-center/.env` to an existing absolute directory other than `/`, then run `sudo scc restart` to recreate the container with the new mount. The host root must not contain a colon. Only that one directory is mounted into the container.

SCC uses descriptor-relative Linux filesystem operations, refuses symbolic-link traversal, rejects `..` path components, and does not permit overwriting an existing file during upload or rename. Upload data is streamed in bounded chunks (1 GiB maximum by default); downloads support HTTP byte ranges. Text editing is limited to UTF-8 files up to 1 MiB.

## Available features

- One-time Root_user bootstrap, Argon2id password hashing, opaque random sessions stored server-side, session expiry and revocation.
- HttpOnly, SameSite cookies; Secure cookies by default; CSRF and same-host Origin checks on browser mutations; login throttling; security headers.
- Root_user-managed USER and ADMIN accounts, account disable/delete, password reset, and session revocation.
- Per-user nested folder grants for browsing, reading, downloading, uploading, creating, editing, renaming, and deleting. A deeper grant replaces the inherited rule for that folder.
- File/folder listing, previews and bounded editing, create, range downloads, rename and delete. Multi-file uploads run one at a time with per-file and overall progress, visible failures, retry, and queue cancellation; a failed file does not discard the rest of the selection.
- Root_user-selectable active filesystem root inside the fixed host mount, with safe grant remapping and an in-app directory picker.
- Live host CPU, memory, uptime, load-average, network-counter, and filesystem-volume monitoring for the volume containing the active root. Resource warning thresholds and shared overview sections/actions are configurable by Root_user. A rolling 5-minute chart is held in the open browser session; selected `/proc` files are mounted read-only, and SCC does not inspect process command lines or control the host.
- Separate Logs view with live server audit entries and per-account browser activity kept in that browser's local storage. Regular accounts see only their own server audit records; Root_user can see all. Raw container output remains host-only through `sudo scc logs`.
- Per-account profile pictures optimized in the browser and stored with the server-side account profile.
- Six built-in color themes, safe JSON color-theme import/export, and per-device menu visibility and ordering. Menus can be reordered by drag-and-drop or accessible move controls.
- Circular quick actions can be chosen per account and device; Root_user controls which shared dashboard sections and shortcuts are available.
- Docker Compose deployment with a read-only container root, dropped Linux capabilities, resource limits, `no-new-privileges`, and an unprivileged container process.

## Release boundaries

SCC does not expose Docker resource controls, a browser terminal, public sharing links, host-wide filesystem browsing, a privileged host agent, resumable/pause-and-resume transfers, syntax highlighting, or recursive search. The configured host mount remains the hard boundary; the web application cannot access `/` or bypass Linux permissions.

## Management

```sh
sudo scc start
sudo scc stop
sudo scc restart
sudo scc update
sudo scc logs
sudo scc status
sudo scc setup-token
sudo scc uninstall
```

`sudo scc update` fetches the latest code, rebuilds/recreates the container, then verifies that the health endpoint reports the version in the updated source. The installer performs the same version check. Account, profile, grant, session, and audit data remain in `/var/lib/server-control-center/data`; database initialization adds new columns/settings without replacing that database. Keep a backup of this directory before updates. If the configured host mount changes, an active root that is no longer within it safely resets to the new mount and stale grants are cleared.

Uninstall asks before stopping/removing application files, then separately asks whether to delete persistent application data under `/var/lib/server-control-center/`. Answer no to retain that data.

## Configuration

The installer writes `/opt/server-control-center/.env` with mode `0600`. The safe template is [.env.example](./.env.example). Important values:

| Variable | Default | Purpose |
|---|---:|---|
| `SCC_UID` / `SCC_GID` | invoking user | Numeric identity used inside the container |
| `SCC_HOST_ROOT` | `/srv` | The single host filesystem path mounted into SCC |
| `SCC_DATA_PATH` | `/var/lib/server-control-center/data` | Persistent SQLite state |
| `SCC_BIND_ADDRESS` | `127.0.0.1` | Host listener address |
| `SCC_PORT` | `8787` | Host listener port |
| `SCC_COOKIE_SECURE` | `true` | Require HTTPS-compatible Secure cookies |
| `SCC_MAX_UPLOAD_BYTES` | `1073741824` | Maximum individual upload size |

Do not publish the database or `.env` file. No credential is hardcoded in the source.

## Development and tests

Requirements: Python 3.12+, Linux for filesystem integration tests.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/test-requirements.txt
python -m pytest -q
```

Windows may run the API/authentication tests; Linux-specific descriptor and `renameat2` integration tests are skipped there. GitHub Actions runs the complete test suite on Ubuntu 24.04 with Python 3.12.

To validate Compose configuration on an installed server:

```sh
sudo docker compose --project-name scc \
  --project-directory /opt/server-control-center \
  --env-file /opt/server-control-center/.env \
  -f /opt/server-control-center/docker-compose.yml config --quiet
```

## Security notes

- Docker Engine itself is a root-level host service. SCC never receives its socket and does not add a user to the root-equivalent Docker group.
- The service is intended to be reached locally or through an HTTPS reverse tunnel. Set firewall rules before changing the bind address.
- Owner grants authorize operations only inside the configured mount and never replace the host user's Linux permissions.
- Review the source and installer before running administrative installation commands.

## References

- [ArchWiki: Docker](https://wiki.archlinux.org/title/Docker)
- [Docker Compose on Linux](https://docs.docker.com/compose/install/linux/)
- [Docker Engine security](https://docs.docker.com/engine/security/)
- [FastAPI password hashing guidance](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Docker Compose environment interpolation](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)

## Minecraft moderation integration

The Minecraft page is a separate workspace from the file manager and uses the same SCC login. It connects to a Minecraft Java server through RCON. Enable `enable-rcon=true` and set a strong `rcon.password` in the server's `server.properties`; keep the RCON port private and firewall it so only the SCC host can reach it. Set `SCC_MC_RCON_HOST`, `SCC_MC_RCON_PORT`, and `SCC_MC_RCON_PASSWORD` in the SCC backend environment (the `.env.example` shows the names), then restart SCC. The moderation endpoint is owner-only and supports kick, ban, and pardon. Do not expose RCON directly to the public internet.

For Docker deployments, use the Minecraft server's reachable hostname or LAN address as `SCC_MC_RCON_HOST`; `127.0.0.1` refers to the SCC container itself. Ensure the server's RCON port is reachable from the SCC container without publishing it publicly.
