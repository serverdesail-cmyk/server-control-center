# SCC — Server Control Center

SCC is a self-hosted web workspace for securely managing an explicitly mounted part of an Arch-based Linux server. The first release focuses on authenticated file operations, owner-managed accounts and folder grants, and a responsive interface.

## Install on Arch, CachyOS, or another Arch-based distribution

Run this single command on the server:

```sh
curl -fsSL https://raw.githubusercontent.com/serverdesail-cmyk/server-control-center/main/install-scc.sh | sudo bash
```

The installer verifies the distribution, installs missing Arch packages with `pacman` (without a partial system upgrade), enables Docker when needed, fetches this public repository, creates a one-time setup token, builds the container, and checks the health endpoint.

Run the command from an unprivileged user account with `sudo`. SCC runs inside the container as that invoking user's numeric UID/GID, not as root. The installer does not add the user to the Docker group.

## First-owner setup

On the server, open `http://localhost:8787` and retrieve the one-time token in a terminal:

```sh
sudo scc setup-token
```

Enter that token, a username, and a password of at least 12 characters in the setup screen. Setup is single-use: the database enforces one OWNER account. After setup, run `sudo scc setup-token` again to remove the now-unused token from the Compose environment.

Keep the owner credentials private. The setup token is not printed during installation or written to installer logs.

## Network access and ngrok

The default listener is `127.0.0.1:8787`, so the service is not directly exposed to a LAN or the public internet. For remote access, use ngrok's HTTPS endpoint:

```sh
ngrok http http://127.0.0.1:8787
```

Open the HTTPS URL displayed by ngrok. SCC still requires its own login; ngrok is only the transport.

To allow direct LAN access, edit `/opt/server-control-center/.env` and set `SCC_BIND_ADDRESS` to the server's LAN address, then apply the change:

```sh
sudo scc restart
```

Configure the host firewall before doing this. `SCC_COOKIE_SECURE=true` is the recommended setting and requires HTTPS for browser sessions. Do not turn it off on an untrusted network.

## Filesystem access boundary

By default, the only host directory mounted into the application is `/srv`. The entire host filesystem and Docker socket are not mounted. The OWNER can grant application permissions beneath this configured root; the container's numeric user must also have the relevant Linux filesystem permissions. SCC does not change host ownership or mode bits.

To use a different dedicated host directory, stop the service, update `SCC_HOST_ROOT` in `/opt/server-control-center/.env` to an existing absolute directory other than `/`, and run `sudo scc restart`. The host root must not contain a colon. Only that one directory is mounted into the container.

SCC uses descriptor-relative Linux filesystem operations, refuses symbolic-link traversal, rejects `..` path components, and does not permit overwriting an existing file during upload or rename. Upload data is streamed in bounded chunks (1 GiB maximum by default); downloads support HTTP byte ranges. Text editing is limited to UTF-8 files up to 1 MiB.

## Available features

- One-time OWNER bootstrap, Argon2id password hashing, opaque random sessions stored server-side, session expiry and revocation.
- HttpOnly, SameSite cookies; Secure cookies by default; CSRF and same-host Origin checks on browser mutations; login throttling; security headers.
- OWNER-managed USER and ADMIN accounts, account disable/delete, password reset, and session revocation.
- Per-user nested folder grants for browsing, reading, downloading, uploading, creating, editing, renaming, and deleting. A deeper grant replaces the inherited rule for that folder.
- File/folder listing, previews and bounded editing, create, upload with progress/cancel, range downloads, rename and delete.
- Storage information and a limited owner-only activity feed.
- Six built-in color themes, safe JSON color-theme import/export, and local appearance preferences.
- Docker Compose deployment with a read-only container root, dropped Linux capabilities, resource limits, `no-new-privileges`, and an unprivileged container process.

## Release boundaries

This initial release does not expose Docker resource controls, a browser terminal, public sharing links, host-wide filesystem browsing, a privileged host agent, resumable/pause-and-resume transfers, syntax highlighting, recursive search, or complete CPU/memory/network monitoring. Those functions are intentionally not represented as working features or given privileged access. The installed version is a secure, useful file-management foundation, not the full feature set in the SCC specification.

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
