# SCC security model

## Container boundary

SCC is intended to run as the dedicated, non-login `scc` host account inside Docker Compose. The application container:

- runs as a non-root numeric UID/GID;
- has a read-only container filesystem and a small `noexec,nosuid` temporary filesystem;
- drops all Linux capabilities and enables `no-new-privileges`;
- has CPU, memory, PID, file-descriptor, and log-size limits;
- receives only the SCC database directory, one dedicated user-file directory, and selected read-only host `/proc` telemetry files; the installer and app reject overlapping file/database mounts;
- does not receive the Docker socket, host network, privileged mode, or host root filesystem.

Docker containers share the host kernel. This is meaningful isolation, but it is not equivalent to a virtual machine. Keep Docker and the host kernel updated. A Docker daemon or kernel compromise is outside the application's security boundary.

## Application protections

- All file operations are authorized by the backend; UI visibility is not treated as an access control.
- Directory listings omit entries without grants. Ancestor folders needed to reach a deeper grant are shown by name and type only, without metadata.
- Filesystem operations use Linux descriptor-relative APIs, reject traversal, and do not follow symlinks.
- Upload request bodies are bounded before multipart parsing, individual files have a configurable size cap, and the configured file mount has aggregate regular-file byte and entry-count caps.
- Upload content is treated as opaque bytes: SCC does not execute uploaded files, uses mode `0600` for newly uploaded files, and exposes downloads as attachments. Arbitrary uploads are not rendered inline. The PDF preview only serves `.pdf` files with a PDF signature, to an authenticated account with `read` permission, as `application/pdf` in a same-origin frame under a restrictive CSP. Keep managed directories away from host services that automatically execute or load their contents; file mode does not prevent an interpreter or another service from reading a file.
- Each account's Minecraft RCON password is Fernet-encrypted and stored separately from account settings in SQLite. The Fernet key is a mode-`0600` file in the SCC private data directory; protect and back it up with the database. RCON configuration only permits private, non-loopback hosts, and DNS results are validated again immediately before the connection. Keep the RCON listener private and use a strong unique password.
- Login attempts are limited per username/client address and across all usernames per client address.
- Mutating browser requests require same-host Origin and CSRF validation.

## Public access

The host listener defaults to loopback. For remote access, put SCC behind an HTTPS tunnel or reverse proxy, keep `SCC_COOKIE_SECURE=true`, use strong unique passwords, and remove the one-time setup token after owner setup. Do not expose Docker, SSH, or other administration ports through the tunnel.

`SCC_TRUSTED_PROXY_CIDRS` controls which proxy peer networks may supply the client address through `X-Forwarded-For`. Keep this list limited to the actual local proxy/Docker bridge. Do not add arbitrary internet ranges. The default includes Docker's private bridge ranges and loopback for the intended local-tunnel deployment.

The Compose network is a project-scoped bridge, not a host network. It is not an outbound firewall: SCC may need outbound access for explicitly configured integrations such as Minecraft RCON. Do not add blanket private-network `iptables` blocks without accounting for those integrations and the host's network design.

Minecraft RCON settings are scoped to the logged-in account. The RCON integration sends only the supported `list`, `kick`, `ban`, and `pardon` commands. It resolves configured names and rejects any DNS answer that is not a private, non-loopback address before connecting. Private-network access is still a sensitive capability: configure RCON only on the intended Minecraft host, restrict it with host firewall rules, and use a strong unique RCON password.

## Storage quota limitation

The 10 GiB byte quota and 100,000-entry default cap are enforced by SCC when SCC creates files/folders or performs uploads. The byte counter counts regular files under the configured mount; the entry counter also counts directories and links. Creation operations are serialized within the single application process. It is not a kernel/filesystem quota: another host process with write access can still consume space, and an administrator can change the configured limit. For a hard host-wide ceiling, use a dedicated filesystem, project quota, or volume quota at the host layer.

## Validation

The API test suite covers authentication, CSRF, grants, directory-list filtering, path traversal, symlink handling, bounded uploads, storage quota cleanup, and login throttling. Run `python -m pytest -q` on the target Linux distribution before deployment. The release should also be checked with `docker compose config` and a staging deployment; a source-level test run does not prove the host's Docker, firewall, or tunnel configuration is correct.


## Quota and accounting caveats (0.6.0)

Quota configuration is persistent in the SCC SQLite database. Upload quota
checks are serialized by the application's process-local lock; deployments with
multiple application workers/replicas are not supported for strict concurrent
quota enforcement. Global usage is measured from the managed filesystem tree.
Ownership is only attributed where an SCC operation or explicit reconciliation
has established an owner; pre-existing/unrecognized files remain unknown.

The current release does not provide a kernel-enforced filesystem quota, nor
does it yet guarantee complete ownership accounting for every external writer,
all file-edit/duplicate/archive workflows, or crash windows between filesystem
placement and SQLite commit. Use a dedicated filesystem/project quota for a
hard storage ceiling, keep the managed root writable only by the SCC service
account, and back up the SQLite database and managed files together.
