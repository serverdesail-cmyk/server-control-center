#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY_URL="https://github.com/serverdesail-cmyk/server-control-center.git"
readonly INSTALL_DIR="/opt/server-control-center"
readonly LEGACY_INSTALL_DIR="/etc/server-control-center"
readonly STATE_DIR="/var/lib/server-control-center"
readonly DATA_DIR="${STATE_DIR}/data"
readonly SERVICE_USER="scc"
readonly SERVICE_GROUP="scc"
readonly DEFAULT_FILES_DIR="/srv/server-control-center-files"
readonly WRAPPER="/usr/local/bin/scc"
readonly PRIVILEGED_HELPER="/usr/local/libexec/scc-manager"
readonly SUDOERS_FILE="/etc/sudoers.d/scc-manager-${SUDO_UID:-unknown}"

log() { printf '[scc-install] %s\n' "$*"; }
fail() { printf '[scc-install] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  fail "Run as root, for example: curl -fsSL https://raw.githubusercontent.com/serverdesail-cmyk/server-control-center/main/install-scc.sh | sudo bash"
fi

if [[ ! -r /etc/os-release ]]; then
  fail "Cannot identify the operating system (/etc/os-release is missing)."
fi
# shellcheck disable=SC1091
source /etc/os-release
os_id="${ID,,}"
os_like="${ID_LIKE,,}"
case " ${os_id} ${os_like} " in
  *" arch "*|*" cachyos "*|*" manjaro "*|*" endeavouros "*|*" garuda "*|*" artix "*)
    ;;
  *)
    fail "This installer supports Arch-based distributions only. Detected: ${PRETTY_NAME:-$os_id}"
    ;;
esac

if ! command -v pacman >/dev/null 2>&1; then
  fail "pacman is required on supported Arch-based systems."
fi
if [[ -z "${SUDO_UID:-}" || "${SUDO_UID}" -eq 0 ]]; then
  fail "Use sudo from an unprivileged account so SCC can run as that account and respect Linux file permissions."
fi
if ! getent passwd "${SUDO_UID}" >/dev/null 2>&1; then
  fail "Could not resolve the invoking user ID ${SUDO_UID}."
fi

packages=()
command -v docker >/dev/null 2>&1 || packages+=(docker)
docker compose version >/dev/null 2>&1 || packages+=(docker-compose)
command -v git >/dev/null 2>&1 || packages+=(git)
command -v curl >/dev/null 2>&1 || packages+=(curl)
command -v openssl >/dev/null 2>&1 || packages+=(openssl)
command -v sudo >/dev/null 2>&1 || packages+=(sudo)
if ((${#packages[@]})); then
  log "Installing missing Arch packages: ${packages[*]}"
  pacman -S --needed --noconfirm "${packages[@]}" || fail "pacman could not install required packages. Update your system with a full system upgrade, then rerun this installer."
fi

command -v docker >/dev/null 2>&1 || fail "Docker CLI is still unavailable after package installation."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is unavailable. Install the Arch docker-compose package and retry."
command -v git >/dev/null 2>&1 || fail "Git is required to fetch and update SCC."
command -v tar >/dev/null 2>&1 || fail "tar is required to refresh the SCC installation."
command -v curl >/dev/null 2>&1 || fail "curl is required for SCC health checks."
command -v openssl >/dev/null 2>&1 || fail "OpenSSL is required to generate the one-time setup token."
command -v sudo >/dev/null 2>&1 || fail "sudo is required for the restricted passwordless management launcher."
command -v visudo >/dev/null 2>&1 || fail "visudo is required to validate the restricted management permission."
command -v groupadd >/dev/null 2>&1 || fail "groupadd is required to create the dedicated SCC account."
command -v useradd >/dev/null 2>&1 || fail "useradd is required to create the dedicated SCC account."

if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${SERVICE_GROUP}" || fail "Could not create the dedicated SCC group."
fi
if ! getent passwd "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_GROUP}" --home-dir "${STATE_DIR}" --no-create-home --shell /usr/bin/nologin "${SERVICE_USER}" || fail "Could not create the dedicated SCC service account."
fi
SCC_UID="$(id -u "${SERVICE_USER}")"
SCC_GID="$(id -g "${SERVICE_USER}")"
[[ "${SCC_UID}" -ne 0 ]] || fail "The dedicated SCC account must not have UID 0."
service_group="$(id -gn "${SERVICE_USER}")"
[[ "${service_group}" == "${SERVICE_GROUP}" ]] || fail "The scc account must use the dedicated scc primary group."
service_shell="$(getent passwd "${SERVICE_USER}" | cut -d: -f7)"
[[ "${service_shell}" == "/usr/bin/nologin" || "${service_shell}" == "/sbin/nologin" ]] || fail "The scc account must have a non-login shell (found: ${service_shell})."

if ! docker info >/dev/null 2>&1; then
  if ! systemctl enable --now docker.service; then
    fail "Docker is installed but its system service could not be started. Check: sudo systemctl status docker.service"
  fi
fi
docker info >/dev/null 2>&1 || fail "Docker Engine is not responding. Check: sudo systemctl status docker.service"

if [[ -L "${INSTALL_DIR}" || ( -e "${INSTALL_DIR}" && ! -d "${INSTALL_DIR}" ) ]]; then
  fail "${INSTALL_DIR} is not a normal directory; refusing to replace it."
fi
if [[ -d "${INSTALL_DIR}" && ! -d "${INSTALL_DIR}/.git" \
  && ! -f "${INSTALL_DIR}/.env" && ! -f "${INSTALL_DIR}/docker-compose.yml" \
  && ! -f "${INSTALL_DIR}/management/scc" ]]; then
  fail "${INSTALL_DIR} exists but does not look like an SCC installation; refusing to overwrite it."
fi

installer_tmp="$(mktemp -d)"
previous_git="${installer_tmp}/previous.git"
git_backup_active=0
cleanup_installer() {
  if [[ "${git_backup_active}" -eq 1 && -e "${previous_git}" && ! -e "${INSTALL_DIR}/.git" ]]; then
    mv "${previous_git}" "${INSTALL_DIR}/.git" || log "WARNING: could not restore the previous Git metadata at ${INSTALL_DIR}/.git."
  fi
  rm -rf -- "${installer_tmp}"
}
trap cleanup_installer EXIT

source_dir="${installer_tmp}/source"
log "Downloading a clean SCC source checkout from GitHub."
git clone --depth 1 "${REPOSITORY_URL}" "${source_dir}" || fail "Could not clone ${REPOSITORY_URL}."

[[ -f "${source_dir}/docker-compose.yml" ]] || fail "The downloaded repository is missing docker-compose.yml."
[[ -f "${source_dir}/backend/Dockerfile" ]] || fail "The downloaded repository is missing the backend image definition."
[[ -f "${source_dir}/backend/app/main.py" ]] || fail "The downloaded repository is missing the SCC application."
[[ -f "${source_dir}/management/scc" ]] || fail "The downloaded repository is missing the SCC management command."
[[ -f "${source_dir}/management/scc-manager-helper" ]] || fail "The downloaded repository is missing the restricted SCC management helper."
app_version="$(sed -n 's/^APP_VERSION = "\([^"]*\)"/\1/p' "${source_dir}/backend/app/main.py")"
compose_version="$(sed -n 's/^[[:space:]]*image: scc-server-control-center:\([^[:space:]]*\)$/\1/p' "${source_dir}/docker-compose.yml")"
[[ -n "${app_version}" && "${app_version}" == "${compose_version}" ]] || fail "The downloaded application and Compose versions do not match."

[[ -d "${INSTALL_DIR}" ]] || install -d -m 0755 "${INSTALL_DIR}"
env_file="${INSTALL_DIR}/.env"
legacy_env_file="${LEGACY_INSTALL_DIR}/.env"
if [[ -L "${env_file}" ]]; then
  fail "${env_file} is a symbolic link; refusing to overwrite or follow it."
fi
if [[ ! -e "${env_file}" && -f "${legacy_env_file}" ]]; then
  [[ ! -L "${legacy_env_file}" ]] || fail "${legacy_env_file} is a symbolic link; refusing to follow it."
  install -m 0600 "${legacy_env_file}" "${env_file}"
  chmod 0600 "${legacy_env_file}"
  log "Preserved configuration from the legacy ${LEGACY_INSTALL_DIR} installation."
fi
if [[ -e "${env_file}" && ! -f "${env_file}" ]]; then
  fail "${env_file} is not a regular file; refusing to overwrite it."
fi

if [[ -d "${INSTALL_DIR}/.git" || -f "${INSTALL_DIR}/.git" || -L "${INSTALL_DIR}/.git" ]]; then
  mv "${INSTALL_DIR}/.git" "${previous_git}" || fail "Could not safely replace the existing Git metadata."
  git_backup_active=1
fi

log "Refreshing SCC application files; existing environment and persistent data are preserved."
git -C "${source_dir}" ls-files -z | tar -C "${source_dir}" --null -T - -cf - \
  | tar -C "${INSTALL_DIR}" -xf - || fail "Could not refresh the SCC application files."; sed -i 's/[[:cntrl:]]$//' "${INSTALL_DIR}/management/scc" || fail "Could not normalize the SCC management command line endings."
mv "${source_dir}/.git" "${INSTALL_DIR}/.git" || fail "Could not install the clean SCC Git metadata."
chmod 0755 "${INSTALL_DIR}/management/scc" || fail "Could not make the SCC management command executable."
git_backup_active=0

[[ -f "${INSTALL_DIR}/docker-compose.yml" ]] || fail "The repaired installation is missing docker-compose.yml."
[[ -f "${INSTALL_DIR}/backend/Dockerfile" ]] || fail "The repaired installation is missing the backend image definition."
[[ -f "${INSTALL_DIR}/backend/app/main.py" ]] || fail "The repaired installation is missing the SCC application."
[[ -x "${INSTALL_DIR}/management/scc" ]] || fail "The repaired management command is not executable."
[[ -f "${INSTALL_DIR}/management/scc-manager-helper" ]] || fail "The repaired installation is missing the restricted management helper."
chmod 0755 "${INSTALL_DIR}/management/scc-manager-helper"
app_version="$(sed -n 's/^APP_VERSION = "\([^"]*\)"/\1/p' "${INSTALL_DIR}/backend/app/main.py")"
compose_version="$(sed -n 's/^[[:space:]]*image: scc-server-control-center:\([^[:space:]]*\)$/\1/p' "${INSTALL_DIR}/docker-compose.yml")"
[[ -n "${app_version}" && "${app_version}" == "${compose_version}" ]] || fail "The repaired application and Compose versions do not match."
bash -n "${INSTALL_DIR}/install-scc.sh" || fail "The repaired installer failed Bash syntax validation."
bash -n "${INSTALL_DIR}/management/scc" || fail "The repaired management command failed Bash syntax validation."
bash -n "${INSTALL_DIR}/management/scc-manager-helper" || fail "The restricted management helper failed Bash syntax validation."

host_root="${DEFAULT_FILES_DIR}"
if [[ -f "${env_file}" ]]; then
  configured_root="$(sed -n 's/^SCC_HOST_ROOT=//p' "${env_file}" | tail -n 1)"
  [[ -n "${configured_root}" ]] && host_root="${configured_root}"
else
  if [[ ! -d "${host_root}" ]]; then
    install -d -o "${SCC_UID}" -g "${SCC_GID}" -m 0750 "${host_root}"
  fi
  setup_token="$(openssl rand -hex 32)"
  cat >"${env_file}" <<EOF
SCC_UID=${SCC_UID}
SCC_GID=${SCC_GID}
SCC_HOST_ROOT=${host_root}
SCC_DATA_PATH=${DATA_DIR}
SCC_BIND_ADDRESS=127.0.0.1
SCC_PORT=8787
SCC_COOKIE_SECURE=true
SCC_SETUP_TOKEN=${setup_token}
SCC_MAX_UPLOAD_BYTES=52428800
SCC_MAX_STORAGE_BYTES=10737418240
SCC_MAX_ENTRIES=100000
SCC_TRUSTED_PROXY_CIDRS=172.16.0.0/12,127.0.0.1/32,::1/128
EOF
  chmod 0600 "${env_file}"
fi

[[ "${host_root}" == /* && "${host_root}" != "/" ]] || fail "SCC_HOST_ROOT must be an existing absolute directory other than /."
[[ "${host_root}" != *:* && "${host_root}" != *$'\n'* ]] || fail "SCC_HOST_ROOT contains characters unsupported by Docker Compose bind mounts."
[[ "${host_root}" != *'"'* && "${host_root}" != *'$'* && "${host_root}" != *'\'* ]] || fail "SCC_HOST_ROOT contains characters unsupported by the Compose environment file."
[[ -d "${host_root}" ]] || fail "Configured SCC_HOST_ROOT does not exist: ${host_root}. Create it or correct ${env_file}."
resolved_root="$(realpath -e "${host_root}")"
[[ "${resolved_root}" != "/" ]] || fail "SCC_HOST_ROOT must not resolve to /."
case "${resolved_root}" in
  /srv|/home|/var|/etc|/opt|/root|/usr|/tmp|/run)
    fail "Resolved SCC_HOST_ROOT=${resolved_root} is a broad system directory; use a dedicated subdirectory."
    ;;
esac
for protected_path in "${STATE_DIR}" "${INSTALL_DIR}" "${LEGACY_INSTALL_DIR}"; do
  protected_resolved="$(realpath -m "${protected_path}")"
  if [[ "${resolved_root}" == "${protected_resolved}" || "${resolved_root}" == "${protected_resolved}/"* || "${protected_resolved}" == "${resolved_root}/"* ]]; then
    fail "SCC_HOST_ROOT overlaps SCC's private application/state path ${protected_resolved}; choose a separate dedicated storage directory."
  fi
done

if [[ "${resolved_root}" != "${host_root}" ]]; then
  escaped_root="$(printf '%s' "${resolved_root}" | sed 's/[&|]/\\&/g')"
  sed -i "s|^SCC_HOST_ROOT=.*|SCC_HOST_ROOT=${escaped_root}|" "${env_file}"
  host_root="${resolved_root}"
fi

ensure_env_default() {
  local key="$1"
  local value="$2"
  if ! grep -q "^${key}=" "${env_file}"; then
    printf '%s=%s\n' "${key}" "${value}" >>"${env_file}"
  fi
}

ensure_env_default SCC_SETUP_TOKEN "$(openssl rand -hex 32)"
ensure_env_default SCC_UID "${SCC_UID}"
ensure_env_default SCC_GID "${SCC_GID}"
ensure_env_default SCC_DATA_PATH "${DATA_DIR}"
ensure_env_default SCC_BIND_ADDRESS "127.0.0.1"
ensure_env_default SCC_PORT "8787"
ensure_env_default SCC_COOKIE_SECURE "true"
ensure_env_default SCC_MAX_UPLOAD_BYTES "52428800"
ensure_env_default SCC_MAX_STORAGE_BYTES "10737418240"
ensure_env_default SCC_MAX_ENTRIES "100000"
ensure_env_default SCC_TRUSTED_PROXY_CIDRS "172.16.0.0/12,127.0.0.1/32,::1/128"

set_env_value() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "${env_file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${env_file}"
  else
    printf '%s=%s\n' "${key}" "${value}" >>"${env_file}"
  fi
}
# Migrate the previous shipped 1 GiB default to the safer 50 MiB default;
# preserve values that an administrator explicitly customized.
if grep -qx 'SCC_MAX_UPLOAD_BYTES=1073741824' "${env_file}"; then
  set_env_value SCC_MAX_UPLOAD_BYTES "52428800"
fi
data_path="$(sed -n 's/^SCC_DATA_PATH=//p' "${env_file}" | tail -n 1)"
[[ -n "${data_path}" && "${data_path}" == /* ]] || fail "SCC_DATA_PATH must be an absolute path."
[[ "${data_path}" != *:* && "${data_path}" != *$'\n'* && "${data_path}" != *'"'* && "${data_path}" != *'$'* && "${data_path}" != *'\'* ]] || fail "SCC_DATA_PATH contains characters unsupported by Docker Compose."
[[ ! -L "${data_path}" ]] || fail "SCC_DATA_PATH must not be a symbolic link."
resolved_data_path="$(realpath -m "${data_path}")"
resolved_state_dir="$(realpath -m "${STATE_DIR}")"
[[ "${resolved_data_path}" == "${resolved_state_dir}/"* ]] || fail "SCC_DATA_PATH must remain inside ${STATE_DIR}."

# Never mount a broad system directory into the application. The dedicated
# service account must own and be able to access only this storage boundary.
case "${host_root}" in
  /|/srv|/home|/var|/etc|/opt|/root|/usr|/tmp|/run)
    fail "SCC_HOST_ROOT=${host_root} is too broad. Move only SCC-managed files into ${DEFAULT_FILES_DIR}, set SCC_HOST_ROOT to that dedicated directory in ${env_file}, and rerun the installer."
    ;;
esac
if [[ ! -d "${host_root}" ]]; then
  install -d -o "${SCC_UID}" -g "${SCC_GID}" -m 0750 "${host_root}"
fi
root_owner="$(stat -c '%u' "${host_root}")"
[[ "${root_owner}" == "${SCC_UID}" ]] || fail "${host_root} must be owned by the dedicated scc account (UID ${SCC_UID}). Review and migrate only SCC-managed files, then set ownership of this dedicated directory; do not recursively chown unrelated data."
if ! runuser -u "${SERVICE_USER}" -- test -r "${host_root}" -a -w "${host_root}" -a -x "${host_root}"; then
  fail "The dedicated scc account cannot read/write ${host_root}. Review permissions of this directory and its intended contents."
fi
[[ ! -L "${STATE_DIR}" ]] || fail "${STATE_DIR} must not be a symbolic link."
[[ ! -L "${DATA_DIR}" ]] || fail "${DATA_DIR} must not be a symbolic link."
install -d -o "${SCC_UID}" -g "${SCC_GID}" -m 0700 "${STATE_DIR}" "${resolved_data_path}"
chown -R --no-dereference "${SCC_UID}:${SCC_GID}" "${STATE_DIR}"
chmod 0700 "${STATE_DIR}" "${resolved_data_path}"
set_env_value SCC_UID "${SCC_UID}"
set_env_value SCC_GID "${SCC_GID}"
set_env_value SCC_DATA_PATH "${resolved_data_path}"
chmod 0600 "${env_file}"
install -d -m 0755 /usr/local/bin
cat >"${WRAPPER}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID}" -eq 0 ]]; then
  exec /usr/bin/bash /opt/server-control-center/management/scc "$@"
fi
if ! command -v sudo >/dev/null 2>&1; then
  printf 'scc: sudo is required for the restricted host management helper.\n' >&2
  exit 1
fi
exec sudo -n /usr/local/libexec/scc-manager "$@"
EOF
chmod 0755 "${WRAPPER}"

# Grant the installing account passwordless access to exactly one root-owned
# dispatcher. The dispatcher has a strict command/argument allowlist and never
# executes user-provided shell text. Docker access is not granted to the user
# or to the application container.
install -d -m 0755 /usr/local/libexec /etc/sudoers.d
install -o root -g root -m 0755 "${INSTALL_DIR}/management/scc-manager-helper" "${PRIVILEGED_HELPER}"
manager_user="$(getent passwd "${SUDO_UID}" | cut -d: -f1)"
[[ -n "${manager_user}" && "${manager_user}" =~ ^[A-Za-z_][A-Za-z0-9_-]*[$]?$ ]] || fail "Could not safely determine the account for the restricted SCC management permission."
sudoers_tmp="$(mktemp /etc/sudoers.d/.scc-manager.XXXXXX)"
printf '%s ALL=(root) NOPASSWD: %s\n' "${manager_user}" "${PRIVILEGED_HELPER}" >"${sudoers_tmp}"
chmod 0440 "${sudoers_tmp}"
visudo -cf "${sudoers_tmp}" >/dev/null || { rm -f "${sudoers_tmp}"; fail "The restricted SCC sudoers rule did not pass validation."; }
install -o root -g root -m 0440 "${sudoers_tmp}" "${SUDOERS_FILE}"
rm -f "${sudoers_tmp}"
visudo -cf /etc/sudoers >/dev/null || fail "The system sudoers configuration failed validation after installing the SCC rule."

legacy_management="${LEGACY_INSTALL_DIR}/management/scc"
if [[ -f "${legacy_management}" ]] \
  && grep -Eq 'server-control-center|management/scc' "${legacy_management}"; then
  cat >"${installer_tmp}/legacy-scc" <<'EOF'
#!/usr/bin/env bash
exec bash /opt/server-control-center/management/scc "$@"
EOF
  chmod 0755 "${installer_tmp}/legacy-scc"
  mv -f -- "${installer_tmp}/legacy-scc" "${legacy_management}"
  log "Repaired the legacy management command at ${legacy_management}."
fi

for command_path in /usr/bin/scc /bin/scc; do
  if [[ -f "${command_path}" && ! -L "${command_path}" ]] \
    && grep -Eq '/etc/server-control-center/management/scc|/opt/server-control-center/management/scc' "${command_path}"; then
    install -m 0755 "${WRAPPER}" "${command_path}"
    log "Repaired the existing SCC launcher at ${command_path}."
  fi
done

log "Building SCC ${app_version} and applying any persistent-data migrations."
docker compose --project-name scc --project-directory "${INSTALL_DIR}" --env-file "${env_file}" -f "${INSTALL_DIR}/docker-compose.yml" up --build --detach --force-recreate

health_url="http://127.0.0.1:$(sed -n 's/^SCC_PORT=//p' "${env_file}" | tail -n 1)/api/health"
ready=0
reported_version=""
for _ in $(seq 1 60); do
  if health_response="$(curl --silent --show-error --fail "${health_url}" 2>/dev/null)"; then
    reported_version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"${health_response}")"
    if [[ "${reported_version}" == "${app_version}" ]]; then
      ready=1
      break
    fi
  fi
  sleep 2
done
if [[ "${ready}" -ne 1 ]]; then
  docker compose --project-name scc --project-directory "${INSTALL_DIR}" --env-file "${env_file}" -f "${INSTALL_DIR}/docker-compose.yml" logs --tail 80 >&2
  fail "SCC did not report expected version ${app_version} (reported: ${reported_version:-unavailable}). Check: scc logs"
fi

log "SCC ${reported_version} is healthy; existing account and audit data were retained."
log "Open http://127.0.0.1:8787 on the server, or run: ngrok http 8787"
log "Retrieve the one-time owner setup token securely with: scc setup-token"
log "Management (no sudo required): scc start|stop|restart|update|logs|status|storage-status|storage-reconcile|uninstall"
log "SCC can access only ${host_root}; Linux filesystem permissions still apply."
