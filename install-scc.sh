#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY_URL="https://github.com/serverdesail-cmyk/server-control-center.git"
readonly INSTALL_DIR="/opt/server-control-center"
readonly LEGACY_INSTALL_DIR="/etc/server-control-center"
readonly STATE_DIR="/var/lib/server-control-center"
readonly DATA_DIR="${STATE_DIR}/data"
readonly WRAPPER="/usr/local/bin/scc"

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
SCC_UID="${SUDO_UID}"
SCC_GID="${SUDO_GID:-$(id -g "$(getent passwd "${SCC_UID}" | cut -d: -f1)")}"

packages=()
command -v docker >/dev/null 2>&1 || packages+=(docker)
docker compose version >/dev/null 2>&1 || packages+=(docker-compose)
command -v git >/dev/null 2>&1 || packages+=(git)
command -v curl >/dev/null 2>&1 || packages+=(curl)
command -v openssl >/dev/null 2>&1 || packages+=(openssl)
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
app_version="$(sed -n 's/^APP_VERSION = "\([^"]*\)"/\1/p' "${INSTALL_DIR}/backend/app/main.py")"
compose_version="$(sed -n 's/^[[:space:]]*image: scc-server-control-center:\([^[:space:]]*\)$/\1/p' "${INSTALL_DIR}/docker-compose.yml")"
[[ -n "${app_version}" && "${app_version}" == "${compose_version}" ]] || fail "The repaired application and Compose versions do not match."
bash -n "${INSTALL_DIR}/install-scc.sh" || fail "The repaired installer failed Bash syntax validation."
bash -n "${INSTALL_DIR}/management/scc" || fail "The repaired management command failed Bash syntax validation."

host_root="/srv"
if [[ -f "${env_file}" ]]; then
  configured_root="$(sed -n 's/^SCC_HOST_ROOT=//p' "${env_file}" | tail -n 1)"
  [[ -n "${configured_root}" ]] && host_root="${configured_root}"
else
  if [[ ! -d "${host_root}" ]]; then
    install -d -m 0755 "${host_root}"
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
SCC_MAX_UPLOAD_BYTES=1073741824
EOF
  chmod 0600 "${env_file}"
fi

[[ "${host_root}" == /* && "${host_root}" != "/" ]] || fail "SCC_HOST_ROOT must be an existing absolute directory other than /."
[[ "${host_root}" != *:* && "${host_root}" != *$'\n'* ]] || fail "SCC_HOST_ROOT contains characters unsupported by Docker Compose bind mounts."
[[ "${host_root}" != *'"'* && "${host_root}" != *'$'* && "${host_root}" != *'\'* ]] || fail "SCC_HOST_ROOT contains characters unsupported by the Compose environment file."
[[ -d "${host_root}" ]] || fail "Configured SCC_HOST_ROOT does not exist: ${host_root}. Create it or correct ${env_file}."
resolved_root="$(realpath -e "${host_root}")"
[[ "${resolved_root}" != "/" ]] || fail "SCC_HOST_ROOT must not resolve to /."

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
ensure_env_default SCC_MAX_UPLOAD_BYTES "1073741824"
chmod 0600 "${env_file}"

install -d -o "${SCC_UID}" -g "${SCC_GID}" -m 0700 "${STATE_DIR}" "${DATA_DIR}"
install -d -m 0755 /usr/local/bin
cat >"${WRAPPER}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID}" -eq 0 ]]; then
  exec bash /opt/server-control-center/management/scc "$@"
fi
exec sudo bash /opt/server-control-center/management/scc "$@"
EOF
chmod 0755 "${WRAPPER}"

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
  fail "SCC did not report expected version ${app_version} (reported: ${reported_version:-unavailable}). Check: sudo scc logs"
fi

log "SCC ${reported_version} is healthy; existing account and audit data were retained."
log "Open http://127.0.0.1:8787 on the server, or run: ngrok http 8787"
log "Retrieve the one-time owner setup token securely with: sudo scc setup-token"
log "Management: scc start|stop|restart|update|logs|status|uninstall"
log "SCC can access only ${host_root}; Linux filesystem permissions still apply."
