import ctypes
import base64
import binascii
import errno
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Iterator
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pwdlib import PasswordHash

APP_VERSION = "0.4.0"
SESSION_SECONDS = 12 * 60 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 8
TEXT_FILE_LIMIT = 1024 * 1024
UPLOAD_LIMIT = 1024 * 1024 * 1024
UPLOAD_CHUNK_SIZE = 1024 * 1024
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
PERMISSIONS = {
    "browse",
    "read",
    "download",
    "upload",
    "create",
    "edit",
    "rename",
    "delete",
}
DEFAULT_DASHBOARD_PREFERENCES = {
    "widgets": ["stats", "activity", "filesystem", "quick-actions"],
    "quick_actions": ["files", "monitoring", "logs", "access", "settings"],
    "cpu_warning_percent": 85,
    "memory_warning_percent": 90,
    "disk_warning_percent": 90,
}
DASHBOARD_WIDGETS = {"stats", "activity", "filesystem", "quick-actions"}
DASHBOARD_ACTIONS = {"files", "monitoring", "logs", "access", "settings"}
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
password_hash = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hash.hash("scc-dummy-password-for-timing")


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    filesystem_root: Path
    setup_token: str
    cookie_secure: bool = True
    max_upload_bytes: int = UPLOAD_LIMIT
    host_proc_dir: Path = Path("/host/proc")

    @classmethod
    def from_env(cls) -> "Settings":
        try:
            max_upload = int(os.getenv("SCC_MAX_UPLOAD_BYTES", str(UPLOAD_LIMIT)))
        except ValueError as exc:
            raise RuntimeError("SCC_MAX_UPLOAD_BYTES must be an integer") from exc
        if max_upload < 1:
            raise RuntimeError("SCC_MAX_UPLOAD_BYTES must be positive")
        secure = os.getenv("SCC_COOKIE_SECURE", "true").strip().lower()
        if secure not in {"true", "false"}:
            raise RuntimeError("SCC_COOKIE_SECURE must be true or false")
        return cls(
            data_dir=Path(os.getenv("SCC_DATA_DIR", "/data")),
            filesystem_root=Path(os.getenv("SCC_FILESYSTEM_ROOT", "/srv")),
            setup_token=os.getenv("SCC_SETUP_TOKEN", ""),
            cookie_secure=secure == "true",
            max_upload_bytes=max_upload,
        )

    @property
    def database_path(self) -> Path:
        return self.data_dir / "scc.sqlite3"


class SetupBody(BaseModel):
    setup_token: str = Field(min_length=24, max_length=256)
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class UserBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(pattern="^(admin|user)$")


class UserActiveBody(BaseModel):
    active: bool


class PasswordBody(BaseModel):
    password: str = Field(min_length=12, max_length=128)


class GrantBody(BaseModel):
    user_id: int = Field(gt=0)
    path: str = Field(max_length=4096)
    permissions: list[str] = Field(max_length=len(PERMISSIONS))
    inherit: bool = True


class FilesystemRootBody(BaseModel):
    path: str = Field(min_length=1, max_length=4096)

class ProfileBody(BaseModel):
    avatar: str | None = Field(default=None, max_length=180_000)


class DashboardPreferencesBody(BaseModel):
    widgets: list[str] = Field(max_length=len(DASHBOARD_WIDGETS))
    quick_actions: list[str] = Field(max_length=len(DASHBOARD_ACTIONS))
    cpu_warning_percent: int = Field(ge=50, le=99)
    memory_warning_percent: int = Field(ge=50, le=99)
    disk_warning_percent: int = Field(ge=50, le=99)


class CreateBody(BaseModel):
    path: str = Field(max_length=4096)
    name: str = Field(min_length=1, max_length=255)


class WriteBody(BaseModel):
    path: str = Field(max_length=4096)
    content: str = Field(max_length=TEXT_FILE_LIMIT)


class RenameBody(BaseModel):
    path: str = Field(max_length=4096)
    name: str = Field(min_length=1, max_length=255)


class DeleteBody(BaseModel):
    path: str = Field(max_length=4096)


class Audit:
    def __init__(self, database_path: Path):
        self.database_path = database_path

    def write(
        self,
        user_id: int | None,
        action: str,
        path: str | None = None,
        detail: str | None = None,
    ) -> None:
        with closing(connect(self.database_path)) as db:
            db.execute(
                "INSERT INTO audit (user_id, action, path, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, path, detail, now()),
            )
            db.commit()


def now() -> int:
    return int(time.time())


def connect(database_path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(database_path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize(settings: Settings) -> None:
    settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(settings.data_dir, 0o700)
    if not settings.filesystem_root.is_dir():
        raise RuntimeError(f"Filesystem root does not exist: {settings.filesystem_root}")
    base_root = settings.filesystem_root.resolve(strict=True)
    if base_root == Path("/"):
        raise RuntimeError("The configured filesystem mount cannot be /")
    with closing(connect(settings.database_path)) as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'user')),
                active INTEGER NOT NULL DEFAULT 1,
                avatar TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_scc_owner
                ON users(role) WHERE role = 'owner';
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_hash TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
            CREATE TABLE IF NOT EXISTS grants (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                permissions TEXT NOT NULL,
                inherit INTEGER NOT NULL DEFAULT 1,
                UNIQUE(user_id, path)
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                remote_host TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS login_attempt_lookup
                ON login_attempts(username, remote_host, attempted_at);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                path TEXT,
                detail TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_created_at ON audit(created_at);
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        db.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('dashboard_preferences', ?)",
            (json.dumps(DEFAULT_DASHBOARD_PREFERENCES, separators=(",", ":")),),
        )
        user_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()
        }
        if "avatar" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
        db.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('active_filesystem_root', ?)",
            (str(base_root),),
        )
        configured_root = db.execute(
            "SELECT value FROM app_settings WHERE key = 'active_filesystem_root'"
        ).fetchone()["value"]
        try:
            active_root = Path(configured_root).resolve(strict=True)
            valid_root = active_root.is_dir() and active_root.is_relative_to(base_root)
        except (OSError, RuntimeError):
            valid_root = False
            active_root = base_root
        if not valid_root:
            db.execute("DELETE FROM grants")
            db.execute(
                "UPDATE app_settings SET value = ? WHERE key = 'active_filesystem_root'",
                (str(base_root),),
            )
            db.execute(
                "INSERT INTO audit (user_id, action, path, detail, created_at) "
                "VALUES (NULL, 'filesystem_root_reset', ?, ?, ?)",
                (str(base_root), str(configured_root), now()),
            )
        db.commit()
    if os.name == "posix":
        os.chmod(settings.database_path, 0o600)


def active_filesystem_root(settings: Settings) -> Path:
        with closing(connect(settings.database_path)) as db:
            row = db.execute(
                "SELECT value FROM app_settings WHERE key = 'active_filesystem_root'"
            ).fetchone()
        if row is None:
            raise RuntimeError("Active filesystem root setting is missing")
        root = Path(row["value"])
        try:
            resolved_root = root.resolve(strict=True)
            base_root = settings.filesystem_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise HTTPException(status_code=503, detail="Configured filesystem root is unavailable") from exc
        if not resolved_root.is_dir() or not resolved_root.is_relative_to(base_root):
            raise HTTPException(status_code=503, detail="Configured filesystem root is outside its mounted boundary")
        return resolved_root


def resolve_managed_directory(settings: Settings, requested_path: str) -> tuple[Path, tuple[str, ...]]:
        if (
            not requested_path.startswith("/")
            or "\x00" in requested_path
            or "\\" in requested_path
            or ".." in requested_path.split("/")
        ):
            raise HTTPException(status_code=400, detail="Choose an absolute directory without traversal components")
        base_root = settings.filesystem_root.resolve(strict=True)
        try:
            resolved_path = Path(requested_path).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise HTTPException(status_code=404, detail="Directory not found") from exc
        if not resolved_path.is_dir():
            raise HTTPException(status_code=400, detail="The selected path is not a directory")
        try:
            relative = resolved_path.relative_to(base_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Directory is outside the configured host mount") from exc
        return resolved_path, relative.parts


def host_metrics(
    settings: Settings,
    previous_sample: tuple[int, int, float] | None,
) -> tuple[dict[str, Any], tuple[int, int, float]]:
        try:
            cpu_line = (settings.host_proc_dir / "stat").read_text(encoding="ascii").splitlines()[0].split()
            if cpu_line[0] != "cpu" or len(cpu_line) < 5:
                raise ValueError("Host CPU counters are unavailable")
            counters = [int(value) for value in cpu_line[1:]]
            total_ticks = sum(counters[:8])
            idle_ticks = counters[3] + (counters[4] if len(counters) > 4 else 0)

            memory = {}
            for line in (settings.host_proc_dir / "meminfo").read_text(encoding="ascii").splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    memory[key] = int(value.strip().split()[0]) * 1024
            total_memory = memory["MemTotal"]
            available_memory = memory["MemAvailable"]
            if total_memory <= 0 or not 0 <= available_memory <= total_memory:
                raise ValueError("Host memory counters are invalid")

            uptime_seconds = float((settings.host_proc_dir / "uptime").read_text(encoding="ascii").split()[0])
            load_average = [
                float(value)
                for value in (settings.host_proc_dir / "loadavg").read_text(encoding="ascii").split()[:3]
            ]
            if len(load_average) != 3:
                raise ValueError("Host load average is unavailable")

            received_bytes = 0
            transmitted_bytes = 0
            network_lines = (settings.host_proc_dir / "net" / "dev").read_text(encoding="ascii").splitlines()[2:]
            for line in network_lines:
                interface, separator, counters_text = line.partition(":")
                if not separator or interface.strip() == "lo":
                    continue
                values = counters_text.split()
                if len(values) < 9:
                    raise ValueError("Host network counters are invalid")
                received_bytes += int(values[0])
                transmitted_bytes += int(values[8])
        except (OSError, IndexError, KeyError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="Host telemetry is unavailable or invalid") from exc

        sampled_at = time.monotonic()
        cpu_percent = None
        if previous_sample is not None:
            previous_total, previous_idle, previous_at = previous_sample
            total_delta = total_ticks - previous_total
            idle_delta = idle_ticks - previous_idle
            if total_delta > 0 and 0 <= idle_delta <= total_delta:
                cpu_percent = round((total_delta - idle_delta) * 100 / total_delta, 1)

        sample = (total_ticks, idle_ticks, sampled_at)
        return (
            {
                "cpu_percent": cpu_percent,
                "memory": {
                    "total": total_memory,
                    "used": total_memory - available_memory,
                    "available": available_memory,
                },
                "uptime_seconds": int(uptime_seconds),
                "load_average": load_average,
                "network": {
                    "received_bytes": received_bytes,
                    "transmitted_bytes": transmitted_bytes,
                },
                "sampled_at": time.time(),
            },
            sample,
        )


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_parts(path: str) -> tuple[str, ...]:
    if "\x00" in path or "\\" in path or len(path) > 4096:
        raise HTTPException(status_code=400, detail="Invalid path")
    parts = tuple(part for part in path.split("/") if part not in {"", "."})
    if any(part == ".." for part in parts):
        raise HTTPException(status_code=400, detail="Path traversal is not allowed")
    if any(len(part.encode("utf-8")) > 255 for part in parts):
        raise HTTPException(status_code=400, detail="Path component is too long")
    return parts


def virtual_path(parts: tuple[str, ...]) -> str:
    return "/" + "/".join(parts)


def open_root(root: Path) -> int:
    if os.name != "posix" or not hasattr(os, "supports_dir_fd") or os.open not in os.supports_dir_fd:
        raise HTTPException(status_code=501, detail="Secure filesystem access requires Linux")
    try:
        return os.open(root, os.O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Filesystem root is unavailable") from exc


def open_directory(root: Path, parts: tuple[str, ...]) -> int:
    fd = open_root(root)
    try:
        for part in parts:
            child = os.open(
                part,
                os.O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
        return fd
    except FileNotFoundError as exc:
        os.close(fd)
        raise HTTPException(status_code=404, detail="Folder not found") from exc
    except NotADirectoryError as exc:
        os.close(fd)
        raise HTTPException(status_code=400, detail="Path is not a folder") from exc
    except PermissionError as exc:
        os.close(fd)
        raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
    except OSError as exc:
        os.close(fd)
        if exc.errno == errno.ELOOP:
            raise HTTPException(status_code=403, detail="Symbolic links are not followed") from exc
        raise HTTPException(status_code=400, detail="Invalid filesystem path") from exc


def open_parent(root: Path, parts: tuple[str, ...]) -> tuple[int, str]:
    if not parts:
        raise HTTPException(status_code=400, detail="The filesystem root cannot be changed")
    return open_directory(root, parts[:-1]), parts[-1]


def check_filename(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or len(name.encode("utf-8")) > 255
    ):
        raise HTTPException(status_code=400, detail="Invalid filename")


def get_permissions(db: sqlite3.Connection, user: sqlite3.Row, target: str) -> set[str]:
    if user["role"] == "owner":
        return set(PERMISSIONS)
    parts = canonical_parts(target)
    candidates: list[tuple[int, set[str]]] = []
    for grant in db.execute(
        "SELECT path, permissions, inherit FROM grants WHERE user_id = ?", (user["id"],)
    ):
        grant_parts = canonical_parts(grant["path"])
        if grant_parts == parts or (
            grant["inherit"] and len(grant_parts) < len(parts) and parts[: len(grant_parts)] == grant_parts
        ):
            try:
                grants = set(json.loads(grant["permissions"]))
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=500, detail="Invalid stored folder permissions") from exc
            candidates.append((len(grant_parts), grants))
    if not candidates:
        return set()
    return max(candidates, key=lambda candidate: candidate[0])[1]


def require_permission(
    db: sqlite3.Connection, user: sqlite3.Row, path: str, permission: str
) -> None:
    if permission not in get_permissions(db, user, path):
        raise HTTPException(status_code=403, detail="Folder permission denied")


def audit_event(
    settings: Settings,
    user: sqlite3.Row | None,
    action: str,
    path: str | None = None,
    detail: str | None = None,
) -> None:
    Audit(settings.database_path).write(
        user["id"] if user is not None else None, action, path, detail
    )


def request_origin_matches(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return False
    try:
        parsed = urlsplit(origin)
        host = parsed.netloc.lower()
        request_host = request.headers.get("host", "").lower()
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(host) and hmac.compare_digest(host, request_host)


def authenticate_request(request: Request, settings: Settings) -> sqlite3.Row:
    token = request.cookies.get("scc_session", "")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    with closing(connect(settings.database_path)) as db:
        session = db.execute(
            """
            SELECT s.token_hash, s.csrf_hash, s.expires_at, u.id, u.username, u.role, u.active
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            """,
            (digest(token), now()),
        ).fetchone()
        if session is None or not session["active"]:
            raise HTTPException(status_code=401, detail="Session expired or revoked")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf_cookie = request.cookies.get("scc_csrf", "")
            csrf_header = request.headers.get("x-csrf-token", "")
            if (
                not request_origin_matches(request)
                or not csrf_cookie
                or not csrf_header
                or not hmac.compare_digest(csrf_cookie, csrf_header)
                or not hmac.compare_digest(digest(csrf_cookie), session["csrf_hash"])
            ):
                raise HTTPException(status_code=403, detail="CSRF validation failed")
        return session


def require_owner(user: sqlite3.Row) -> None:
    if user["role"] != "owner":
        raise HTTPException(status_code=403, detail="Owner access required")


def valid_dashboard_preferences(preferences: dict[str, Any]) -> bool:
    widgets = preferences.get("widgets")
    actions = preferences.get("quick_actions")
    return (
        isinstance(widgets, list)
        and len(widgets) == len(set(widgets))
        and set(widgets) <= DASHBOARD_WIDGETS
        and isinstance(actions, list)
        and len(actions) == len(set(actions))
        and set(actions) <= DASHBOARD_ACTIONS
    )


def read_dashboard_preferences(settings: Settings) -> dict[str, Any]:
    with closing(connect(settings.database_path)) as db:
        row = db.execute(
            "SELECT value FROM app_settings WHERE key = 'dashboard_preferences'"
        ).fetchone()
    if row is None:
        return dict(DEFAULT_DASHBOARD_PREFERENCES)
    try:
        preferences = DashboardPreferencesBody.model_validate_json(row["value"]).model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Dashboard settings are invalid") from exc
    if not valid_dashboard_preferences(preferences):
        raise HTTPException(status_code=503, detail="Dashboard settings are invalid")
    return preferences


def file_metadata(name: str, entry_stat: os.stat_result) -> dict[str, Any]:
    mode = stat.S_IMODE(entry_stat.st_mode)
    return {
        "name": name,
        "kind": (
            "link"
            if stat.S_ISLNK(entry_stat.st_mode)
            else "folder"
            if stat.S_ISDIR(entry_stat.st_mode)
            else "file"
        ),
        "size": entry_stat.st_size,
        "modified": datetime.fromtimestamp(entry_stat.st_mtime, timezone.utc).isoformat(),
        "permissions": stat.filemode(entry_stat.st_mode),
        "mode": f"{mode:04o}",
        "uid": entry_stat.st_uid,
        "gid": entry_stat.st_gid,
    }


def read_chunks(fd: int, start: int, length: int) -> Iterator[bytes]:
    try:
        os.lseek(fd, start, os.SEEK_SET)
        remaining = length
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            remaining -= len(block)
            yield block
    finally:
        os.close(fd)


def rename_without_replace(src_fd: int, src: str, dst_fd: int, dst: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise HTTPException(status_code=501, detail="Safe no-replace rename is unavailable") from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        src_fd,
        os.fsencode(src),
        dst_fd,
        os.fsencode(dst),
        1,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise HTTPException(status_code=409, detail="A file with that name already exists")
    if error in {errno.EPERM, errno.EACCES}:
        raise HTTPException(status_code=403, detail="Filesystem access denied")
    if error == errno.ENOENT:
        raise HTTPException(status_code=404, detail="File not found")
    raise HTTPException(status_code=400, detail="Safe rename failed")


def range_bounds(header: str | None, size: int) -> tuple[int, int, int]:
    if size == 0:
        if header:
            raise HTTPException(status_code=416, detail="Byte range is not satisfiable")
        return 0, -1, 200
    if not header:
        return 0, size - 1, 200
    if not header.startswith("bytes=") or "," in header:
        raise HTTPException(status_code=416, detail="Invalid byte range")
    try:
        first, last = header[6:].split("-", 1)
        if first:
            start = int(first)
            end = min(int(last), size - 1) if last else size - 1
        else:
            suffix_length = int(last)
            if suffix_length <= 0:
                raise ValueError
            start = max(0, size - suffix_length)
            end = size - 1
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=416, detail="Invalid byte range") from exc
    if start < 0 or start >= size or end < start:
        raise HTTPException(status_code=416, detail="Byte range is not satisfiable")
    return start, end, 206


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        initialize(config)
        yield

    app = FastAPI(
        title="SCC - Server Control Center",
        version=APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = config
    app.state.started_at = time.time()
    app.state.host_metrics_sample = None
    app.state.host_metrics_lock = threading.Lock()
    app.mount("/assets", StaticFiles(directory=Path(__file__).parent / "static"), name="assets")

    def current_user(request: Request) -> sqlite3.Row:
        return authenticate_request(request, config)

    CurrentUser = Annotated[sqlite3.Row, Depends(current_user)]

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if config.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": APP_VERSION}

    @app.get("/api/setup/status")
    async def setup_status():
        with closing(connect(config.database_path)) as db:
            owner_exists = db.execute("SELECT 1 FROM users WHERE role = 'owner'").fetchone() is not None
        return {"owner_exists": owner_exists}

    @app.post("/api/setup")
    async def setup_owner(body: SetupBody, request: Request, response: Response):
        if not request_origin_matches(request):
            raise HTTPException(status_code=403, detail="Invalid request origin")
        if not config.setup_token or not hmac.compare_digest(body.setup_token, config.setup_token):
            audit_event(config, None, "setup_failed")
            raise HTTPException(status_code=403, detail="Invalid setup token")
        username = body.username.strip()
        if not USERNAME_PATTERN.fullmatch(username):
            raise HTTPException(status_code=422, detail="Username must be 3-32 safe characters")
        with closing(connect(config.database_path)) as db:
            if db.execute("SELECT 1 FROM users WHERE role = 'owner'").fetchone():
                raise HTTPException(status_code=409, detail="Owner account already exists")
            cursor = db.execute(
                "INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?, ?, 'owner', 1, ?)",
                (username, password_hash.hash(body.password), now()),
            )
            user_id = cursor.lastrowid
            db.commit()
        issue_session(response, config, user_id)
        audit_event(config, {"id": user_id}, "owner_created")
        return {"id": user_id, "username": username, "role": "owner"}

    def issue_session(response: Response, cfg: Settings, user_id: int) -> None:
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        created = now()
        with closing(connect(cfg.database_path)) as db:
            db.execute(
                "INSERT INTO sessions (token_hash, csrf_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (digest(session_token), digest(csrf_token), user_id, created, created + SESSION_SECONDS),
            )
            db.commit()
        cookie_options = {
            "path": "/",
            "max_age": SESSION_SECONDS,
            "secure": cfg.cookie_secure,
            "samesite": "strict",
        }
        response.set_cookie("scc_session", session_token, httponly=True, **cookie_options)
        response.set_cookie("scc_csrf", csrf_token, httponly=False, **cookie_options)

    @app.post("/api/auth/login")
    async def login(body: LoginBody, request: Request, response: Response):
        if not request_origin_matches(request):
            raise HTTPException(status_code=403, detail="Invalid request origin")
        username = body.username.strip()
        remote_host = request.client.host if request.client else "unknown"
        current_time = now()
        with closing(connect(config.database_path)) as db:
            db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (current_time - LOGIN_WINDOW_SECONDS,))
            attempts = db.execute(
                """
                SELECT COUNT(*) AS count FROM login_attempts
                WHERE username = ? COLLATE NOCASE AND remote_host = ? AND attempted_at >= ?
                """,
                (username, remote_host, current_time - LOGIN_WINDOW_SECONDS),
            ).fetchone()["count"]
            if attempts >= LOGIN_MAX_ATTEMPTS:
                raise HTTPException(status_code=429, detail="Too many login attempts; try again later")
            user = db.execute(
                "SELECT id, username, password_hash, role, active FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
            stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
            valid = password_hash.verify(body.password, stored_hash)
            if not user or not user["active"] or not valid:
                db.execute(
                    "INSERT INTO login_attempts (username, remote_host, attempted_at) VALUES (?, ?, ?)",
                    (username, remote_host, current_time),
                )
                db.commit()
                raise HTTPException(status_code=401, detail="Invalid username or password")
            db.execute(
                "DELETE FROM login_attempts WHERE username = ? COLLATE NOCASE AND remote_host = ?",
                (username, remote_host),
            )
            db.commit()
        issue_session(response, config, user["id"])
        audit_event(config, user, "login")
        return {"id": user["id"], "username": user["username"], "role": user["role"]}

    @app.post("/api/auth/logout")
    async def logout(request: Request, response: Response, user: CurrentUser):
        token = request.cookies.get("scc_session", "")
        with closing(connect(config.database_path)) as db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (digest(token),))
            db.commit()
        response.delete_cookie("scc_session", path="/", secure=config.cookie_secure, httponly=True, samesite="strict")
        response.delete_cookie("scc_csrf", path="/", secure=config.cookie_secure, samesite="strict")
        audit_event(config, user, "logout")
        return {"ok": True}

    @app.get("/api/auth/me")
    async def me(user: CurrentUser):
        return {"id": user["id"], "username": user["username"], "role": user["role"]}

    @app.get("/api/profile")
    async def get_profile(user: CurrentUser):
        with closing(connect(config.database_path)) as db:
            profile = db.execute(
                "SELECT avatar FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
        if profile is None:
            raise HTTPException(status_code=404, detail="Account not found")
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "avatar": profile["avatar"],
        }

    @app.put("/api/profile")
    async def update_profile(body: ProfileBody, user: CurrentUser):
        avatar = body.avatar
        if avatar is not None:
            prefix, separator, encoded = avatar.partition(",")
            mime_types = {
                "data:image/jpeg;base64": "jpeg",
                "data:image/png;base64": "png",
                "data:image/webp;base64": "webp",
            }
            image_type = mime_types.get(prefix)
            if not separator or image_type is None:
                raise HTTPException(
                    status_code=400,
                    detail="Profile picture must be a JPEG, PNG, or WebP image",
                )
            try:
                image_bytes = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise HTTPException(status_code=400, detail="Profile picture data is invalid") from exc
            if not image_bytes or len(image_bytes) > 128 * 1024:
                raise HTTPException(
                    status_code=413,
                    detail="Profile picture must be no larger than 128 KiB",
                )
            valid_signature = (
                image_bytes.startswith(b"\xff\xd8\xff")
                if image_type == "jpeg"
                else image_bytes.startswith(b"\x89PNG\r\n\x1a\n")
                if image_type == "png"
                else image_bytes.startswith(b"RIFF")
                and image_bytes[8:12] == b"WEBP"
            )
            if not valid_signature:
                raise HTTPException(status_code=400, detail="Profile picture format does not match its data")

        with closing(connect(config.database_path)) as db:
            db.execute("UPDATE users SET avatar = ? WHERE id = ?", (avatar, user["id"]))
            db.commit()
        audit_event(config, user, "profile_picture_updated")
        return {"avatar": avatar}

    @app.put("/api/auth/password")
    async def change_own_password(body: PasswordBody, user: CurrentUser):
        with closing(connect(config.database_path)) as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash.hash(body.password), user["id"]),
            )
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
            db.commit()
        audit_event(config, user, "password_changed")
        return {"ok": True, "message": "Password changed. Sign in again."}

    @app.get("/api/dashboard/preferences")
    async def get_dashboard_preferences(_: CurrentUser):
        return read_dashboard_preferences(config)

    @app.put("/api/owner/dashboard/preferences")
    async def update_dashboard_preferences(
        body: DashboardPreferencesBody, user: CurrentUser
    ):
        require_owner(user)
        preferences = body.model_dump()
        if not valid_dashboard_preferences(preferences):
            raise HTTPException(status_code=422, detail="Choose supported dashboard options")
        with closing(connect(config.database_path)) as db:
            db.execute(
                "INSERT INTO app_settings (key, value) VALUES ('dashboard_preferences', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps(preferences, separators=(",", ":")),),
            )
            db.commit()
        audit_event(config, user, "dashboard_preferences_updated")
        return preferences

    @app.get("/api/dashboard")
    async def dashboard(user: CurrentUser):
        filesystem_root = active_filesystem_root(config)
        disk = shutil.disk_usage(filesystem_root)
        with closing(connect(config.database_path)) as db:
            sessions = db.execute(
                "SELECT COUNT(*) AS count FROM sessions WHERE expires_at > ?", (now(),)
            ).fetchone()["count"]
            audit_query = """
                SELECT a.action, a.path, a.detail, a.created_at, u.username
                FROM audit a LEFT JOIN users u ON u.id = a.user_id
            """
            if user["role"] != "owner":
                audit_query += " WHERE a.user_id = ?"
                audit = db.execute(
                    audit_query + " ORDER BY a.created_at DESC LIMIT 12",
                    (user["id"],),
                ).fetchall()
            else:
                audit = db.execute(
                    audit_query + " ORDER BY a.created_at DESC LIMIT 12"
                ).fetchall()
        return {
            "version": APP_VERSION,
            "uptime_seconds": int(time.time() - app.state.started_at),
            "filesystem_root": str(filesystem_root),
            "filesystem_mount_root": str(config.filesystem_root.resolve(strict=True)),
            "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
            "active_sessions": sessions if user["role"] == "owner" else None,
            "recent_activity": [
                {
                    "action": row["action"],
                    "path": row["path"],
                    "detail": row["detail"],
                    "created_at": row["created_at"],
                    "username": row["username"],
                }
                for row in audit
            ],
        }

    @app.get("/api/system/metrics")
    async def system_metrics(_: CurrentUser):
        with app.state.host_metrics_lock:
            metrics, app.state.host_metrics_sample = host_metrics(
                config, app.state.host_metrics_sample
            )
        disk = shutil.disk_usage(active_filesystem_root(config))
        metrics["disk"] = {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
        }
        return metrics

    @app.get("/api/owner/filesystem")
    async def owner_filesystem(user: CurrentUser, path: str | None = None):
        require_owner(user)
        mount_root = config.filesystem_root.resolve(strict=True)
        current_root = active_filesystem_root(config)
        resolved_path, relative_parts = resolve_managed_directory(
            config, path if path is not None else str(current_root)
        )
        fd = open_directory(mount_root, relative_parts)
        try:
            directories = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(entry_stat.st_mode):
                        directories.append(
                            {"name": entry.name, "path": str(resolved_path / entry.name)}
                        )
            directories.sort(key=lambda item: item["name"].casefold())
            return {
                "mount_root": str(mount_root),
                "active_root": str(current_root),
                "path": str(resolved_path),
                "parent": (
                    str(resolved_path.parent)
                    if resolved_path != mount_root
                    else None
                ),
                "directories": directories[:500],
                "truncated": len(directories) > 500,
            }
        finally:
            os.close(fd)

    @app.post("/api/owner/filesystem-root")
    async def set_owner_filesystem_root(body: FilesystemRootBody, user: CurrentUser):
        require_owner(user)
        new_root, _ = resolve_managed_directory(config, body.path)
        with closing(connect(config.database_path)) as db:
            db.execute("BEGIN IMMEDIATE")
            setting = db.execute(
                "SELECT value FROM app_settings WHERE key = 'active_filesystem_root'"
            ).fetchone()
            if setting is None:
                raise HTTPException(status_code=500, detail="Filesystem root setting is missing")
            old_root = Path(setting["value"])
            if old_root == new_root:
                db.commit()
                return {
                    "filesystem_root": str(new_root),
                    "remapped_grants": 0,
                    "removed_grants": 0,
                }

            remapped_grants = 0
            removed_grants = 0
            grants = db.execute("SELECT id, path FROM grants ORDER BY id").fetchall()
            for grant_row in grants:
                grant_path = old_root.joinpath(*canonical_parts(grant_row["path"]))
                try:
                    relative_path = grant_path.relative_to(new_root)
                except ValueError:
                    db.execute("DELETE FROM grants WHERE id = ?", (grant_row["id"],))
                    removed_grants += 1
                else:
                    db.execute(
                        "UPDATE grants SET path = ? WHERE id = ?",
                        (virtual_path(relative_path.parts), grant_row["id"]),
                    )
                    remapped_grants += 1
            db.execute(
                "UPDATE app_settings SET value = ? WHERE key = 'active_filesystem_root'",
                (str(new_root),),
            )
            db.execute(
                "INSERT INTO audit (user_id, action, path, detail, created_at) "
                "VALUES (?, 'filesystem_root_changed', ?, ?, ?)",
                (
                    user["id"],
                    str(new_root),
                    f"previous={old_root}; remapped_grants={remapped_grants}; removed_grants={removed_grants}",
                    now(),
                ),
            )
            db.commit()
        return {
            "filesystem_root": str(new_root),
            "remapped_grants": remapped_grants,
            "removed_grants": removed_grants,
        }

    @app.get("/api/activity")
    async def list_activity(user: CurrentUser, limit: int = 50):
        if not 1 <= limit <= 100:
            raise HTTPException(status_code=400, detail="Activity limit must be between 1 and 100")
        with closing(connect(config.database_path)) as db:
            query = """
                SELECT a.action, a.path, a.detail, a.created_at, u.username
                FROM audit a LEFT JOIN users u ON u.id = a.user_id
            """
            if user["role"] == "owner":
                rows = db.execute(
                    query + " ORDER BY a.created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = db.execute(
                    query + " WHERE a.user_id = ? ORDER BY a.created_at DESC LIMIT ?",
                    (user["id"], limit),
                ).fetchall()
        return [
            {
                "action": row["action"],
                "path": row["path"],
                "detail": row["detail"],
                "created_at": row["created_at"],
                "username": row["username"],
            }
            for row in rows
        ]

    @app.get("/api/files")
    async def list_files(user: CurrentUser, path: str = "/"):
        parts = canonical_parts(path)
        target = virtual_path(parts)
        filesystem_root = active_filesystem_root(config)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "browse")
            fd = open_directory(filesystem_root, parts)
            try:
                items = []
                with os.scandir(fd) as entries:
                    for entry in entries:
                        try:
                            item_stat = entry.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        item = file_metadata(entry.name, item_stat)
                        item_path = virtual_path(parts + (entry.name,))
                        item["access"] = sorted(get_permissions(db, user, item_path))
                        items.append(item)
                items.sort(key=lambda item: (item["kind"] != "folder", item["name"].casefold()))
                return {
                    "path": target,
                    "items": items,
                    "permissions": sorted(get_permissions(db, user, target)),
                }
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
            finally:
                os.close(fd)

    @app.get("/api/files/roots")
    async def accessible_roots(user: CurrentUser):
        if user["role"] == "owner":
            return {"paths": ["/"]}
        with closing(connect(config.database_path)) as db:
            grants = db.execute(
                "SELECT path FROM grants WHERE user_id = ? ORDER BY length(path), path",
                (user["id"],),
            ).fetchall()
            roots = [
                row["path"]
                for row in grants
                if "browse" in get_permissions(db, user, row["path"])
            ]
        return {"paths": list(dict.fromkeys(roots))}

    @app.get("/api/files/read")
    async def read_text(path: str, user: CurrentUser):
        parts = canonical_parts(path)
        target = virtual_path(parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "read")
        parent_fd, name = open_parent(active_filesystem_root(config), parts)
        try:
            try:
                fd = os.open(name, os.O_RDONLY | NONBLOCK | NOFOLLOW | CLOEXEC, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail="File not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise HTTPException(status_code=403, detail="Symbolic links are not followed") from exc
            raise HTTPException(status_code=400, detail="File cannot be opened") from exc
        finally:
            os.close(parent_fd)
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise HTTPException(status_code=400, detail="Only regular files can be opened")
            if file_stat.st_size > TEXT_FILE_LIMIT:
                raise HTTPException(status_code=413, detail="File is too large for the text editor")
            chunks: list[bytes] = []
            remaining = TEXT_FILE_LIMIT + 1
            while remaining:
                block = os.read(fd, remaining)
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            try:
                content = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HTTPException(status_code=415, detail="File is not UTF-8 text") from exc
        finally:
            os.close(fd)
        audit_event(config, user, "file_read", target)
        return {"path": target, "content": content}

    @app.get("/api/files/download")
    async def download_file(request: Request, path: str, user: CurrentUser):
        parts = canonical_parts(path)
        target = virtual_path(parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "download")
        parent_fd, name = open_parent(active_filesystem_root(config), parts)
        try:
            fd = os.open(name, os.O_RDONLY | NONBLOCK | NOFOLLOW | CLOEXEC, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            os.close(parent_fd)
            raise HTTPException(status_code=404, detail="File not found") from exc
        except PermissionError as exc:
            os.close(parent_fd)
            raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
        except OSError as exc:
            os.close(parent_fd)
            if exc.errno == errno.ELOOP:
                raise HTTPException(status_code=403, detail="Symbolic links are not followed") from exc
            raise HTTPException(status_code=400, detail="File cannot be opened") from exc
        os.close(parent_fd)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            os.close(fd)
            raise HTTPException(status_code=400, detail="Only regular files can be downloaded")
        try:
            start, end, status = range_bounds(request.headers.get("range"), file_stat.st_size)
        except HTTPException as exc:
            os.close(fd)
            if exc.status_code == 416:
                exc.headers = {"Content-Range": f"bytes */{file_stat.st_size}"}
            raise
        length = max(0, end - start + 1)
        media_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Length": str(length),
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
        }
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{end}/{file_stat.st_size}"
        audit_event(config, user, "file_download", target)
        return StreamingResponse(
            read_chunks(fd, start, length),
            status_code=status,
            media_type=media_type,
            headers=headers,
        )

    @app.post("/api/files/mkdir")
    async def create_folder(body: CreateBody, user: CurrentUser):
        parent_parts = canonical_parts(body.path)
        check_filename(body.name)
        parent_path = virtual_path(parent_parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, parent_path, "create")
        fd = open_directory(active_filesystem_root(config), parent_parts)
        try:
            os.mkdir(body.name, mode=0o700, dir_fd=fd)
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail="A file with that name already exists") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
        finally:
            os.close(fd)
        target = virtual_path(parent_parts + (body.name,))
        audit_event(config, user, "folder_created", target)
        return {"path": target}

    @app.post("/api/files/create")
    async def create_file(body: WriteBody, user: CurrentUser):
        parts = canonical_parts(body.path)
        if not parts:
            raise HTTPException(status_code=400, detail="A filename is required")
        check_filename(parts[-1])
        target = virtual_path(parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, virtual_path(parts[:-1]), "create")
        data = body.content.encode("utf-8")
        if len(data) > TEXT_FILE_LIMIT:
            raise HTTPException(status_code=413, detail="Text content exceeds the file limit")
        parent_fd = open_directory(active_filesystem_root(config), parts[:-1])
        try:
            fd = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                offset = 0
                while offset < len(data):
                    offset += os.write(fd, data[offset:])
            finally:
                os.close(fd)
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail="A file with that name already exists") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
        finally:
            os.close(parent_fd)
        audit_event(config, user, "file_created", target)
        return {"path": target}

    @app.put("/api/files/write")
    async def write_file(body: WriteBody, user: CurrentUser):
        parts = canonical_parts(body.path)
        if not parts:
            raise HTTPException(status_code=400, detail="A filename is required")
        check_filename(parts[-1])
        target = virtual_path(parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "edit")
        data = body.content.encode("utf-8")
        if len(data) > TEXT_FILE_LIMIT:
            raise HTTPException(status_code=413, detail="Text content exceeds the file limit")
        parent_fd = open_directory(active_filesystem_root(config), parts[:-1])
        try:
            try:
                fd = os.open(
                    parts[-1],
                    os.O_WRONLY | NONBLOCK | NOFOLLOW | CLOEXEC,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail="File not found") from exc
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise HTTPException(status_code=403, detail="Symbolic links are not followed") from exc
                raise HTTPException(status_code=400, detail="File cannot be opened") from exc
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise HTTPException(status_code=400, detail="Only regular files can be edited")
                os.ftruncate(fd, 0)
                offset = 0
                while offset < len(data):
                    offset += os.write(fd, data[offset:])
            finally:
                os.close(fd)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
        finally:
            os.close(parent_fd)
        audit_event(config, user, "file_edited", target)
        return {"path": target}

    @app.post("/api/files/rename")
    async def rename_file(body: RenameBody, user: CurrentUser):
        parts = canonical_parts(body.path)
        if not parts:
            raise HTTPException(status_code=400, detail="The filesystem root cannot be renamed")
        check_filename(body.name)
        target = virtual_path(parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "rename")
            require_permission(db, user, virtual_path(parts[:-1]), "rename")
        parent_fd = open_directory(active_filesystem_root(config), parts[:-1])
        try:
            rename_without_replace(parent_fd, parts[-1], parent_fd, body.name)
        finally:
            os.close(parent_fd)
        new_path = virtual_path(parts[:-1] + (body.name,))
        audit_event(config, user, "file_renamed", target, new_path)
        return {"path": new_path}

    @app.post("/api/files/delete")
    async def delete_file(body: DeleteBody, user: CurrentUser):
        parts = canonical_parts(body.path)
        if not parts:
            raise HTTPException(status_code=400, detail="The filesystem root cannot be deleted")
        target = virtual_path(parts)
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "delete")
        parent_fd = open_directory(active_filesystem_root(config), parts[:-1])
        try:
            try:
                entry_stat = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail="File not found") from exc
            try:
                if stat.S_ISDIR(entry_stat.st_mode):
                    os.rmdir(parts[-1], dir_fd=parent_fd)
                else:
                    os.unlink(parts[-1], dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EPERM}:
                    raise HTTPException(status_code=403, detail="Filesystem access denied") from exc
                if exc.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                    raise HTTPException(status_code=409, detail="Folder is not empty") from exc
                raise
        finally:
            os.close(parent_fd)
        audit_event(config, user, "file_deleted", target)
        return {"ok": True}

    @app.post("/api/files/upload")
    async def upload_file(
        path: str,
        user: CurrentUser,
        file: Annotated[UploadFile, File()],
    ):
        parts = canonical_parts(path)
        target = virtual_path(parts)
        check_filename(file.filename or "")
        with closing(connect(config.database_path)) as db:
            require_permission(db, user, target, "upload")
        parent_fd = open_directory(active_filesystem_root(config), parts)
        temporary_name = f".scc-upload-{secrets.token_hex(16)}"
        temporary_fd: int | None = None
        total = 0
        try:
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            while True:
                block = await file.read(UPLOAD_CHUNK_SIZE)
                if not block:
                    break
                total += len(block)
                if total > config.max_upload_bytes:
                    raise HTTPException(status_code=413, detail="Upload exceeds the configured limit")
                offset = 0
                while offset < len(block):
                    offset += os.write(temporary_fd, block[offset:])
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            with closing(connect(config.database_path)) as db:
                require_permission(db, user, target, "upload")
            rename_without_replace(parent_fd, temporary_name, parent_fd, file.filename)
        except Exception:
            if temporary_fd is not None:
                os.close(temporary_fd)
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(parent_fd)
            await file.close()
        result_path = virtual_path(parts + (file.filename,))
        audit_event(config, user, "file_uploaded", result_path, str(total))
        return {"path": result_path, "size": total}

    @app.get("/api/users")
    async def list_users(user: CurrentUser):
        require_owner(user)
        with closing(connect(config.database_path)) as db:
            users = db.execute(
                "SELECT id, username, role, active, created_at FROM users ORDER BY id"
            ).fetchall()
        return [
            {
                "id": item["id"],
                "username": item["username"],
                "role": item["role"],
                "active": bool(item["active"]),
                "created_at": item["created_at"],
            }
            for item in users
        ]

    @app.post("/api/users")
    async def create_user(body: UserBody, user: CurrentUser):
        require_owner(user)
        username = body.username.strip()
        if not USERNAME_PATTERN.fullmatch(username):
            raise HTTPException(status_code=422, detail="Username must be 3-32 safe characters")
        try:
            with closing(connect(config.database_path)) as db:
                cursor = db.execute(
                    "INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?, ?, ?, 1, ?)",
                    (username, password_hash.hash(body.password), body.role, now()),
                )
                created_id = cursor.lastrowid
                db.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username already exists") from exc
        audit_event(config, user, "user_created", detail=f"{username}:{body.role}")
        return {"id": created_id, "username": username, "role": body.role}

    @app.patch("/api/users/{user_id}")
    async def set_user_active(user_id: int, body: UserActiveBody, user: CurrentUser):
        require_owner(user)
        with closing(connect(config.database_path)) as db:
            target = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="User not found")
            if target["role"] == "owner":
                raise HTTPException(status_code=403, detail="The owner account cannot be disabled")
            db.execute("UPDATE users SET active = ? WHERE id = ?", (int(body.active), user_id))
            if not body.active:
                db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            db.commit()
        audit_event(config, user, "user_activation_changed", detail=f"{target['username']}:{body.active}")
        return {"id": user_id, "active": body.active}

    @app.post("/api/users/{user_id}/password")
    async def reset_user_password(user_id: int, body: PasswordBody, user: CurrentUser):
        require_owner(user)
        with closing(connect(config.database_path)) as db:
            target = db.execute(
                "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="User not found")
            if target["role"] == "owner":
                raise HTTPException(status_code=403, detail="Use the owner password change flow")
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash.hash(body.password), user_id),
            )
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            db.commit()
        audit_event(config, user, "user_password_reset", detail=target["username"])
        return {"ok": True}

    @app.delete("/api/users/{user_id}")
    async def delete_user(user_id: int, user: CurrentUser):
        require_owner(user)
        with closing(connect(config.database_path)) as db:
            target = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="User not found")
            if target["role"] == "owner":
                raise HTTPException(status_code=403, detail="The owner account cannot be deleted")
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        audit_event(config, user, "user_deleted", detail=target["username"])
        return {"ok": True}

    @app.get("/api/grants")
    async def list_grants(user: CurrentUser):
        require_owner(user)
        with closing(connect(config.database_path)) as db:
            rows = db.execute(
                """
                SELECT g.id, g.user_id, u.username, g.path, g.permissions, g.inherit
                FROM grants g JOIN users u ON u.id = g.user_id
                ORDER BY g.path, u.username
                """
            ).fetchall()
        return [
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "username": row["username"],
                "path": row["path"],
                "permissions": json.loads(row["permissions"]),
                "inherit": bool(row["inherit"]),
            }
            for row in rows
        ]

    @app.post("/api/grants")
    async def create_grant(body: GrantBody, user: CurrentUser):
        require_owner(user)
        path_parts = canonical_parts(body.path)
        target_path = virtual_path(path_parts)
        if any(permission not in PERMISSIONS for permission in body.permissions):
            raise HTTPException(status_code=422, detail="Unknown folder permission")
        with closing(connect(config.database_path)) as db:
            target_user = db.execute(
                "SELECT id, role FROM users WHERE id = ? AND active = 1", (body.user_id,)
            ).fetchone()
            if target_user is None:
                raise HTTPException(status_code=404, detail="Active user not found")
            if target_user["role"] == "owner":
                raise HTTPException(status_code=400, detail="The owner does not need folder grants")
        fd = open_directory(active_filesystem_root(config), path_parts)
        os.close(fd)
        with closing(connect(config.database_path)) as db:
            db.execute(
                """
                INSERT INTO grants (user_id, path, permissions, inherit) VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, path) DO UPDATE SET permissions = excluded.permissions, inherit = excluded.inherit
                """,
                (body.user_id, target_path, json.dumps(sorted(set(body.permissions))), int(body.inherit)),
            )
            db.commit()
        audit_event(config, user, "folder_grant_changed", target_path, target_user["role"])
        return {"user_id": body.user_id, "path": target_path}

    @app.delete("/api/grants/{grant_id}")
    async def delete_grant(grant_id: int, user: CurrentUser):
        require_owner(user)
        with closing(connect(config.database_path)) as db:
            row = db.execute("SELECT path FROM grants WHERE id = ?", (grant_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Folder grant not found")
            db.execute("DELETE FROM grants WHERE id = ?", (grant_id,))
            db.commit()
        audit_event(config, user, "folder_grant_deleted", row["path"])
        return {"ok": True}

    app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="frontend")
    return app


app = create_app()
