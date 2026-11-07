from __future__ import annotations

import sys
import sqlite3
import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fastapi import HTTPException

from backend.app.main import PERMISSIONS, Settings, canonical_parts, create_app, digest

OWNER_PASSWORD = "owner-password-for-tests-123"
SETUP_TOKEN = "this-is-a-test-only-bootstrap-token-123"
USER_PASSWORD = "user-password-for-tests-123"


@pytest.fixture
def client(tmp_path: Path):
    root = tmp_path / "host-root"
    root.mkdir()
    (root / "team").mkdir()
    (root / "private").mkdir()
    (root / "team" / "hello.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    if sys.platform == "linux":
        (root / "escape").symlink_to(tmp_path / "outside.txt")
    config = Settings(
        data_dir=tmp_path / "data",
        filesystem_root=root,
        setup_token=SETUP_TOKEN,
        cookie_secure=False,
        max_upload_bytes=1024,
    )
    with TestClient(create_app(config)) as test_client:
        yield test_client


def csrf(client: TestClient) -> dict[str, str]:
    token = client.cookies.get("scc_csrf")
    assert token
    return {"X-CSRF-Token": token, "Origin": "http://testserver"}


def bootstrap(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/setup",
        headers={"Origin": "http://testserver"},
        json={
            "setup_token": SETUP_TOKEN,
            "username": "rootowner",
            "password": OWNER_PASSWORD,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["id"] > 0
    return csrf(client)


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    assert response.json()["id"] > 0
    return csrf(client)


def create_user(client: TestClient, headers: dict[str, str]) -> int:
    response = client.post(
        "/api/users",
        headers=headers,
        json={"username": "alice", "password": USER_PASSWORD, "role": "user"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def grant(
    client: TestClient,
    headers: dict[str, str],
    user_id: int,
    path: str,
    permissions: list[str],
    inherit: bool = True,
) -> None:
    response = client.post(
        "/api/grants",
        headers=headers,
        json={
            "user_id": user_id,
            "path": path,
            "permissions": permissions,
            "inherit": inherit,
        },
    )
    assert response.status_code == 200, response.text


def test_filesystem_root_cannot_overlap_private_database_directory(tmp_path: Path) -> None:
    root = tmp_path / "shared-root"
    root.mkdir()
    settings = Settings(
        data_dir=root / "private-db",
        filesystem_root=root,
        setup_token=SETUP_TOKEN,
        cookie_secure=False,
    )
    with pytest.raises(RuntimeError, match="private application or database directories"):
        with TestClient(create_app(settings)):
            pass


def test_setup_is_single_owner_and_protected_apis_require_login(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert "SERVER CONTROL CENTER" in page.text
    assert page.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/dashboard").status_code == 401
    headers = bootstrap(client)
    assert client.get("/api/auth/me").json()["role"] == "owner"
    second = client.post(
        "/api/setup",
        headers={"Origin": "http://testserver"},
        json={
            "setup_token": SETUP_TOKEN,
            "username": "secondowner",
            "password": OWNER_PASSWORD,
        },
    )
    assert second.status_code == 409
    assert client.get("/api/users").status_code == 200
    assert headers["X-CSRF-Token"] == client.cookies.get("scc_csrf")


def test_standalone_pages_use_same_origin_scripts_and_csrf_logout(client: TestClient) -> None:
    bootstrap(client)
    minecraft = client.get("/minecraft")
    services = client.get("/services")
    assert minecraft.status_code == services.status_code == 200
    assert '<script src="/assets/minecraft.js" defer></script>' in minecraft.text
    assert '<script src="/assets/services.js" defer></script>' in services.text
    assert "Content-Security-Policy" in minecraft.headers
    assert client.get("/assets/minecraft.js").status_code == 200
    assert client.get("/assets/services.js").status_code == 200


def test_existing_database_is_migrated_without_losing_owner_or_audit(client: TestClient) -> None:
    bootstrap(client)
    database_path = client.app.state.settings.database_path
    with sqlite3.connect(database_path) as db:
        audit_count = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        db.execute("DROP TABLE app_settings")
        db.execute("ALTER TABLE users DROP COLUMN avatar")

    with TestClient(create_app(client.app.state.settings)) as migrated:
        migrated.cookies.update(client.cookies)
        status = migrated.get("/api/setup/status")
        assert status.json()["owner_exists"] is True
        assert migrated.get("/api/auth/me").json()["username"] == "rootowner"
        assert migrated.get("/api/activity").status_code == 200
        with sqlite3.connect(database_path) as db:
            assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == audit_count
            assert "avatar" in {
                row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()
            }
            assert db.execute("SELECT value FROM app_settings WHERE key = 'active_filesystem_root'").fetchone()[0] == str(
                client.app.state.settings.filesystem_root.resolve()
            )


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_owner_filesystem_root_change_remaps_grants_and_stays_inside_mount(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    user_id = create_user(client, owner_headers)
    grant(client, owner_headers, user_id, "/team", ["browse", "read"])
    grant(client, owner_headers, user_id, "/private", ["browse"])

    filesystem = client.get("/api/owner/filesystem")
    assert filesystem.status_code == 200
    assert filesystem.json()["active_root"] == str(client.app.state.settings.filesystem_root)
    assert {item["name"] for item in filesystem.json()["directories"]} >= {"team", "private"}

    outside = client.app.state.settings.filesystem_root.parent / "outside-root"
    outside.mkdir()
    rejected = client.post(
        "/api/owner/filesystem-root",
        headers=owner_headers,
        json={"path": str(outside)},
    )
    assert rejected.status_code == 403

    changed = client.post(
        "/api/owner/filesystem-root",
        headers=owner_headers,
        json={"path": str(client.app.state.settings.filesystem_root / "team")},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["remapped_grants"] == 1
    assert changed.json()["removed_grants"] == 1
    assert client.get("/api/files?path=/").status_code == 200
    assert {item["name"] for item in client.get("/api/files?path=/").json()["items"]} == {"hello.txt"}

    grants = client.get("/api/grants").json()
    assert [(item["path"], item["user_id"]) for item in grants] == [("/", user_id)]

    client.post("/api/auth/logout", headers=csrf(client))
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/files?path=/").status_code == 200
    assert client.post(
        "/api/owner/filesystem-root",
        headers=csrf(client),
        json={"path": str(client.app.state.settings.filesystem_root)},
    ).status_code == 403


def test_host_metrics_returns_validated_samples(client: TestClient, tmp_path: Path) -> None:
    proc = tmp_path / "host-proc"
    (proc / "net").mkdir(parents=True)
    (proc / "stat").write_text("cpu 100 0 50 850 0 0 0 0 80 20\n", encoding="ascii")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 400 kB\n", encoding="ascii")
    (proc / "uptime").write_text("12345.67 1.0\n", encoding="ascii")
    (proc / "loadavg").write_text("0.12 0.34 0.56 1/100 200\n", encoding="ascii")
    (proc / "net" / "dev").write_text(
        "Inter-| Receive | Transmit\n"
        " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
        "  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n",
        encoding="ascii",
    )
    settings = replace(client.app.state.settings, host_proc_dir=proc)

    with TestClient(create_app(settings)) as metrics_client:
        headers = bootstrap(metrics_client)
        first = metrics_client.get("/api/system/metrics", headers=headers)
        assert first.status_code == 200, first.text
        assert first.json()["cpu_percent"] is None
        assert first.json()["memory"] == {"total": 1024000, "used": 614400, "available": 409600}
        assert first.json()["network"] == {"received_bytes": 1000, "transmitted_bytes": 2000}
        disk = first.json()["disk"]
        assert disk["total"] > 0
        assert disk["used"] >= 0
        assert disk["free"] >= 0
        assert disk["used"] + disk["free"] <= disk["total"]

        (proc / "stat").write_text("cpu 110 0 60 930 0 0 0 0 90 30\n", encoding="ascii")
        (proc / "net" / "dev").write_text(
            "Inter-| Receive | Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
            "  eth0: 1500 0 0 0 0 0 0 0 2500 0 0 0 0 0 0 0\n",
            encoding="ascii",
        )
        second = metrics_client.get("/api/system/metrics", headers=headers)
        assert second.status_code == 200, second.text
        assert second.json()["cpu_percent"] == 20.0
        assert second.json()["uptime_seconds"] == 12345
        assert second.json()["load_average"] == [0.12, 0.34, 0.56]
        assert second.json()["network"] == {"received_bytes": 1500, "transmitted_bytes": 2500}


def test_dashboard_preferences_are_owner_managed_and_persisted(client: TestClient) -> None:
    assert client.get("/api/dashboard/preferences").status_code == 401
    owner_headers = bootstrap(client)
    defaults = client.get("/api/dashboard/preferences")
    assert defaults.status_code == 200
    assert defaults.json() == {
        "widgets": ["stats", "activity", "filesystem", "quick-actions"],
        "quick_actions": ["files", "monitoring", "logs", "access", "settings"],
        "cpu_warning_percent": 85,
        "memory_warning_percent": 90,
        "disk_warning_percent": 90,
    }

    create_user(client, owner_headers)
    client.post("/api/auth/logout", headers=csrf(client))
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/dashboard/preferences").json() == defaults.json()
    assert client.put(
        "/api/owner/dashboard/preferences",
        headers=csrf(client),
        json=defaults.json(),
    ).status_code == 403

    client.post("/api/auth/logout", headers=csrf(client))
    owner_headers = login(client, "rootowner", OWNER_PASSWORD)
    updated = {
        "widgets": ["stats", "quick-actions"],
        "quick_actions": ["files", "monitoring"],
        "cpu_warning_percent": 80,
        "memory_warning_percent": 88,
        "disk_warning_percent": 92,
    }
    response = client.put(
        "/api/owner/dashboard/preferences",
        headers=owner_headers,
        json=updated,
    )
    assert response.status_code == 200, response.text
    assert response.json() == updated
    assert client.get("/api/dashboard/preferences").json() == updated

    invalid = {**updated, "quick_actions": ["files", "unsupported"]}
    assert client.put(
        "/api/owner/dashboard/preferences",
        headers=owner_headers,
        json=invalid,
    ).status_code == 422
    with sqlite3.connect(client.app.state.settings.database_path) as db:
        saved = db.execute(
            "SELECT value FROM app_settings WHERE key = 'dashboard_preferences'"
        ).fetchone()[0]
    assert json.loads(saved) == updated


def test_profile_picture_is_private_validated_and_persisted(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    owner = client.get("/api/profile")
    assert owner.status_code == 200
    assert owner.json()["role"] == "owner"
    assert owner.json()["avatar"] is None

    png = b"\x89PNG\r\n\x1a\n" + b"browser-optimized-picture"
    avatar = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
    updated = client.put(
        "/api/profile",
        headers=owner_headers,
        json={"avatar": avatar},
    )
    assert updated.status_code == 200
    assert client.get("/api/profile").json()["avatar"] == avatar

    invalid_type = client.put(
        "/api/profile",
        headers=csrf(client),
        json={"avatar": "data:image/svg+xml;base64," + base64.b64encode(b"<svg/>").decode("ascii")},
    )
    assert invalid_type.status_code == 400
    invalid_signature = client.put(
        "/api/profile",
        headers=csrf(client),
        json={"avatar": "data:image/png;base64," + base64.b64encode(b"not png").decode("ascii")},
    )
    assert invalid_signature.status_code == 400

    user_id = create_user(client, owner_headers)
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/profile").json()["avatar"] is None
    own_avatar = "data:image/jpeg;base64," + base64.b64encode(b"\xff\xd8\xff" + b"alice-avatar").decode("ascii")
    assert client.put(
        "/api/profile",
        headers=csrf(client),
        json={"avatar": own_avatar},
    ).status_code == 200
    assert client.get("/api/profile").json()["avatar"] == own_avatar
    assert client.get("/api/activity").status_code == 200
    assert all(row["username"] == "alice" for row in client.get("/api/activity").json())
    assert all(
        row["username"] == "alice"
        for row in client.get("/api/dashboard").json()["recent_activity"]
    )

    client.post("/api/auth/logout", headers=csrf(client))
    login(client, "rootowner", OWNER_PASSWORD)
    assert client.get("/api/profile").json()["avatar"] == avatar
    assert any(row["username"] == "rootowner" for row in client.get("/api/activity").json())
    assert user_id > 0


def test_profile_picture_size_is_limited(client: TestClient) -> None:
    headers = bootstrap(client)
    too_large = b"\x89PNG\r\n\x1a\n" + b"x" * (128 * 1024)
    response = client.put(
        "/api/profile",
        headers=headers,
        json={"avatar": "data:image/png;base64," + base64.b64encode(too_large).decode("ascii")},
    )
    assert response.status_code == 413


def test_virtual_paths_reject_traversal_and_platform_separators() -> None:
    assert canonical_parts("/") == ()
    assert canonical_parts("/media/usb") == ("media", "usb")
    with pytest.raises(HTTPException):
        canonical_parts("/media/../etc")
    with pytest.raises(HTTPException):
        canonical_parts(r"\media\usb")


def test_login_logout_csrf_and_session_expiration(client: TestClient) -> None:
    bootstrap(client)
    client.post("/api/auth/logout", headers=csrf(client))
    assert client.get("/api/auth/me").status_code == 401
    headers = login(client, "rootowner", OWNER_PASSWORD)
    bad_csrf = client.post(
        "/api/users",
        headers={"Origin": "http://testserver", "X-CSRF-Token": "invalid"},
        json={"username": "alice", "password": USER_PASSWORD, "role": "user"},
    )
    assert bad_csrf.status_code == 403
    session_token = client.cookies.get("scc_session")
    database_path = client.app.state.settings.database_path
    db = sqlite3.connect(database_path)
    try:
        db.execute(
            "UPDATE sessions SET expires_at = 0 WHERE token_hash = ?",
            (digest(session_token),),
        )
        db.commit()
    finally:
        db.close()
    assert client.get("/api/auth/me").status_code == 401
    headers = login(client, "rootowner", OWNER_PASSWORD)
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_login_rate_limit_and_owner_password_reset_revoke_sessions(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    user_id = create_user(client, owner_headers)
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/files/roots").json() == {"paths": []}

    client.post("/api/auth/logout", headers=csrf(client))
    owner_headers = login(client, "rootowner", OWNER_PASSWORD)
    reset = client.post(
        f"/api/users/{user_id}/password",
        headers=owner_headers,
        json={"password": "alice-new-password-123"},
    )
    assert reset.status_code == 200
    old_password = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": "alice", "password": USER_PASSWORD},
    )
    assert old_password.status_code == 401
    new_password = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": "alice", "password": "alice-new-password-123"},
    )
    assert new_password.status_code == 200

    client.post("/api/auth/logout", headers=csrf(client))
    for _ in range(8):
        response = client.post(
            "/api/auth/login",
            headers={"Origin": "http://testserver"},
            json={"username": "missing-user", "password": USER_PASSWORD},
        )
        assert response.status_code == 401
    limited = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": "missing-user", "password": USER_PASSWORD},
    )
    assert limited.status_code == 429


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux secure filesystem access.")
def test_grant_target_is_resolved_by_username_and_rejects_mismatched_id(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    first_user_id = create_user(client, owner_headers)
    second_user = client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "bob", "password": USER_PASSWORD, "role": "user"},
    )
    assert second_user.status_code == 200, second_user.text
    second_user_id = second_user.json()["id"]

    by_username = client.post(
        "/api/grants",
        headers=owner_headers,
        json={"username": "bob", "path": "/team", "permissions": ["browse", "upload"]},
    )
    assert by_username.status_code == 200, by_username.text
    assert by_username.json()["user_id"] == second_user_id

    mismatch = client.post(
        "/api/grants",
        headers=owner_headers,
        json={"username": "bob", "user_id": first_user_id, "path": "/private", "permissions": ["browse"]},
    )
    assert mismatch.status_code == 409

    grants = client.get("/api/grants", headers=owner_headers).json()
    assert [(item["username"], item["path"]) for item in grants] == [("bob", "/team")]


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_nested_grants_enforce_permissions_and_revoke_access(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    user_id = create_user(client, owner_headers)
    grant(client, owner_headers, user_id, "/", sorted(PERMISSIONS))
    grant(client, owner_headers, user_id, "/private", [], inherit=False)

    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/files?path=/team").status_code == 200
    assert client.get("/api/files?path=/private").status_code == 403
    assert client.get("/api/files/read?path=/team/hello.txt").status_code == 200
    assert client.post(
        "/api/files/mkdir",
        headers=csrf(client),
        json={"path": "/team", "name": "new-folder"},
    ).status_code == 200

    client.post("/api/auth/logout", headers=csrf(client))
    owner_headers = login(client, "rootowner", OWNER_PASSWORD)
    grants = client.get("/api/grants").json()
    root_grant = next(item for item in grants if item["path"] == "/" and item["user_id"] == user_id)
    assert client.delete(f"/api/grants/{root_grant['id']}", headers=owner_headers).status_code == 200
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/files?path=/team").status_code == 403


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_directory_listing_hides_ungranted_entries_but_keeps_nested_grant_ancestors(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    user_id = create_user(client, owner_headers)
    secret_dir = client.app.state.settings.filesystem_root / "private" / "secret"
    secret_dir.mkdir()
    (secret_dir / "allowed.txt").write_text("allowed", encoding="utf-8")
    grant(client, owner_headers, user_id, "/", sorted(PERMISSIONS))
    grant(client, owner_headers, user_id, "/private", [], inherit=False)

    login(client, "alice", USER_PASSWORD)
    root_listing = client.get("/api/files?path=/").json()
    assert "private" not in {item["name"] for item in root_listing["items"]}

    client.post("/api/auth/logout", headers=csrf(client))
    owner_headers = login(client, "rootowner", OWNER_PASSWORD)
    grant(client, owner_headers, user_id, "/private/secret", ["browse", "read"], inherit=True)
    login(client, "alice", USER_PASSWORD)

    root_listing = client.get("/api/files?path=/").json()
    private = next(item for item in root_listing["items"] if item["name"] == "private")
    assert private["restricted_ancestor"] is True
    assert private["access"] == []
    assert private["uid"] is None
    assert client.get("/api/files?path=/private").status_code == 200
    private_listing = client.get("/api/files?path=/private").json()
    assert {item["name"] for item in private_listing["items"]} == {"secret"}
    assert client.get("/api/files/read?path=/private/secret/allowed.txt").status_code == 200


def test_login_rate_limit_applies_across_usernames_from_one_client_ip(client: TestClient) -> None:
    bootstrap(client)
    for index in range(20):
        response = client.post(
            "/api/auth/login",
            headers={"Origin": "http://testserver"},
            json={"username": f"missing{index}", "password": USER_PASSWORD},
        )
        assert response.status_code == 401
    limited = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": "another-missing", "password": USER_PASSWORD},
    )
    assert limited.status_code == 429


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_upload_request_body_is_bounded_before_multipart_processing(client: TestClient) -> None:
    headers = bootstrap(client)
    response = client.post(
        "/api/files/upload?path=/team",
        headers=headers,
        files={"file": ("large.bin", b"x" * (300 * 1024), "application/octet-stream")},
    )
    assert response.status_code == 413


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_path_traversal_symlinks_and_range_download(client: TestClient) -> None:
    bootstrap(client)
    assert client.get("/api/files?path=/../private").status_code == 400
    assert client.get("/api/files/read?path=/escape").status_code == 403
    response = client.get(
        "/api/files/download?path=/team/hello.txt",
        headers={"Range": "bytes=1-3"},
    )
    assert response.status_code == 206
    assert response.content == b"ell"
    assert response.headers["content-range"] == "bytes 1-3/5"


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_arbitrary_binary_upload_keeps_files_non_executable(client: TestClient) -> None:
    headers = bootstrap(client)
    binary = b"\x7fELF\x00opaque uploaded bytes\x00\xff"
    response = client.post(
        "/api/files/upload?path=/team",
        headers=headers,
        files={"file": ("unknown-runtime.bin", binary, "application/x-executable")},
    )
    assert response.status_code == 200, response.text
    uploaded = client.app.state.settings.filesystem_root / "team" / "unknown-runtime.bin"
    assert uploaded.read_bytes() == binary
    assert uploaded.stat().st_mode & 0o111 == 0
    assert uploaded.stat().st_mode & 0o777 == 0o600

    invalid_name = client.post(
        "/api/files/upload?path=/team",
        headers=csrf(client),
        files={"file": ("file.txt:stream", b"data", "text/plain")},
    )
    assert invalid_name.status_code == 400


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_pdf_preview_requires_read_grant_and_is_inline_pdf(client: TestClient) -> None:
    pdf = client.app.state.settings.filesystem_root / "team" / "guide.pdf"
    pdf.write_bytes(b"%PDF-1.7\nsafe placeholder pdf bytes\n")
    owner_headers = bootstrap(client)
    user_id = create_user(client, owner_headers)

    client.post("/api/auth/logout", headers=csrf(client))
    login(client, "alice", USER_PASSWORD)
    denied = client.get("/api/files/preview?path=/team/guide.pdf")
    assert denied.status_code == 403

    client.post("/api/auth/logout", headers=csrf(client))
    owner_headers = login(client, "rootowner", OWNER_PASSWORD)
    grant(client, owner_headers, user_id, "/team", ["browse", "read"])
    client.post("/api/auth/logout", headers=csrf(client))
    login(client, "alice", USER_PASSWORD)
    preview = client.get("/api/files/preview?path=/team/guide.pdf")
    assert preview.status_code == 200
    assert preview.headers["content-type"] == "application/pdf"
    assert preview.headers["content-disposition"].startswith("inline;")
    assert preview.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'self'"
    assert preview.content.startswith(b"%PDF-")

    not_pdf = client.get("/api/files/preview?path=/team/hello.txt")
    assert not_pdf.status_code == 415


def test_minecraft_rcon_settings_are_encrypted_and_account_scoped(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    saved = client.put(
        "/api/minecraft/config",
        headers=owner_headers,
        json={"host": "192.168.1.20", "port": 25575, "password": "a-strong-private-rcon-password"},
    )
    assert saved.status_code == 200, saved.text
    assert client.get("/api/minecraft/config").json() == {
        "configured": True,
        "host": "192.168.1.20",
        "port": 25575,
        "password_set": True,
    }

    with sqlite3.connect(client.app.state.settings.database_path) as db:
        encrypted = db.execute(
            "SELECT password_encrypted FROM minecraft_rcon"
        ).fetchone()[0]
    assert b"a-strong-private-rcon-password" not in encrypted
    assert "a-strong-private-rcon-password" not in client.get("/api/minecraft/config").text
    changed_host = client.put(
        "/api/minecraft/config",
        headers=csrf(client),
        json={"host": "192.168.1.21", "port": 25576},
    )
    assert changed_host.status_code == 200
    with sqlite3.connect(client.app.state.settings.database_path) as db:
        updated_encrypted = db.execute(
            "SELECT password_encrypted FROM minecraft_rcon"
        ).fetchone()[0]
    assert updated_encrypted == encrypted

    public_host = client.put(
        "/api/minecraft/config",
        headers=csrf(client),
        json={"host": "8.8.8.8", "port": 25575, "password": "a-strong-private-rcon-password"},
    )
    assert public_host.status_code == 422
    bad_csrf = client.put(
        "/api/minecraft/config",
        headers={"Origin": "http://testserver", "X-CSRF-Token": "invalid"},
        json={"host": "192.168.1.20", "port": 25575, "password": "a-strong-private-rcon-password"},
    )
    assert bad_csrf.status_code == 403

    client.post("/api/auth/logout", headers=csrf(client))
    create_user(client, login(client, "rootowner", OWNER_PASSWORD))
    client.post("/api/auth/logout", headers=csrf(client))
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/minecraft/config").json()["configured"] is False
    assert client.post(
        "/api/minecraft/moderate",
        headers=csrf(client),
        json={"action": "kick", "player": "Example"},
    ).status_code == 409


def test_minecraft_moderation_uses_calling_accounts_credentials(client: TestClient, monkeypatch) -> None:
    from backend.app import main

    headers = bootstrap(client)
    client.put(
        "/api/minecraft/config",
        headers=headers,
        json={"host": "minecraft.internal", "port": 25575, "password": "a-strong-private-rcon-password"},
    )
    calls = []

    def fake_rcon(host, port, password, command):
        calls.append((host, port, password, command))
        return "Moderation action accepted"

    monkeypatch.setattr(main, "minecraft_rcon", fake_rcon)
    response = client.post(
        "/api/minecraft/moderate",
        headers=csrf(client),
        json={"action": "kick", "player": "Example", "reason": "testing"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["response"] == "Moderation action accepted"
    assert calls == [("minecraft.internal", 25575, "a-strong-private-rcon-password", "kick Example testing")]


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_upload_create_edit_rename_delete_and_no_overwrite(client: TestClient) -> None:
    headers = bootstrap(client)
    response = client.post(
        "/api/files/upload?path=/team",
        headers=headers,
        files={"file": ("upload.txt", b"upload-data", "text/plain")},
    )
    assert response.status_code == 200, response.text
    assert (client.app.state.settings.filesystem_root / "team" / "upload.txt").read_bytes() == b"upload-data"

    duplicate = client.post(
        "/api/files/upload?path=/team",
        headers=csrf(client),
        files={"file": ("upload.txt", b"replacement", "text/plain")},
    )
    assert duplicate.status_code == 409
    assert (client.app.state.settings.filesystem_root / "team" / "upload.txt").read_bytes() == b"upload-data"

    created = client.post(
        "/api/files/create",
        headers=csrf(client),
        json={"path": "/team/new.txt", "content": "first"},
    )
    assert created.status_code == 200
    updated = client.put(
        "/api/files/write",
        headers=csrf(client),
        json={"path": "/team/new.txt", "content": "second"},
    )
    assert updated.status_code == 200
    assert client.post(
        "/api/files/rename",
        headers=csrf(client),
        json={"path": "/team/new.txt", "name": "renamed.txt"},
    ).status_code == 200
    assert client.post(
        "/api/files/delete",
        headers=csrf(client),
        json={"path": "/team/renamed.txt"},
    ).status_code == 200


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_file_and_folder_creation_respects_entry_limit(client: TestClient) -> None:
    settings = replace(client.app.state.settings, max_entries=4)
    with TestClient(create_app(settings)) as limited_client:
        headers = bootstrap(limited_client)
        response = limited_client.post(
            "/api/files/mkdir",
            headers=headers,
            json={"path": "/team", "name": "too-many"},
        )
        assert response.status_code == 413
        assert not (settings.filesystem_root / "team" / "too-many").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux openat filesystem APIs.")
def test_upload_respects_aggregate_storage_quota_and_cleans_temporary_file(client: TestClient) -> None:
    settings = replace(client.app.state.settings, max_storage_bytes=1024)
    with TestClient(create_app(settings)) as limited_client:
        headers = bootstrap(limited_client)
        response = limited_client.post(
            "/api/files/upload?path=/team",
            headers=headers,
            files={"file": ("quota.bin", b"x" * 1020, "application/octet-stream")},
        )
        assert response.status_code == 413
        team = settings.filesystem_root / "team"
        assert not (team / "quota.bin").exists()
        assert not any(path.name.startswith(".scc-upload-") for path in team.iterdir())


def test_regular_user_cannot_use_owner_apis_and_disabling_revokes_sessions(client: TestClient) -> None:
    owner_headers = bootstrap(client)
    user_id = create_user(client, owner_headers)
    login(client, "alice", USER_PASSWORD)
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/grants").status_code == 403

    client.post("/api/auth/logout", headers=csrf(client))
    owner_headers = login(client, "rootowner", OWNER_PASSWORD)
    assert client.patch(
        f"/api/users/{user_id}",
        headers=owner_headers,
        json={"active": False},
    ).status_code == 200
    login_response = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": "alice", "password": USER_PASSWORD},
    )
    assert login_response.status_code == 401
