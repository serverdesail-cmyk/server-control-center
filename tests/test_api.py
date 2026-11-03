from __future__ import annotations

import sys
import sqlite3
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
    return csrf(client)


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
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


def test_setup_is_single_owner_and_protected_apis_require_login(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert "SCC | Server Control Center" in page.text
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
