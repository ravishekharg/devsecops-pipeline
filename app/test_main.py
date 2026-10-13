import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "notes.db"))
    monkeypatch.setenv("API_TOKEN", "test-token")
    import main
    importlib.reload(main)
    return TestClient(main.app)


AUTH = {"Authorization": "Bearer test-token"}


def test_create_and_list(client):
    assert client.post("/notes", json={"owner": "alice", "body": "hi"}, headers=AUTH).status_code == 201
    assert client.get("/notes", params={"owner": "alice"}).json() == [{"id": 1, "owner": "alice", "body": "hi"}]


def test_writes_need_the_token(client):
    assert client.post("/notes", json={"owner": "alice", "body": "hi"}).status_code == 401
    assert client.post("/notes", json={"owner": "alice", "body": "hi"}, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_injection_attempt_is_just_data(client):
    client.post("/notes", json={"owner": "alice", "body": "secret"}, headers=AUTH)
    assert client.get("/notes", params={"owner": "x' OR '1'='1"}).json() == []


def test_input_validation(client):
    assert client.post("/notes", json={"owner": "a b;--", "body": "x"}, headers=AUTH).status_code == 422
    assert client.post("/notes", json={"owner": "a", "body": "x" * 2001}, headers=AUTH).status_code == 422


def test_security_headers(client):
    h = client.get("/healthz").headers
    assert h["x-content-type-options"] == "nosniff" and "default-src 'none'" in h["content-security-policy"]
