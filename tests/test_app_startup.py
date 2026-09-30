"""Point 1 regression: the application must start and serve requests."""


def test_app_starts_and_serves_config(app_client):
    resp = app_client.get("/api/config")
    assert resp.status_code == 200
    assert resp.json()["portRisk"]["22"] == "medium"


def test_index_is_served(app_client):
    resp = app_client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
