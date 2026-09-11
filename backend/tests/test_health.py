def test_health_check_v1(client):
    """Verify GET /api/v1/health returns status 200 OK and valid health schema."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "app" in data


def test_root_health_check(client):
    """Verify GET / root endpoint returns status 200 OK."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
