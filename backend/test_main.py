import pytest
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.mark.asyncio
async def test_get_habits_without_authorization():
	"""Test that GET /habits returns 401 when no Authorization header is provided."""
	async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
		response = await client.get("/habits")
		assert response.status_code == 401
		assert "Missing token" in response.json()["detail"]


@pytest.mark.asyncio
async def test_post_habits_without_authorization():
	"""Test that POST /habits returns 401 when no Authorization header is provided."""
	async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
		payload = {
			"name": "Test Habit",
			"time": "08:00",
			"location": "Home",
			"preposition": "at",
			"frequency": "daily",
			"createdDay": "2026-03-31",
		}
		response = await client.post("/habits", json=payload)
		assert response.status_code == 401
		assert "Missing token" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auth_login_redirect():
	"""Test that GET /auth/login returns 307 redirect."""
	async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
		response = await client.get("/auth/login")
		assert response.status_code == 307
		assert "location" in response.headers
		assert "accounts.google.com" in response.headers["location"]
